package vpnc

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"sslcon/base"
	"sslcon/session"
)

func setupDarwinStubs(t *testing.T) (*[]string, *int, *int) {
	t.Helper()
	origRunCmd := runCmd
	origApplyDNS := applyDNS
	origRevertDNS := revertDNS
	origNoDNS := base.Cfg.NoDNS
	origGateway := base.LocalInterface.Gateway

	var cmds []string
	applyCount := 0
	revertCount := 0

	runCmd = func(cmdStrs []string) error {
		cmds = append(cmds, cmdStrs...)
		return nil
	}
	applyDNS = func(cSess *session.ConnSession) error {
		applyCount++
		return nil
	}
	revertDNS = func(cSess *session.ConnSession) {
		revertCount++
	}
	base.LocalInterface.Gateway = "192.168.1.1"

	t.Cleanup(func() {
		runCmd = origRunCmd
		applyDNS = origApplyDNS
		revertDNS = origRevertDNS
		base.Cfg.NoDNS = origNoDNS
		base.LocalInterface.Gateway = origGateway
	})

	return &cmds, &applyCount, &revertCount
}

func TestSetRoutesAndResetRoutes_NoDNSDisabled(t *testing.T) {
	_, applyCount, revertCount := setupDarwinStubs(t)
	base.Cfg.NoDNS = false

	cSess := &session.ConnSession{
		ServerAddress: "1.2.3.4",
		VPNAddress:    "10.8.0.2",
		TunName:       "utun5",
		DNS:           []string{"10.0.0.53", "8.8.8.8"},
		SplitInclude:  []string{"10.0.0.0/255.0.0.0"},
	}

	if err := SetRoutes(cSess); err != nil {
		t.Fatalf("SetRoutes failed: %v", err)
	}
	if *applyCount != 1 {
		t.Fatalf("expected applyDNS called once, got %d", *applyCount)
	}
	if !cSess.DNSApplied {
		t.Fatalf("expected DNSApplied=true")
	}

	// Flipping config before disconnect must NOT prevent restoreDNS since DNSApplied is true.
	base.Cfg.NoDNS = true
	ResetRoutes(cSess)
	if *revertCount != 1 {
		t.Fatalf("expected revertDNS called once, got %d", *revertCount)
	}
	if cSess.DNSApplied {
		t.Fatalf("expected DNSApplied=false after ResetRoutes")
	}
}

func TestSetRoutes_NoDNSDisabled_ApplyDNSFailure(t *testing.T) {
	_, _, revertCount := setupDarwinStubs(t)
	base.Cfg.NoDNS = false
	applyDNS = func(cSess *session.ConnSession) error {
		return errors.New("scutil failed")
	}

	cSess := &session.ConnSession{
		ServerAddress: "1.2.3.4",
		VPNAddress:    "10.8.0.2",
		DNS:           []string{"10.0.0.53"},
	}

	if err := SetRoutes(cSess); err == nil {
		t.Fatalf("expected SetRoutes to return applyDNS error")
	}
	if cSess.DNSApplied {
		t.Fatalf("expected DNSApplied=false when applyDNS fails")
	}
	ResetRoutes(cSess)
	if *revertCount != 0 {
		t.Fatalf("expected revertDNS not called when DNSApplied=false")
	}
}

func TestSetRoutes_NoDNSDisabled_WithoutServerDNS(t *testing.T) {
	_, applyCount, revertCount := setupDarwinStubs(t)
	base.Cfg.NoDNS = false

	cSess := &session.ConnSession{
		ServerAddress: "1.2.3.4",
		VPNAddress:    "10.8.0.2",
	}

	if err := SetRoutes(cSess); err != nil {
		t.Fatalf("SetRoutes failed: %v", err)
	}
	if *applyCount != 0 {
		t.Fatalf("expected applyDNS not called when no DNS provided")
	}
	if cSess.DNSApplied {
		t.Fatalf("expected DNSApplied=false")
	}

	ResetRoutes(cSess)
	if *revertCount != 0 {
		t.Fatalf("expected revertDNS not called")
	}
}

func TestSetRoutesAndResetRoutes_NoDNSEnabled(t *testing.T) {
	cmds, applyCount, revertCount := setupDarwinStubs(t)
	base.Cfg.NoDNS = true

	cSess := &session.ConnSession{
		ServerAddress: "1.2.3.4",
		VPNAddress:    "10.8.0.2",
		TunName:       "utun5",
		SplitInclude:  []string{"10.0.0.0/255.0.0.0"},
		DNS: []string{
			"10.0.0.53",      // covered by SplitInclude
			"172.16.1.53",    // private RFC1918, uncovered
			"192.168.100.53", // private RFC1918, uncovered
			"100.64.2.53",    // private RFC6598, uncovered
			"8.8.8.8",        // public, must skip
			"223.5.5.5",      // public, must skip
		},
	}

	if err := SetRoutes(cSess); err != nil {
		t.Fatalf("SetRoutes failed: %v", err)
	}
	if *applyCount != 0 {
		t.Fatalf("expected applyDNS skipped when NoDNS=true, got %d", *applyCount)
	}
	if cSess.DNSApplied {
		t.Fatalf("expected DNSApplied=false when NoDNS=true")
	}

	wantCmds := []string{
		"route add -host 1.2.3.4 192.168.1.1",
		"route add -net 10.0.0.0/8 10.8.0.2",
		"route add -net 172.16.1.53/32 10.8.0.2",
		"route add -net 192.168.100.53/32 10.8.0.2",
		"route add -net 100.64.2.53/32 10.8.0.2",
	}
	if !reflect.DeepEqual(*cmds, wantCmds) {
		t.Fatalf("cmds = %#v, want %#v", *cmds, wantCmds)
	}

	// Flipping config back to false before disconnect must NOT call restoreDNS since DNSApplied is false.
	base.Cfg.NoDNS = false
	ResetRoutes(cSess)
	if *revertCount != 0 {
		t.Fatalf("expected revertDNS not called when DNSApplied=false, got %d", *revertCount)
	}
}

func TestSetRoutes_NoDNSEnabled_ToleratesFileExists(t *testing.T) {
	setupDarwinStubs(t)
	base.Cfg.NoDNS = true

	runCmd = func(cmdStrs []string) error {
		for _, c := range cmdStrs {
			if strings.Contains(c, "172.16.1.53/32") {
				return errors.New("exit status 1 /bin/sh -c route add -net 172.16.1.53/32 10.8.0.2 route: writing to routing socket: File exists")
			}
		}
		return nil
	}

	cSess := &session.ConnSession{
		ServerAddress: "1.2.3.4",
		VPNAddress:    "10.8.0.2",
		DNS:           []string{"172.16.1.53", "100.64.2.53"},
	}

	if err := SetRoutes(cSess); err != nil {
		t.Fatalf("expected File exists on private DNS route to be tolerated, got: %v", err)
	}
	if cSess.DNSApplied {
		t.Fatalf("expected DNSApplied=false")
	}
}

func TestSetRoutes_NoDNSEnabled_PropagatesOtherRouteError(t *testing.T) {
	setupDarwinStubs(t)
	base.Cfg.NoDNS = true

	runCmd = func(cmdStrs []string) error {
		for _, c := range cmdStrs {
			if strings.Contains(c, "172.16.1.53/32") {
				return errors.New("operation not permitted")
			}
		}
		return nil
	}

	cSess := &session.ConnSession{
		ServerAddress: "1.2.3.4",
		VPNAddress:    "10.8.0.2",
		DNS:           []string{"172.16.1.53"},
	}

	if err := SetRoutes(cSess); err == nil {
		t.Fatalf("expected non-exists error on private DNS route to fail SetRoutes")
	}
}
