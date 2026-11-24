package vpnc

import (
	"errors"
	"reflect"
	"testing"
)

func TestIsPrivateDNSIPv4(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.1", true},
		{"10.255.255.254", true},
		{"172.16.0.1", true},
		{"172.31.255.254", true},
		{"172.15.255.255", false},
		{"172.32.0.1", false},
		{"192.168.0.1", true},
		{"192.168.255.254", true},
		{"100.64.0.1", true},
		{"100.127.255.254", true},
		{"100.63.255.255", false},
		{"100.128.0.1", false},
		{"8.8.8.8", false},
		{"223.5.5.5", false},
		{"1.1.1.1", false},
		{"127.0.0.1", false},
		{"169.254.1.1", false},
		{"::1", false},
		{"fc00::1", false},
		{"::ffff:10.0.0.1", false},
		{"not-an-ip", false},
		{"", false},
	}

	for _, tc := range tests {
		if got := isPrivateDNSIPv4(tc.ip); got != tc.want {
			t.Errorf("isPrivateDNSIPv4(%q) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestIsIPCoveredBySplitInclude(t *testing.T) {
	splitInclude := []string{
		"10.0.0.0/255.0.0.0",
		"172.16.10.0/255.255.255.0",
		"192.168.50.53/255.255.255.255",
		"100.64.2.0/24",
		"invalid-entry",
		"10.1.0.0/255.0.255.0",
	}

	tests := []struct {
		ip   string
		want bool
	}{
		{"10.1.2.3", true},
		{"172.16.10.53", true},
		{"172.16.11.53", false},
		{"192.168.50.53", true},
		{"192.168.50.54", false},
		{"100.64.2.10", true},
		{"100.64.3.10", false},
		{"8.8.8.8", false},
		{"bad-ip", false},
	}

	for _, tc := range tests {
		if got := isIPCoveredBySplitInclude(tc.ip, splitInclude); got != tc.want {
			t.Errorf("isIPCoveredBySplitInclude(%q) = %v, want %v", tc.ip, got, tc.want)
		}
	}

	if !isIPCoveredBySplitInclude("10.9.9.9", []string{"0.0.0.0/0.0.0.0"}) {
		t.Fatalf("expected 0.0.0.0/0.0.0.0 to cover all IPv4 addresses")
	}
}

func TestPrivateDNSRoutesToAdd(t *testing.T) {
	dnsList := []string{
		"10.0.0.53",
		"172.16.20.53",
		"192.168.100.53",
		"100.64.10.10",
		"100.64.10.10",
		"8.8.8.8",
		"223.5.5.5",
		"fc00::53",
		"",
	}
	splitInclude := []string{
		"10.0.0.0/255.0.0.0",
		"192.168.100.0/255.255.255.0",
	}

	got := privateDNSRoutesToAdd(dnsList, splitInclude)
	want := []string{"172.16.20.53", "100.64.10.10"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("privateDNSRoutesToAdd = %v, want %v", got, want)
	}
}

func TestIsRouteExistsError(t *testing.T) {
	if isRouteExistsError(nil) {
		t.Fatalf("expected nil error to return false")
	}
	if !isRouteExistsError(errors.New("exit status 1 /bin/sh -c route add -net 10.0.0.53/32 10.8.0.2 route: writing to routing socket: File exists\n")) {
		t.Fatalf("expected macOS File exists error to match")
	}
	if !isRouteExistsError(errors.New("file exists")) {
		t.Fatalf("expected linux file exists error to match")
	}
	if !isRouteExistsError(errors.New("The object already exists.")) {
		t.Fatalf("expected windows already exists error to match")
	}
	if isRouteExistsError(errors.New("permission denied")) {
		t.Fatalf("expected permission denied not to match")
	}
}
