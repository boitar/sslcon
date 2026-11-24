package session

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"

	"sslcon/base"
)

func TestNewConnSessionParsesDNSHeaders(t *testing.T) {
	origNoDNS := base.Cfg.NoDNS
	defer func() {
		base.Cfg.NoDNS = origNoDNS
	}()
	base.Cfg.NoDNS = true

	header := http.Header{}
	header.Set("X-CSTP-Address", "10.8.0.2")
	header.Set("X-CSTP-Netmask", "255.255.255.0")
	header.Set("X-CSTP-MTU", "1399")
	header.Add("X-CSTP-DNS", " 10.0.0.53 ")
	header.Add("X-CSTP-DNS", "")
	header.Add("X-CSTP-DNS", "100.64.1.2, 8.8.8.8")
	header.Add("X-CSTP-DNS", "10.0.0.53")
	header.Set("X-CSTP-Default-Domain", "  corp.example.com \t")
	header.Add("X-CSTP-Split-DNS", "corp.example.com, internal.local")
	header.Add("X-CSTP-Split-DNS", "   ")
	header.Add("X-CSTP-Split-DNS", "svc.internal   dev.local")
	header.Add("X-CSTP-Split-DNS", "internal.local")

	sess := &Session{}
	cSess := sess.NewConnSession(&header)

	wantDNS := []string{"10.0.0.53", "100.64.1.2", "8.8.8.8"}
	if !reflect.DeepEqual(cSess.DNS, wantDNS) {
		t.Fatalf("DNS = %v, want %v", cSess.DNS, wantDNS)
	}

	if cSess.DefaultDomain != "corp.example.com" {
		t.Fatalf("DefaultDomain = %q, want %q", cSess.DefaultDomain, "corp.example.com")
	}

	wantSplitDNS := []string{"corp.example.com", "internal.local", "svc.internal", "dev.local"}
	if !reflect.DeepEqual(cSess.SplitDNS, wantSplitDNS) {
		t.Fatalf("SplitDNS = %v, want %v", cSess.SplitDNS, wantSplitDNS)
	}

	if cSess.DNSApplied {
		t.Fatalf("expected initial DNSApplied to be false")
	}
}

func TestNewConnSessionEmptyDNSHeadersAndJSONFields(t *testing.T) {
	header := http.Header{}
	header.Add("X-CSTP-DNS", "  ")
	header.Add("X-CSTP-Split-DNS", " ,  ")
	header.Set("X-CSTP-Default-Domain", "   ")

	sess := &Session{}
	cSess := sess.NewConnSession(&header)

	if len(cSess.DNS) != 0 {
		t.Fatalf("expected empty DNS, got %v", cSess.DNS)
	}
	if len(cSess.SplitDNS) != 0 {
		t.Fatalf("expected empty SplitDNS, got %v", cSess.SplitDNS)
	}
	if cSess.DefaultDomain != "" {
		t.Fatalf("expected empty DefaultDomain, got %q", cSess.DefaultDomain)
	}

	raw, err := json.Marshal(cSess)
	if err != nil {
		t.Fatalf("json.Marshal(ConnSession) failed: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	val, exists := payload["DNSApplied"]
	if !exists {
		t.Fatalf("expected JSON key DNSApplied to always be present")
	}
	if applied, ok := val.(bool); !ok || applied {
		t.Fatalf("expected DNSApplied=false, got %#v", val)
	}
	if _, exists := payload["DefaultDomain"]; !exists {
		t.Fatalf("expected JSON key DefaultDomain to be present")
	}
	if _, exists := payload["SplitDNS"]; !exists {
		t.Fatalf("expected JSON key SplitDNS to be present")
	}
}
