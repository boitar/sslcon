package base

import (
	"encoding/json"
	"testing"
)

func TestClientConfigNoDNSDefaultAndJSON(t *testing.T) {
	orig := *Cfg
	defer func() {
		*Cfg = orig
	}()

	Cfg = &ClientConfig{}
	initCfg()
	if Cfg.NoDNS {
		t.Fatalf("expected default NoDNS to be false, got true")
	}

	// Backward compatible payload without no_dns keeps default false.
	if err := json.Unmarshal([]byte(`{"log_level":"Info","no_dtls":true}`), &Cfg); err != nil {
		t.Fatalf("unmarshal without no_dns failed: %v", err)
	}
	if Cfg.NoDNS {
		t.Fatalf("expected NoDNS to remain false when omitted")
	}
	if !Cfg.NoDTLS {
		t.Fatalf("expected NoDTLS to be true")
	}

	// Explicitly enabling no_dns.
	if err := json.Unmarshal([]byte(`{"no_dns":true}`), &Cfg); err != nil {
		t.Fatalf("unmarshal no_dns=true failed: %v", err)
	}
	if !Cfg.NoDNS {
		t.Fatalf("expected NoDNS to be true")
	}

	// Explicitly disabling no_dns.
	if err := json.Unmarshal([]byte(`{"no_dns":false}`), &Cfg); err != nil {
		t.Fatalf("unmarshal no_dns=false failed: %v", err)
	}
	if Cfg.NoDNS {
		t.Fatalf("expected NoDNS to be false after reset")
	}
}
