package config

import "testing"

func TestDefaultConfigValidates(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatalf("default config should validate: %v", err)
	}
}

func TestLoadOverridesFromEnvironment(t *testing.T) {
	t.Setenv("PNET_LISTEN_ADDRESS", "127.0.0.1:9999")
	t.Setenv("PNET_FEATURE_LATENCY", "true")
	t.Setenv("PNET_MAX_FQDNS_PER_CONTAINER", "7")
	t.Setenv("PNET_DURATION_BUCKETS", "0.1,0.5,1")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.ListenAddress != "127.0.0.1:9999" {
		t.Fatalf("unexpected listen address: %s", cfg.ListenAddress)
	}
	if !cfg.Features.Latency {
		t.Fatal("expected latency feature to be enabled")
	}
	if cfg.Store.FQDNCeiling != 7 {
		t.Fatalf("unexpected fqdn ceiling: %d", cfg.Store.FQDNCeiling)
	}
	if len(cfg.Store.DurationBuckets) != 3 || cfg.Store.DurationBuckets[1] != 0.5 {
		t.Fatalf("unexpected duration buckets: %#v", cfg.Store.DurationBuckets)
	}
}

func TestLoadRejectsInvalidBuckets(t *testing.T) {
	t.Setenv("PNET_DURATION_BUCKETS", "0.1,nope")

	if _, err := Load(); err == nil {
		t.Fatal("expected invalid bucket error")
	}
}
