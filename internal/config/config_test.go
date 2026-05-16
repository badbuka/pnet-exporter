package config

import "testing"

func TestDefaultConfigValidates(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatalf("default config should validate: %v", err)
	}
}

func TestDefaultIsIndependentOfEnvironment(t *testing.T) {
	t.Setenv("PNET_LISTEN_ADDRESS", "0.0.0.0:1234")
	cfg := Default()
	if cfg.ListenAddress != ":9108" {
		t.Fatalf("Default() must ignore env, got %q", cfg.ListenAddress)
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

func TestLoadRejectsUnknownLogLevel(t *testing.T) {
	t.Setenv("PNET_LOG_LEVEL", "verbose")

	if _, err := Load(); err == nil {
		t.Fatal("expected unknown log level error")
	}
}

func TestLoadParsesProtocolPorts(t *testing.T) {
	t.Setenv("PNET_HTTP_PORTS", "8081, 8082")
	t.Setenv("PNET_POSTGRES_PORTS", "15432")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if got := cfg.Protocols.HTTPPorts; len(got) != 2 || got[0] != 8081 || got[1] != 8082 {
		t.Fatalf("unexpected http ports: %#v", got)
	}
	if got := cfg.Protocols.PostgresPorts; len(got) != 1 || got[0] != 15432 {
		t.Fatalf("unexpected postgres ports: %#v", got)
	}
}

func TestLoadRejectsInvalidPort(t *testing.T) {
	t.Setenv("PNET_HTTP_PORTS", "0")

	if _, err := Load(); err == nil {
		t.Fatal("expected invalid port error (zero not allowed)")
	}
}

func TestLoadRejectsDuplicatePort(t *testing.T) {
	t.Setenv("PNET_KAFKA_PORTS", "9100,9100")

	if _, err := Load(); err == nil {
		t.Fatal("expected duplicate port error")
	}
}
