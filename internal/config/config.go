package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	ListenAddress     string
	PodmanSocket      string
	PodmanBinary      string
	SysFS             string
	LogLevel          slog.Level
	DiscoveryInterval time.Duration
	ShutdownTimeout   time.Duration
	ContainerTTL      time.Duration
	Features          Features
	Store             StoreConfig
	Latency           LatencyConfig
	EBPF              EBPFConfig
}

type Features struct {
	Network  bool
	DNS      bool
	Latency  bool
	HTTP     bool
	Postgres bool
	Redis    bool
	Kafka    bool
}

type StoreConfig struct {
	DestinationLimit   int
	FQDNCeiling        int
	MetricTTL          time.Duration
	CleanupInterval    time.Duration
	DurationBuckets    []float64
	DNSDurationBuckets []float64
}

type LatencyConfig struct {
	Interval          time.Duration
	Timeout           time.Duration
	MaxTargetsPerTick int
}

type EBPFConfig struct {
	BPFDir         string
	RingBufferSize int
}

// envConfig is the flat struct envconfig reads from PNET_* variables.
// All default values are declared via the `default` struct tag so no
// separate Default() or defaultEnvConfig() initializer is needed.
type envConfig struct {
	ListenAddress      string        `envconfig:"LISTEN_ADDRESS"                 default:":9108"`
	PodmanSocket       string        `envconfig:"PODMAN_SOCKET"                  default:"/run/podman/podman.sock"`
	PodmanBinary       string        `envconfig:"PODMAN_BINARY"                  default:"podman"`
	SysFS              string        `envconfig:"SYSFS"                          default:"/sys"`
	LogLevel           string        `envconfig:"LOG_LEVEL"                      default:"info"`
	DiscoveryInterval  time.Duration `envconfig:"DISCOVERY_INTERVAL"             default:"10s"`
	ShutdownTimeout    time.Duration `envconfig:"SHUTDOWN_TIMEOUT"               default:"10s"`
	ContainerTTL       time.Duration `envconfig:"CONTAINER_TTL"                  default:"1m"`
	FeatureNetwork     bool          `envconfig:"FEATURE_NETWORK"                default:"true"`
	FeatureDNS         bool          `envconfig:"FEATURE_DNS"                    default:"true"`
	FeatureLatency     bool          `envconfig:"FEATURE_LATENCY"                default:"false"`
	FeatureHTTP        bool          `envconfig:"FEATURE_HTTP"                   default:"true"`
	FeaturePostgres    bool          `envconfig:"FEATURE_POSTGRES"               default:"true"`
	FeatureRedis       bool          `envconfig:"FEATURE_REDIS"                  default:"true"`
	FeatureKafka       bool          `envconfig:"FEATURE_KAFKA"                  default:"true"`
	DestinationLimit   int           `envconfig:"MAX_DESTINATIONS_PER_CONTAINER" default:"512"`
	FQDNCeiling        int           `envconfig:"MAX_FQDNS_PER_CONTAINER"        default:"100"`
	MetricTTL          time.Duration `envconfig:"METRIC_TTL"                     default:"10m"`
	CleanupInterval    time.Duration `envconfig:"CLEANUP_INTERVAL"               default:"1m"`
	DurationBuckets    string        `envconfig:"DURATION_BUCKETS"               default:"0.005,0.01,0.025,0.05,0.1,0.25,0.5,1,2.5,5,10"`
	DNSDurationBuckets string        `envconfig:"DNS_DURATION_BUCKETS"           default:"0.001,0.0025,0.005,0.01,0.025,0.05,0.1,0.25,0.5"`
	LatencyInterval    time.Duration `envconfig:"LATENCY_INTERVAL"               default:"30s"`
	LatencyTimeout     time.Duration `envconfig:"LATENCY_TIMEOUT"                default:"1s"`
	LatencyMaxTargets  int           `envconfig:"LATENCY_MAX_TARGETS"            default:"100"`
	BPFDir             string        `envconfig:"BPF_DIR"                        default:"./bpf"`
	RingBufferSize     int           `envconfig:"RING_BUFFER_SIZE"               default:"1048576"`
}

// Load reads PNET_* environment variables and returns a validated Config.
func Load() (Config, error) {
	var raw envConfig
	if err := envconfig.Process("PNET", &raw); err != nil {
		return Config{}, err
	}
	return raw.toConfig()
}

// Default returns a Config populated entirely from envconfig default tags.
// It is environment-independent: useful as a reference and from tests.
func Default() Config {
	var raw envConfig
	// Process with an empty prefix and an isolated namespace so no PNET_* env
	// variables leak in. envconfig falls back to `default` struct tags when
	// the underlying variable is unset.
	if err := envconfig.Process("__pnet_default__", &raw); err != nil {
		// Defaults are static, so a failure here is a programmer error in
		// the struct tags themselves.
		panic(fmt.Sprintf("config defaults are invalid: %v", err))
	}
	cfg, err := raw.toConfig()
	if err != nil {
		panic(fmt.Sprintf("config defaults are invalid: %v", err))
	}
	return cfg
}

func (c Config) Validate() error {
	if c.ListenAddress == "" {
		return errors.New("PNET_LISTEN_ADDRESS cannot be empty")
	}
	host, port, err := net.SplitHostPort(c.ListenAddress)
	if err != nil {
		return fmt.Errorf("invalid PNET_LISTEN_ADDRESS: %w", err)
	}
	if host == "" && port == "" {
		return errors.New("PNET_LISTEN_ADDRESS must include a port")
	}
	if c.DiscoveryInterval <= 0 {
		return errors.New("PNET_DISCOVERY_INTERVAL must be positive")
	}
	if c.ShutdownTimeout <= 0 {
		return errors.New("PNET_SHUTDOWN_TIMEOUT must be positive")
	}
	if c.ContainerTTL <= 0 {
		return errors.New("PNET_CONTAINER_TTL must be positive")
	}
	if c.Store.DestinationLimit <= 0 || c.Store.FQDNCeiling <= 0 {
		return errors.New("cardinality limits must be positive")
	}
	if c.Store.MetricTTL <= 0 || c.Store.CleanupInterval <= 0 {
		return errors.New("metric ttl and cleanup interval must be positive")
	}
	if c.Latency.Interval <= 0 || c.Latency.Timeout <= 0 || c.Latency.MaxTargetsPerTick <= 0 {
		return errors.New("latency settings must be positive")
	}
	if c.EBPF.RingBufferSize <= 0 {
		return errors.New("PNET_RING_BUFFER_SIZE must be positive")
	}
	return nil
}

func (e envConfig) toConfig() (Config, error) {
	durationBuckets, err := parseBuckets(e.DurationBuckets)
	if err != nil {
		return Config{}, fmt.Errorf("invalid PNET_DURATION_BUCKETS: %w", err)
	}
	dnsDurationBuckets, err := parseBuckets(e.DNSDurationBuckets)
	if err != nil {
		return Config{}, fmt.Errorf("invalid PNET_DNS_DURATION_BUCKETS: %w", err)
	}
	logLevel, err := parseLogLevel(e.LogLevel)
	if err != nil {
		return Config{}, fmt.Errorf("invalid PNET_LOG_LEVEL: %w", err)
	}

	cfg := Config{
		ListenAddress:     e.ListenAddress,
		PodmanSocket:      e.PodmanSocket,
		PodmanBinary:      e.PodmanBinary,
		SysFS:             e.SysFS,
		LogLevel:          logLevel,
		DiscoveryInterval: e.DiscoveryInterval,
		ShutdownTimeout:   e.ShutdownTimeout,
		ContainerTTL:      e.ContainerTTL,
		Features: Features{
			Network:  e.FeatureNetwork,
			DNS:      e.FeatureDNS,
			Latency:  e.FeatureLatency,
			HTTP:     e.FeatureHTTP,
			Postgres: e.FeaturePostgres,
			Redis:    e.FeatureRedis,
			Kafka:    e.FeatureKafka,
		},
		Store: StoreConfig{
			DestinationLimit:   e.DestinationLimit,
			FQDNCeiling:        e.FQDNCeiling,
			MetricTTL:          e.MetricTTL,
			CleanupInterval:    e.CleanupInterval,
			DurationBuckets:    durationBuckets,
			DNSDurationBuckets: dnsDurationBuckets,
		},
		Latency: LatencyConfig{
			Interval:          e.LatencyInterval,
			Timeout:           e.LatencyTimeout,
			MaxTargetsPerTick: e.LatencyMaxTargets,
		},
		EBPF: EBPFConfig{
			BPFDir:         e.BPFDir,
			RingBufferSize: e.RingBufferSize,
		},
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func parseBuckets(value string) ([]float64, error) {
	parts := strings.Split(value, ",")
	buckets := make([]float64, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		bucket, err := strconv.ParseFloat(trimmed, 64)
		if err != nil {
			return nil, err
		}
		if bucket <= 0 {
			return nil, fmt.Errorf("bucket %s must be positive", trimmed)
		}
		buckets = append(buckets, bucket)
	}
	if len(buckets) == 0 {
		return nil, errors.New("at least one bucket is required")
	}
	return buckets, nil
}

func parseLogLevel(value string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unknown level %q", value)
	}
}
