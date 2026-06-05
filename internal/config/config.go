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
	ListenAddress         string
	PodmanSocket          string
	PodmanUserSocketsGlob string
	SysFS                 string
	ProcFS                string
	LogLevel              slog.Level
	DiscoveryInterval     time.Duration
	ShutdownTimeout       time.Duration
	ContainerTTL          time.Duration
	Features              Features
	Store                 StoreConfig
	Latency               LatencyConfig
	Delays                DelayConfig
	Resources             ResourcesConfig
	EBPF                  EBPFConfig
	Protocols             ProtocolsConfig
}

// ProtocolsConfig carries operator-supplied TCP port lists that are
// appended to the L7 classifier's built-in defaults. Empty slices mean
// "no extra ports for this protocol".
type ProtocolsConfig struct {
	HTTPPorts     []uint16
	PostgresPorts []uint16
	RedisPorts    []uint16
	KafkaPorts    []uint16
}

type Features struct {
	Network            bool
	DNS                bool
	Latency            bool
	HTTP               bool
	Postgres           bool
	Redis              bool
	Kafka              bool
	NodeMetrics        bool
	DelayAccounting    bool
	OOM                bool
	ContainerResources bool
	IPv6               bool
}

type StoreConfig struct {
	DestinationLimit     int
	FQDNCeiling          int
	URLLimit             int
	MetricTTL            time.Duration
	CleanupInterval      time.Duration
	DurationBuckets      []float64
	DNSDurationBuckets   []float64
	CollapseDynamicPorts bool
	DynamicPortMin       uint16
	DynamicPortMax       uint16
}

type LatencyConfig struct {
	Interval          time.Duration
	Timeout           time.Duration
	MaxTargetsPerTick int
}

type DelayConfig struct {
	Interval time.Duration
}

type ResourcesConfig struct {
	Interval time.Duration
}

type EBPFConfig struct {
	BPFDir         string
	RingBufferSize int
}

// envConfig is the flat struct envconfig reads from PNET_* variables.
// All default values are declared via the `default` struct tag so no
// separate Default() or defaultEnvConfig() initializer is needed.
type envConfig struct {
	ListenAddress             string        `envconfig:"LISTEN_ADDRESS"                 default:":9108"`
	PodmanSocket              string        `envconfig:"PODMAN_SOCKET"                  default:"/run/podman/podman.sock"`
	PodmanUserSocketsGlob     string        `envconfig:"PODMAN_USER_SOCKETS_GLOB"       default:"/run/user/*/podman/podman.sock"`
	SysFS                     string        `envconfig:"SYSFS"                          default:"/sys"`
	ProcFS                    string        `envconfig:"PROCFS"                         default:"/proc"`
	LogLevel                  string        `envconfig:"LOG_LEVEL"                      default:"info"`
	DiscoveryInterval         time.Duration `envconfig:"DISCOVERY_INTERVAL"             default:"10s"`
	ShutdownTimeout           time.Duration `envconfig:"SHUTDOWN_TIMEOUT"               default:"10s"`
	ContainerTTL              time.Duration `envconfig:"CONTAINER_TTL"                  default:"1m"`
	FeatureNetwork            bool          `envconfig:"FEATURE_NETWORK"                default:"true"`
	FeatureDNS                bool          `envconfig:"FEATURE_DNS"                    default:"true"`
	FeatureLatency            bool          `envconfig:"FEATURE_LATENCY"                default:"false"`
	FeatureHTTP               bool          `envconfig:"FEATURE_HTTP"                   default:"true"`
	FeaturePostgres           bool          `envconfig:"FEATURE_POSTGRES"               default:"true"`
	FeatureRedis              bool          `envconfig:"FEATURE_REDIS"                  default:"true"`
	FeatureKafka              bool          `envconfig:"FEATURE_KAFKA"                  default:"true"`
	FeatureNodeMetrics        bool          `envconfig:"FEATURE_NODE_METRICS"           default:"true"`
	FeatureDelayAccounting    bool          `envconfig:"FEATURE_DELAY_ACCOUNTING"       default:"true"`
	FeatureOOM                bool          `envconfig:"FEATURE_OOM"                    default:"true"`
	FeatureContainerResources bool          `envconfig:"FEATURE_CONTAINER_RESOURCES"    default:"true"`
	FeatureIPv6               bool          `envconfig:"FEATURE_IPV6"                   default:"false"`
	DestinationLimit          int           `envconfig:"MAX_DESTINATIONS_PER_CONTAINER" default:"512"`
	FQDNCeiling               int           `envconfig:"MAX_FQDNS_PER_CONTAINER"        default:"100"`
	URLLimit                  int           `envconfig:"MAX_URLS_PER_CONTAINER"         default:"200"`
	CollapseDynamicPorts      bool          `envconfig:"COLLAPSE_DYNAMIC_PORTS"         default:"true"`
	DynamicPortMin            uint16        `envconfig:"DYNAMIC_PORT_MIN"               default:"32768"`
	DynamicPortMax            uint16        `envconfig:"DYNAMIC_PORT_MAX"               default:"65535"`
	MetricTTL                 time.Duration `envconfig:"METRIC_TTL"                     default:"10m"`
	CleanupInterval           time.Duration `envconfig:"CLEANUP_INTERVAL"               default:"1m"`
	DurationBuckets           string        `envconfig:"DURATION_BUCKETS"               default:"0.005,0.01,0.025,0.05,0.1,0.25,0.5,1,2.5,5,10"`
	DNSDurationBuckets        string        `envconfig:"DNS_DURATION_BUCKETS"           default:"0.001,0.0025,0.005,0.01,0.025,0.05,0.1,0.25,0.5"`
	LatencyInterval           time.Duration `envconfig:"LATENCY_INTERVAL"               default:"30s"`
	LatencyTimeout            time.Duration `envconfig:"LATENCY_TIMEOUT"                default:"1s"`
	LatencyMaxTargets         int           `envconfig:"LATENCY_MAX_TARGETS"            default:"100"`
	DelayInterval             time.Duration `envconfig:"DELAY_INTERVAL"                 default:"15s"`
	ResourcesInterval         time.Duration `envconfig:"RESOURCES_INTERVAL"             default:"15s"`
	BPFDir                    string        `envconfig:"BPF_DIR"                        default:"./bpf"`
	RingBufferSize            int           `envconfig:"RING_BUFFER_SIZE"               default:"1048576"`
	HTTPPorts                 string        `envconfig:"HTTP_PORTS"                     default:""`
	PostgresPorts             string        `envconfig:"POSTGRES_PORTS"                 default:""`
	RedisPorts                string        `envconfig:"REDIS_PORTS"                    default:""`
	KafkaPorts                string        `envconfig:"KAFKA_PORTS"                    default:""`
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
	if err := envconfig.Process("__pnet_default__", &raw); err != nil {
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
	if c.Store.DestinationLimit <= 0 || c.Store.FQDNCeiling <= 0 || c.Store.URLLimit <= 0 {
		return errors.New("cardinality limits must be positive")
	}
	if c.Store.MetricTTL <= 0 || c.Store.CleanupInterval <= 0 {
		return errors.New("metric ttl and cleanup interval must be positive")
	}
	if c.Store.CollapseDynamicPorts {
		if c.Store.DynamicPortMin == 0 || c.Store.DynamicPortMin > c.Store.DynamicPortMax {
			return errors.New("PNET_DYNAMIC_PORT_MIN must be in 1..PNET_DYNAMIC_PORT_MAX")
		}
	}
	if c.Latency.Interval <= 0 || c.Latency.Timeout <= 0 || c.Latency.MaxTargetsPerTick <= 0 {
		return errors.New("latency settings must be positive")
	}
	if c.Delays.Interval <= 0 {
		return errors.New("PNET_DELAY_INTERVAL must be positive")
	}
	if c.Resources.Interval <= 0 {
		return errors.New("PNET_RESOURCES_INTERVAL must be positive")
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

	httpPorts, err := parsePorts(e.HTTPPorts)
	if err != nil {
		return Config{}, fmt.Errorf("invalid PNET_HTTP_PORTS: %w", err)
	}
	postgresPorts, err := parsePorts(e.PostgresPorts)
	if err != nil {
		return Config{}, fmt.Errorf("invalid PNET_POSTGRES_PORTS: %w", err)
	}
	redisPorts, err := parsePorts(e.RedisPorts)
	if err != nil {
		return Config{}, fmt.Errorf("invalid PNET_REDIS_PORTS: %w", err)
	}
	kafkaPorts, err := parsePorts(e.KafkaPorts)
	if err != nil {
		return Config{}, fmt.Errorf("invalid PNET_KAFKA_PORTS: %w", err)
	}

	cfg := Config{
		ListenAddress:         e.ListenAddress,
		PodmanSocket:          e.PodmanSocket,
		PodmanUserSocketsGlob: e.PodmanUserSocketsGlob,
		SysFS:                 e.SysFS,
		ProcFS:                e.ProcFS,
		LogLevel:              logLevel,
		DiscoveryInterval:     e.DiscoveryInterval,
		ShutdownTimeout:       e.ShutdownTimeout,
		ContainerTTL:          e.ContainerTTL,
		Features: Features{
			Network:            e.FeatureNetwork,
			DNS:                e.FeatureDNS,
			Latency:            e.FeatureLatency,
			HTTP:               e.FeatureHTTP,
			Postgres:           e.FeaturePostgres,
			Redis:              e.FeatureRedis,
			Kafka:              e.FeatureKafka,
			NodeMetrics:        e.FeatureNodeMetrics,
			DelayAccounting:    e.FeatureDelayAccounting,
			OOM:                e.FeatureOOM,
			ContainerResources: e.FeatureContainerResources,
			IPv6:               e.FeatureIPv6,
		},
		Store: StoreConfig{
			DestinationLimit:     e.DestinationLimit,
			FQDNCeiling:          e.FQDNCeiling,
			URLLimit:             e.URLLimit,
			MetricTTL:            e.MetricTTL,
			CleanupInterval:      e.CleanupInterval,
			DurationBuckets:      durationBuckets,
			DNSDurationBuckets:   dnsDurationBuckets,
			CollapseDynamicPorts: e.CollapseDynamicPorts,
			DynamicPortMin:       e.DynamicPortMin,
			DynamicPortMax:       e.DynamicPortMax,
		},
		Latency: LatencyConfig{
			Interval:          e.LatencyInterval,
			Timeout:           e.LatencyTimeout,
			MaxTargetsPerTick: e.LatencyMaxTargets,
		},
		Delays: DelayConfig{
			Interval: e.DelayInterval,
		},
		Resources: ResourcesConfig{
			Interval: e.ResourcesInterval,
		},
		EBPF: EBPFConfig{
			BPFDir:         e.BPFDir,
			RingBufferSize: e.RingBufferSize,
		},
		Protocols: ProtocolsConfig{
			HTTPPorts:     httpPorts,
			PostgresPorts: postgresPorts,
			RedisPorts:    redisPorts,
			KafkaPorts:    kafkaPorts,
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

// parsePorts splits a comma-separated list of TCP port numbers and
// rejects empty entries, out-of-range values, and duplicates within the
// same list. An empty input yields a nil slice (no extra ports).
func parsePorts(value string) ([]uint16, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, nil
	}
	parts := strings.Split(trimmed, ",")
	ports := make([]uint16, 0, len(parts))
	seen := make(map[uint16]struct{}, len(parts))
	for _, part := range parts {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("port %q: %w", p, err)
		}
		if n == 0 {
			return nil, fmt.Errorf("port %q must be in 1..65535", p)
		}
		port := uint16(n)
		if _, dup := seen[port]; dup {
			return nil, fmt.Errorf("duplicate port %d", port)
		}
		seen[port] = struct{}{}
		ports = append(ports, port)
	}
	return ports, nil
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
