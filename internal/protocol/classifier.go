package protocol

import (
	"fmt"

	"pnet-exporter/internal/store"
)

// Classifier maps TCP port numbers to the application protocols the exporter has parsers for.
type Classifier struct {
	byPort map[uint16]store.Protocol
}

// defaultPorts returns the built-in protocol-to-port mapping. These
// ports are always recognised regardless of operator configuration.
func defaultPorts() map[store.Protocol][]uint16 {
	return map[store.Protocol][]uint16{
		store.ProtocolHTTP:     {80, 8080, 8000, 3000, 5000},
		store.ProtocolPostgres: {5432},
		store.ProtocolRedis:    {6379},
		store.ProtocolKafka:    {9092, 9093, 9094},
	}
}

// NewClassifier builds a Classifier that recognises the built-in
// default ports plus any operator-supplied extras. The extras map keys
// the additional ports by protocol; nil or empty entries are ignored.
// It returns an error if any port (default or extra) is claimed by more
// than one protocol, naming both sides of the conflict.
func NewClassifier(extra map[store.Protocol][]uint16) (Classifier, error) {
	byPort := make(map[uint16]store.Protocol)
	add := func(proto store.Protocol, port uint16) error {
		if existing, ok := byPort[port]; ok && existing != proto {
			return fmt.Errorf("port %d claimed by both %s and %s", port, existing, proto)
		}
		byPort[port] = proto
		return nil
	}

	for proto, ports := range defaultPorts() {
		for _, port := range ports {
			if err := add(proto, port); err != nil {
				return Classifier{}, err
			}
		}
	}
	for proto, ports := range extra {
		for _, port := range ports {
			if err := add(proto, port); err != nil {
				return Classifier{}, err
			}
		}
	}
	return Classifier{byPort: byPort}, nil
}

// ProtocolForPort returns the application protocol registered for the
// given TCP port. Unknown ports return ("", false).
func (c Classifier) ProtocolForPort(port uint16) (store.Protocol, bool) {
	proto, ok := c.byPort[port]
	return proto, ok
}

// NormalizeStatus collapses protocol-specific status strings into a
// small bounded set of values so label cardinality stays tame.
func NormalizeStatus(protocol store.Protocol, raw string) string {
	if raw == "" {
		return "unknown"
	}
	switch protocol {
	case store.ProtocolHTTP:
		return raw
	case store.ProtocolPostgres, store.ProtocolRedis, store.ProtocolKafka:
		if raw == "ok" || raw == "error" || raw == "timeout" {
			return raw
		}
		return "unknown"
	default:
		return "unknown"
	}
}
