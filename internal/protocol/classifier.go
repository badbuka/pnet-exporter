package protocol

import "pnet-exporter/internal/store"

type Classifier struct{}

func NewClassifier() Classifier {
	return Classifier{}
}

// ProtocolForPort returns the most likely application protocol for a
// given TCP port. The mapping is intentionally limited to ports the
// exporter has parsers for; unknown ports return ("", false).
func (Classifier) ProtocolForPort(port uint16) (store.Protocol, bool) {
	switch port {
	case 80, 8080, 8000, 3000, 5000:
		return store.ProtocolHTTP, true
	case 5432:
		return store.ProtocolPostgres, true
	case 6379:
		return store.ProtocolRedis, true
	case 9092, 9093, 9094:
		return store.ProtocolKafka, true
	default:
		return "", false
	}
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
