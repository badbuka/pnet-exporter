package ebpf

import (
	"strconv"

	"pnet-exporter/internal/protocol"
	"pnet-exporter/internal/store"
)

// protocolCorrelation derives a correlation token for matching a
// request to its response. The token must remain stable between the
// request L7 event and the response L7 event for the same logical
// operation. When no protocol-specific token is available the caller
// substitutes the destination so simple ping-pong flows still correlate.
//
// Only Kafka carries a token that appears in both frames: HTTP, Postgres
// and Redis responses contain nothing that echoes request data, so any
// request-derived token would never match its response (leaking tracker
// entries) and the destination fallback is used on both sides instead.
//
// The direction matters for Kafka: a request header carries
// api_key/api_version before the correlation_id while a response header
// carries only the correlation_id, so the same token must be read from
// different offsets on each side.
func protocolCorrelation(proto store.Protocol, dir Direction, payload []byte) string {
	if proto == store.ProtocolKafka {
		return kafkaCorrelation(dir, payload)
	}
	return ""
}

// kafkaCorrelation reads the correlation_id from a Kafka frame using the
// header layout appropriate to the direction and renders the shared token.
// Requests place the ID after api_key/api_version; responses place it
// immediately after the size prefix.
func kafkaCorrelation(dir Direction, payload []byte) string {
	switch dir {
	case DirResponse:
		id, ok := protocol.ParseKafkaResponseCorrelationID(payload)
		if !ok {
			return ""
		}
		return "kafka:" + strconv.FormatInt(int64(id), 10)
	default:
		header, ok := protocol.ParseKafkaRequestHeader(payload)
		if !ok {
			return ""
		}
		return "kafka:" + strconv.FormatInt(int64(header.CorrelationID), 10)
	}
}

// protocolStatus extracts a normalized status string from a protocol
// response payload. Unknown payloads return an empty string and the
// caller normalises that to "unknown".
func protocolStatus(proto store.Protocol, payload []byte) string {
	switch proto {
	case store.ProtocolHTTP:
		if status, ok := protocol.ParseHTTPStatus(payload); ok {
			return status
		}
		if status, ok := protocol.ParseHTTP2Status(payload); ok {
			return status
		}
	case store.ProtocolPostgres:
		return protocol.ParsePostgresStatus(payload)
	case store.ProtocolRedis:
		return protocol.ParseRedisStatus(payload)
	case store.ProtocolKafka:
		// A Kafka response carries no per-API status in its header; error
		// codes live in the API-specific body. A well-formed response header
		// is treated as a successful exchange, anything shorter as unknown.
		if _, ok := protocol.ParseKafkaResponseCorrelationID(payload); ok {
			return "ok"
		}
		return "unknown"
	}
	return ""
}
