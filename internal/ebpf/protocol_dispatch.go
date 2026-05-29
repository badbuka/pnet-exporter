package ebpf

import (
	"fmt"
	"strconv"

	"pnet-exporter/internal/protocol"
	"pnet-exporter/internal/store"
)

// protocolCorrelation derives a correlation token for matching a
// request to its response. The token must remain stable between the
// request L7 event and the response L7 event for the same logical
// operation. When no protocol-specific token is available the caller
// substitutes the destination so simple ping-pong flows still correlate.
func protocolCorrelation(proto store.Protocol, payload []byte) string {
	switch proto {
	case store.ProtocolKafka:
		header, ok := protocol.ParseKafkaRequestHeader(payload)
		if !ok {
			return ""
		}
		return "kafka:" + strconv.FormatInt(int64(header.CorrelationID), 10)
	case store.ProtocolHTTP:
		if request, ok := protocol.ParseHTTPRequest(payload); ok {
			return fmt.Sprintf("http:%s %s", request.Method, request.Path)
		}
		return ""
	case store.ProtocolPostgres:
		if msgType, ok := protocol.ParsePostgresMessageType(payload); ok {
			return "pg:" + msgType
		}
		return ""
	case store.ProtocolRedis:
		if command, ok := protocol.ParseRedisCommand(payload); ok {
			return "redis:" + command
		}
		return ""
	default:
		return ""
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
		if _, ok := protocol.ParseKafkaRequestHeader(payload); ok {
			return "ok"
		}
		return "unknown"
	}
	return ""
}
