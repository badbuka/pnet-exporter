package protocol

import "encoding/binary"

type KafkaRequestHeader struct {
	APIKey        int16
	APIVersion    int16
	CorrelationID int32
}

func ParseKafkaRequestHeader(payload []byte) (KafkaRequestHeader, bool) {
	if len(payload) < 12 {
		return KafkaRequestHeader{}, false
	}
	return KafkaRequestHeader{
		APIKey:        int16(binary.BigEndian.Uint16(payload[4:6])),
		APIVersion:    int16(binary.BigEndian.Uint16(payload[6:8])),
		CorrelationID: int32(binary.BigEndian.Uint32(payload[8:12])),
	}, true
}

// ParseKafkaResponseCorrelationID extracts the correlation ID from a Kafka
// response frame. Unlike a request, a response header carries no api_key or
// api_version: the layout is Size(int32) followed immediately by
// correlation_id(int32), so the ID lives at bytes [4:8]. The broker echoes the
// request's correlation_id here, which is what lets the request and response
// be paired regardless of pipelining.
func ParseKafkaResponseCorrelationID(payload []byte) (int32, bool) {
	if len(payload) < 8 {
		return 0, false
	}
	return int32(binary.BigEndian.Uint32(payload[4:8])), true
}

func KafkaAPIName(apiKey int16) string {
	switch apiKey {
	case 0:
		return "produce"
	case 1:
		return "fetch"
	case 3:
		return "metadata"
	case 18:
		return "api_versions"
	default:
		return "api"
	}
}
