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
