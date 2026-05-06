package protocol

func ParsePostgresMessageType(payload []byte) (string, bool) {
	if len(payload) < 5 {
		return "", false
	}
	switch payload[0] {
	case 'Q':
		return "query", true
	case 'P':
		return "parse", true
	case 'B':
		return "bind", true
	case 'E':
		return "execute", true
	case 'S':
		return "sync", true
	default:
		return "message", true
	}
}

func ParsePostgresStatus(payload []byte) string {
	if len(payload) == 0 {
		return "unknown"
	}
	switch payload[0] {
	case 'E':
		return "error"
	case 'C', 'Z', 'T', 'D':
		return "ok"
	default:
		return "unknown"
	}
}
