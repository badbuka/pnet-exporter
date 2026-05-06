package protocol

import (
	"bytes"
	"strings"
)

func ParseRedisCommand(payload []byte) (string, bool) {
	if len(payload) == 0 {
		return "", false
	}
	if payload[0] == '*' {
		lines := bytes.Split(payload, []byte("\r\n"))
		if len(lines) >= 4 && len(lines[2]) > 0 {
			return strings.ToUpper(string(lines[2])), true
		}
		return "", false
	}
	line, _, _ := bytes.Cut(payload, []byte("\r\n"))
	fields := strings.Fields(string(line))
	if len(fields) == 0 {
		return "", false
	}
	return strings.ToUpper(fields[0]), true
}

func ParseRedisStatus(payload []byte) string {
	if len(payload) == 0 {
		return "unknown"
	}
	if payload[0] == '-' {
		return "error"
	}
	return "ok"
}
