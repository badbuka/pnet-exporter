package protocol

import (
	"bytes"
	"strconv"
	"strings"
)

type HTTPRequest struct {
	Method string
	Path   string
}

func ParseHTTPRequest(payload []byte) (HTTPRequest, bool) {
	line, _, ok := bytes.Cut(payload, []byte("\r\n"))
	if !ok {
		return HTTPRequest{}, false
	}
	parts := strings.SplitN(string(line), " ", 3)
	if len(parts) != 3 || !strings.HasPrefix(parts[2], "HTTP/") {
		return HTTPRequest{}, false
	}
	return HTTPRequest{Method: parts[0], Path: parts[1]}, true
}

func ParseHTTPStatus(payload []byte) (string, bool) {
	line, _, ok := bytes.Cut(payload, []byte("\r\n"))
	if !ok {
		return "", false
	}
	parts := strings.SplitN(string(line), " ", 3)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/") {
		return "", false
	}
	if _, err := strconv.Atoi(parts[1]); err != nil {
		return "", false
	}
	return parts[1], true
}
