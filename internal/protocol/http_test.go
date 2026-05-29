package protocol

import "testing"

// h2headersFrame wraps an HPACK header block in a HEADERS frame with the
// given flags and stream id 1.
func h2headersFrame(flags byte, block []byte) []byte {
	n := len(block)
	frame := []byte{
		byte(n >> 16), byte(n >> 8), byte(n),
		http2FrameTypeHeads,
		flags,
		0x00, 0x00, 0x00, 0x01,
	}
	return append(frame, block...)
}

func TestIsHTTP2Preface(t *testing.T) {
	if !IsHTTP2Preface([]byte(http2Preface + "extra")) {
		t.Fatal("expected preface to be detected")
	}
	if IsHTTP2Preface([]byte("GET / HTTP/1.1\r\n")) {
		t.Fatal("HTTP/1.x request must not be detected as h2 preface")
	}
	if IsHTTP2Preface([]byte("PRI * HTTP/1.0\r\n")) {
		t.Fatal("partial match must not be detected as h2 preface")
	}
}

func TestParseHTTP2StatusIndexed(t *testing.T) {
	tests := []struct {
		name  string
		index byte
		want  string
	}{
		{"200", 0x88, "200"},
		{"204", 0x89, "204"},
		{"404", 0x8d, "404"},
		{"500", 0x8e, "500"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			payload := h2headersFrame(0x04, []byte{tc.index})
			got, ok := ParseHTTP2Status(payload)
			if !ok || got != tc.want {
				t.Fatalf("ParseHTTP2Status = %q, %v; want %q, true", got, ok, tc.want)
			}
		})
	}
}

func TestParseHTTP2StatusLiteral(t *testing.T) {
	// Literal with incremental indexing, name index 8 (:status), plain value "201".
	block := []byte{0x48, 0x03, '2', '0', '1'}
	got, ok := ParseHTTP2Status(h2headersFrame(0x04, block))
	if !ok || got != "201" {
		t.Fatalf("ParseHTTP2Status = %q, %v; want 201, true", got, ok)
	}
}

func TestParseHTTP2StatusHuffman(t *testing.T) {
	// Literal with incremental indexing, name index 8 (:status), Huffman value.
	// Each ASCII digit is a 5-bit code equal to its value; 3 digits + 1 pad bit
	// pack into 2 bytes.
	tests := []struct {
		name  string
		value []byte
		want  string
	}{
		{"200", []byte{0x10, 0x01}, "200"},
		{"503", []byte{0x28, 0x07}, "503"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			block := append([]byte{0x48, 0x82}, tc.value...)
			got, ok := ParseHTTP2Status(h2headersFrame(0x04, block))
			if !ok || got != tc.want {
				t.Fatalf("ParseHTTP2Status = %q, %v; want %q, true", got, ok, tc.want)
			}
		})
	}
}

func TestParseHTTP2StatusSkipsLeadingFrame(t *testing.T) {
	// An empty SETTINGS frame (type 0x4) precedes the HEADERS frame.
	settings := []byte{0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00}
	payload := append(settings, h2headersFrame(0x04, []byte{0x88})...)
	got, ok := ParseHTTP2Status(payload)
	if !ok || got != "200" {
		t.Fatalf("ParseHTTP2Status = %q, %v; want 200, true", got, ok)
	}
}

func TestParseHTTP2StatusUnsupported(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
	}{
		{"empty", nil},
		{"short frame header", []byte{0x00, 0x00}},
		{"huffman non-digit value", h2headersFrame(0x04, []byte{0x48, 0x82, 0x60, 0x6f})},
		{"non-status indexed", h2headersFrame(0x04, []byte{0x82})}, // :method GET
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got, ok := ParseHTTP2Status(tc.payload); ok {
				t.Fatalf("expected no status, got %q", got)
			}
		})
	}
}

func TestParseHTTPRequestMethods(t *testing.T) {
	methods := []string{"POST", "PUT", "DELETE", "PATCH"}
	for _, m := range methods {
		payload := []byte(m + " /api/resource HTTP/1.1\r\nHost: example\r\n\r\n")
		req, ok := ParseHTTPRequest(payload)
		if !ok || req.Method != m || req.Path != "/api/resource" {
			t.Fatalf("ParseHTTPRequest(%s): got %#v ok=%v", m, req, ok)
		}
	}
}

func TestParseHTTPRequestErrors(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
	}{
		{"no CRLF", []byte("GET /foo HTTP/1.1")},
		{"bad protocol", []byte("GET /foo FTP/1.0\r\n")},
		{"too few fields", []byte("GET\r\n")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := ParseHTTPRequest(tc.payload); ok {
				t.Fatalf("expected false for %q", tc.payload)
			}
		})
	}
}

func TestParseHTTPStatusCodes(t *testing.T) {
	tests := []struct {
		payload string
		want    string
	}{
		{"HTTP/1.1 200 OK\r\n", "200"},
		{"HTTP/1.1 404 Not Found\r\n", "404"},
		{"HTTP/1.1 500 Internal Server Error\r\n", "500"},
	}
	for _, tc := range tests {
		got, ok := ParseHTTPStatus([]byte(tc.payload))
		if !ok || got != tc.want {
			t.Fatalf("ParseHTTPStatus(%q) = %q, %v; want %q, true", tc.payload, got, ok, tc.want)
		}
	}
}

func TestParseHTTPStatusErrors(t *testing.T) {
	tests := []struct {
		name    string
		payload string
	}{
		{"no CRLF", "HTTP/1.1 200 OK"},
		{"non-numeric code", "HTTP/1.1 OK\r\n"},
		{"missing HTTP prefix", "BOGUS/1.1 200 OK\r\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := ParseHTTPStatus([]byte(tc.payload)); ok {
				t.Fatalf("expected false for %q", tc.payload)
			}
		})
	}
}
