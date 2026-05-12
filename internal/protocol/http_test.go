package protocol

import "testing"

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
