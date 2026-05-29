package ebpf

import (
	"testing"

	"pnet-exporter/internal/store"
)

func TestSniffProtocolHTTP1(t *testing.T) {
	tests := []struct {
		name    string
		dir     Direction
		payload []byte
		want    store.Protocol
		wantOK  bool
	}{
		{
			name:    "http1 request line",
			dir:     DirRequest,
			payload: []byte("GET /healthz HTTP/1.1\r\nHost: svc\r\n\r\n"),
			want:    store.ProtocolHTTP,
			wantOK:  true,
		},
		{
			name:    "http1 status line",
			dir:     DirResponse,
			payload: []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
			want:    store.ProtocolHTTP,
			wantOK:  true,
		},
		{
			name:    "h2c preface request",
			dir:     DirRequest,
			payload: []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00"),
			want:    store.ProtocolHTTP,
			wantOK:  true,
		},
		{
			name:    "h2 response headers frame",
			dir:     DirResponse,
			payload: append([]byte{0x00, 0x00, 0x01, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01}, 0x88),
			want:    store.ProtocolHTTP,
			wantOK:  true,
		},
		{
			name:    "non-http request",
			dir:     DirRequest,
			payload: []byte("\x16\x03\x01\x02\x00binarytls"),
			want:    "",
			wantOK:  false,
		},
		{
			name:    "non-http response",
			dir:     DirResponse,
			payload: []byte("+OK redis\r\n"),
			want:    "",
			wantOK:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := sniffProtocol(tc.dir, tc.payload)
			if got != tc.want || ok != tc.wantOK {
				t.Fatalf("sniffProtocol = %q, %v; want %q, %v", got, ok, tc.want, tc.wantOK)
			}
		})
	}
}
