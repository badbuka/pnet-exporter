package protocol

import "testing"

func TestParseRedisCommandInline(t *testing.T) {
	cmd, ok := ParseRedisCommand([]byte("SET mykey myval\r\n"))
	if !ok || cmd != "SET" {
		t.Fatalf("inline SET: got %q ok=%v", cmd, ok)
	}
}

func TestParseRedisCommandRESPSet(t *testing.T) {
	payload := []byte("*3\r\n$3\r\nset\r\n$5\r\nhello\r\n$5\r\nworld\r\n")
	cmd, ok := ParseRedisCommand(payload)
	if !ok || cmd != "SET" {
		t.Fatalf("RESP SET: got %q ok=%v", cmd, ok)
	}
}

func TestParseRedisCommandEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
	}{
		{"nil", nil},
		{"empty RESP array count only", []byte("*1\r\n")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got, ok := ParseRedisCommand(tc.payload); ok && tc.payload == nil {
				t.Fatalf("expected false for nil, got %q", got)
			} else if tc.name == "empty RESP array count only" && ok {
				t.Fatalf("expected false for truncated RESP, got %q", got)
			}
		})
	}
}

func TestParseRedisStatusOK(t *testing.T) {
	if got := ParseRedisStatus([]byte("+OK\r\n")); got != "ok" {
		t.Fatalf("got %q, want ok", got)
	}
}

func TestParseRedisStatusEmpty(t *testing.T) {
	if got := ParseRedisStatus(nil); got != "unknown" {
		t.Fatalf("got %q, want unknown", got)
	}
}
