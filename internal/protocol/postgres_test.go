package protocol

import "testing"

func TestParsePostgresMessageType(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		want    string
		wantOK  bool
	}{
		{"query", []byte{'Q', 0, 0, 0, 0}, "query", true},
		{"parse", []byte{'P', 0, 0, 0, 0}, "parse", true},
		{"bind", []byte{'B', 0, 0, 0, 0}, "bind", true},
		{"execute", []byte{'E', 0, 0, 0, 0}, "execute", true},
		{"sync", []byte{'S', 0, 0, 0, 0}, "sync", true},
		{"fallthrough", []byte{'X', 0, 0, 0, 0}, "message", true},
		{"too short", []byte{0, 0}, "", false},
		{"nil", nil, "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ParsePostgresMessageType(tc.payload)
			if ok != tc.wantOK || got != tc.want {
				t.Fatalf("ParsePostgresMessageType(%v) = %q, %v; want %q, %v", tc.payload, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestParsePostgresStatus(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		want    string
	}{
		{"error", []byte{'E'}, "error"},
		{"ok C", []byte{'C'}, "ok"},
		{"ok Z", []byte{'Z'}, "ok"},
		{"ok T", []byte{'T'}, "ok"},
		{"ok D", []byte{'D'}, "ok"},
		{"unknown", []byte{'X'}, "unknown"},
		{"empty", []byte{}, "unknown"},
		{"nil", nil, "unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ParsePostgresStatus(tc.payload); got != tc.want {
				t.Fatalf("ParsePostgresStatus(%v) = %q; want %q", tc.payload, got, tc.want)
			}
		})
	}
}
