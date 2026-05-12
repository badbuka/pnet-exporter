package protocol

import "testing"

func TestKafkaAPIName(t *testing.T) {
	tests := []struct {
		key  int16
		want string
	}{
		{0, "produce"},
		{1, "fetch"},
		{3, "metadata"},
		{18, "api_versions"},
		{99, "api"},
	}
	for _, tc := range tests {
		if got := KafkaAPIName(tc.key); got != tc.want {
			t.Fatalf("KafkaAPIName(%d) = %q; want %q", tc.key, got, tc.want)
		}
	}
}

func TestParseKafkaRequestHeaderTooShort(t *testing.T) {
	if _, ok := ParseKafkaRequestHeader(make([]byte, 11)); ok {
		t.Fatal("expected false for 11-byte payload")
	}
	if _, ok := ParseKafkaRequestHeader(nil); ok {
		t.Fatal("expected false for nil payload")
	}
}

func TestParseKafkaRequestHeaderFieldLayout(t *testing.T) {
	// size=8, APIKey=1, APIVersion=2, CorrelationID=100
	buf := []byte{0, 0, 0, 8, 0, 1, 0, 2, 0, 0, 0, 100}
	h, ok := ParseKafkaRequestHeader(buf)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if h.APIKey != 1 {
		t.Fatalf("APIKey: got %d, want 1", h.APIKey)
	}
	if h.APIVersion != 2 {
		t.Fatalf("APIVersion: got %d, want 2", h.APIVersion)
	}
	if h.CorrelationID != 100 {
		t.Fatalf("CorrelationID: got %d, want 100", h.CorrelationID)
	}
}
