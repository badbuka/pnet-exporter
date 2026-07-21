package ebpf

import (
	"testing"

	"pnet-exporter/internal/identity"
	"pnet-exporter/internal/store"
)

func l7Tuple(dport uint16) SocketTuple {
	var tuple SocketTuple
	tuple.Family = familyIPv4
	tuple.SourceAddress = [16]byte{10, 0, 0, 5}
	tuple.SourcePort = 51234
	tuple.DestinationAddress = [16]byte{10, 0, 0, 9}
	tuple.DestinationPort = dport
	return tuple
}

func TestDispatchL7PairsRequestAndResponse(t *testing.T) {
	loader, metricStore, cache := newTestLoader(t, false)
	cache.Replace([]identity.Container{{ID: "c1", Name: "web", CgroupID: 42, PID: 100}})

	loader.dispatchL7(L7Event{
		Kind:      EventL7,
		Direction: DirRequest,
		CgroupID:  42,
		Tuple:     l7Tuple(8080),
		Payload:   []byte("GET /api HTTP/1.1\r\nHost: example\r\n\r\n"),
	})
	loader.dispatchL7(L7Event{
		Kind:      EventL7,
		Direction: DirResponse,
		CgroupID:  42,
		Tuple:     l7Tuple(8080),
		Payload:   []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
	})

	snap := metricStore.Snapshot()
	if len(snap.Protocol) != 1 {
		t.Fatalf("expected one protocol series, got %d", len(snap.Protocol))
	}
	series := snap.Protocol[0]
	if series.Protocol != store.ProtocolHTTP || series.Status != "200" || series.URL != "example/api" {
		t.Fatalf("unexpected series: %#v", series)
	}
	// The request entry must be consumed by Finish, not leaked.
	if got := loader.tracker.Len(); got != 0 {
		t.Fatalf("tracker leaked %d entries after a matched exchange", got)
	}
	if len(snap.ProtocolDur) != 1 {
		t.Fatalf("expected duration histogram from pairing, got %d", len(snap.ProtocolDur))
	}
}

func TestDispatchTCPListenUsesBindAddress(t *testing.T) {
	loader, metricStore, cache := newTestLoader(t, false)
	cache.Replace([]identity.Container{{ID: "c1", CgroupID: 42, PID: 100}})

	// Listening socket: source half carries the bind address, the
	// destination half (remote peer) is zero.
	var tuple SocketTuple
	tuple.Family = familyIPv4
	tuple.SourceAddress = [16]byte{0, 0, 0, 0}
	tuple.SourcePort = 8080
	loader.dispatchTCP(TCPEvent{Kind: EventTCPListen, CgroupID: 42, Tuple: tuple, Value: 1})

	snap := metricStore.Snapshot()
	if len(snap.Listens) != 1 || snap.Listens[0].ListenAddr != "0.0.0.0:8080" {
		t.Fatalf("listens: %#v", snap.Listens)
	}
}

func TestDispatchTCPCloseDecrementsActive(t *testing.T) {
	loader, metricStore, cache := newTestLoader(t, false)
	cache.Replace([]identity.Container{{ID: "c1", CgroupID: 42, PID: 100}})

	loader.dispatchTCP(TCPEvent{Kind: EventTCPSuccessfulConnect, CgroupID: 42, Tuple: l7Tuple(8080), Value: 1})
	loader.dispatchTCP(TCPEvent{Kind: EventTCPClose, CgroupID: 42, Tuple: l7Tuple(8080), Value: 1})

	snap := metricStore.Snapshot()
	if len(snap.Active) != 1 || snap.Active[0].Value != 0 {
		t.Fatalf("active after close: %#v", snap.Active)
	}
	if len(snap.Successful) != 1 || snap.Successful[0].Value != 1 {
		t.Fatalf("successful counter must survive close: %#v", snap.Successful)
	}
}
