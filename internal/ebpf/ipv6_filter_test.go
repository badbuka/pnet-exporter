package ebpf

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"pnet-exporter/internal/config"
	"pnet-exporter/internal/identity"
	"pnet-exporter/internal/protocol"
	"pnet-exporter/internal/store"
)

func newTestLoader(t *testing.T, dropIPv6 bool) (*Loader, *store.Store, *identity.Cache) {
	t.Helper()
	classifier, err := protocol.NewClassifier(nil)
	if err != nil {
		t.Fatalf("new classifier: %v", err)
	}
	cache := identity.NewCache(time.Minute)
	metricStore := store.New(config.Default().Store)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	loader := NewLoader(config.Default().EBPF, classifier, cache, metricStore, logger, dropIPv6)
	return loader, metricStore, cache
}

func tcpConnectEvent(family uint16) TCPEvent {
	return TCPEvent{
		Kind:     EventTCPSuccessfulConnect,
		CgroupID: 100,
		Tuple: SocketTuple{
			DestinationPort: 443,
			Family:          family,
		},
		Value: 1,
	}
}

func TestDispatchTCPDropsIPv6WhenDisabled(t *testing.T) {
	loader, metricStore, _ := newTestLoader(t, true)

	loader.dispatchTCP(tcpConnectEvent(familyIPv6))
	if got := len(metricStore.Snapshot().Successful); got != 0 {
		t.Fatalf("expected IPv6 connect to be dropped, got %d series", got)
	}

	loader.dispatchTCP(tcpConnectEvent(familyIPv4))
	if got := len(metricStore.Snapshot().Successful); got != 1 {
		t.Fatalf("expected IPv4 connect to be recorded, got %d series", got)
	}
}

func TestDispatchTCPKeepsIPv6WhenEnabled(t *testing.T) {
	loader, metricStore, _ := newTestLoader(t, false)

	loader.dispatchTCP(tcpConnectEvent(familyIPv6))
	if got := len(metricStore.Snapshot().Successful); got != 1 {
		t.Fatalf("expected IPv6 connect to be recorded, got %d series", got)
	}
}

// dnsAAAAResponse is a hand-crafted DNS response for localhost. -> ::1 (AAAA).
func dnsAAAAResponse() []byte {
	return []byte{
		0x00, 0x01, // id
		0x81, 0x80, // flags: response, recursion available
		0x00, 0x01, // qdcount
		0x00, 0x01, // ancount
		0x00, 0x00, // nscount
		0x00, 0x00, // arcount
		9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't',
		0,
		0x00, 0x1c, // QTYPE AAAA
		0x00, 0x01, // QCLASS IN
		0xc0, 0x0c, // pointer to QNAME
		0x00, 0x1c, // TYPE AAAA
		0x00, 0x01, // CLASS IN
		0x00, 0x00, 0x00, 0x3c, // TTL 60
		0x00, 0x10, // RDLENGTH 16
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // ::1
	}
}

func dnsAAAAEvent(family uint16) DNSWireEvent {
	payload := dnsAAAAResponse()
	return DNSWireEvent{
		Kind:       EventDNS,
		Direction:  DirResponse,
		CgroupID:   200,
		Tuple:      SocketTuple{Family: family},
		PayloadLen: uint16(len(payload)),
		Payload:    payload,
	}
}

// dnsAResponse is a hand-crafted DNS response for example.com -> 93.184.216.34 (A).
func dnsAResponse() []byte {
	return []byte{
		0x12, 0x34, // id
		0x81, 0x80, // flags: response, recursion available
		0x00, 0x01, // qdcount
		0x00, 0x01, // ancount
		0x00, 0x00, // nscount
		0x00, 0x00, // arcount
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		3, 'c', 'o', 'm',
		0,
		0x00, 0x01, // QTYPE A
		0x00, 0x01, // QCLASS IN
		0xc0, 0x0c, // pointer to QNAME
		0x00, 0x01, // TYPE A
		0x00, 0x01, // CLASS IN
		0x00, 0x00, 0x00, 0x3c, // TTL 60
		0x00, 0x04, // RDLENGTH 4
		93, 184, 216, 34,
	}
}

func dnsAEvent(family uint16) DNSWireEvent {
	payload := dnsAResponse()
	return DNSWireEvent{
		Kind:       EventDNS,
		Direction:  DirResponse,
		CgroupID:   200,
		Tuple:      SocketTuple{Family: family},
		PayloadLen: uint16(len(payload)),
		Payload:    payload,
	}
}

func TestDispatchDNSDropsAAAAMappingWhenDisabled(t *testing.T) {
	loader, metricStore, cache := newTestLoader(t, true)
	cache.Upsert(identity.Container{ID: "abc", Name: "web", CgroupID: 200})

	// AAAA answer over IPv4 transport: the mapping itself is IPv6 and must drop.
	loader.dispatchDNS(dnsAAAAEvent(familyIPv4))
	if got := len(metricStore.Snapshot().IPToFQDN); got != 0 {
		t.Fatalf("expected AAAA ip_to_fqdn mapping to be dropped, got %d series", got)
	}
}

func TestDispatchDNSDropsAAAARequestWhenDisabled(t *testing.T) {
	loader, metricStore, cache := newTestLoader(t, true)
	cache.Upsert(identity.Container{ID: "abc", Name: "web", CgroupID: 200})

	// AAAA question over IPv4 transport: the request itself is for an IPv6
	// address and must not produce a container_dns_requests_total series.
	loader.dispatchDNS(dnsAAAAEvent(familyIPv4))
	if got := len(metricStore.Snapshot().DNSRequests); got != 0 {
		t.Fatalf("expected AAAA dns request to be dropped, got %d series", got)
	}
}

func TestDispatchDNSKeepsAAAAMappingWhenEnabled(t *testing.T) {
	loader, metricStore, cache := newTestLoader(t, false)
	cache.Upsert(identity.Container{ID: "abc", Name: "web", CgroupID: 200})

	loader.dispatchDNS(dnsAAAAEvent(familyIPv4))
	snap := metricStore.Snapshot()
	if len(snap.IPToFQDN) != 1 {
		t.Fatalf("expected AAAA ip_to_fqdn mapping to be recorded, got %d series", len(snap.IPToFQDN))
	}
	if snap.IPToFQDN[0].IP != "::1" {
		t.Fatalf("unexpected ip_to_fqdn IP: %q", snap.IPToFQDN[0].IP)
	}
}

func TestDispatchDNSKeepsIPv4DataOverIPv6Transport(t *testing.T) {
	loader, metricStore, cache := newTestLoader(t, true)
	cache.Upsert(identity.Container{ID: "abc", Name: "web", CgroupID: 200})

	// Resolvers commonly use an AF_INET6 socket even for A-record lookups,
	// so a DNS event over IPv6 transport must NOT discard its IPv4 data.
	loader.dispatchDNS(dnsAEvent(familyIPv6))
	snap := metricStore.Snapshot()
	if len(snap.DNSRequests) != 1 || snap.DNSRequests[0].RequestType != "A" {
		t.Fatalf("expected A dns request to survive IPv6 transport, got %#v", snap.DNSRequests)
	}
	if len(snap.IPToFQDN) != 1 || snap.IPToFQDN[0].IP != "93.184.216.34" {
		t.Fatalf("expected IPv4 ip_to_fqdn to survive IPv6 transport, got %#v", snap.IPToFQDN)
	}
}
