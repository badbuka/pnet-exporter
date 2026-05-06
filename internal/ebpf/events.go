package ebpf

import (
	"fmt"
	"net/netip"

	"pnet-exporter/internal/store"
)

type EventKind uint8

const (
	EventTCPListen EventKind = iota + 1
	EventTCPSuccessfulConnect
	EventTCPFailedConnect
	EventTCPActiveConnections
	EventTCPRetransmit
	EventTCPBytesSent
	EventTCPBytesReceived
	EventProtocol
	EventDNS
)

type SocketTuple struct {
	SourceAddress      [16]byte
	DestinationAddress [16]byte
	SourcePort         uint16
	DestinationPort    uint16
	Family             uint16
}

func (t SocketTuple) Destination() string {
	return endpoint(t.DestinationAddress, t.DestinationPort, t.Family)
}

func endpoint(raw [16]byte, port uint16, family uint16) string {
	addr, ok := address(raw, family)
	if !ok {
		return ""
	}
	return fmt.Sprintf("%s:%d", addr.String(), port)
}

func address(raw [16]byte, family uint16) (netip.Addr, bool) {
	switch family {
	case 2:
		return netip.AddrFrom4([4]byte{raw[0], raw[1], raw[2], raw[3]}), true
	case 10:
		return netip.AddrFrom16(raw), true
	default:
		return netip.Addr{}, false
	}
}

type TCPEvent struct {
	Kind              EventKind
	Container         store.ContainerLabels
	Tuple             SocketTuple
	ActualDestination string
	Value             uint64
}
