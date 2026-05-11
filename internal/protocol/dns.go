package protocol

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
)

// DNSResponse is a minimal decoded view of a DNS response packet
// suitable for emitting per-question request totals and per-answer
// ip_to_fqdn mappings.
type DNSResponse struct {
	Status    string
	Questions []DNSQuestion
	Answers   []DNSAnswer
}

type DNSQuestion struct {
	Name string
	Type string
}

type DNSAnswer struct {
	Name string
	IP   string
}

// ParseDNSResponse parses a DNS response packet from a UDP payload. It
// is deliberately tolerant of malformed packets: as soon as a field
// can't be read it returns whatever was decoded successfully so far.
func ParseDNSResponse(payload []byte) (DNSResponse, bool) {
	if len(payload) < 12 {
		return DNSResponse{}, false
	}
	flags := binary.BigEndian.Uint16(payload[2:4])
	if flags&0x8000 == 0 {
		// Not a response.
		return DNSResponse{}, false
	}
	rcode := flags & 0x000F
	status := "ok"
	if rcode != 0 {
		status = "error"
	}
	qdcount := int(binary.BigEndian.Uint16(payload[4:6]))
	ancount := int(binary.BigEndian.Uint16(payload[6:8]))

	offset := 12
	resp := DNSResponse{Status: status}
	for i := 0; i < qdcount && offset < len(payload); i++ {
		name, next, ok := readName(payload, offset)
		if !ok || next+4 > len(payload) {
			return resp, len(resp.Questions) > 0 || len(resp.Answers) > 0
		}
		qtype := binary.BigEndian.Uint16(payload[next : next+2])
		resp.Questions = append(resp.Questions, DNSQuestion{
			Name: strings.TrimSuffix(name, "."),
			Type: dnsTypeName(qtype),
		})
		offset = next + 4
	}
	for i := 0; i < ancount && offset < len(payload); i++ {
		name, next, ok := readName(payload, offset)
		if !ok || next+10 > len(payload) {
			break
		}
		atype := binary.BigEndian.Uint16(payload[next : next+2])
		rdlength := int(binary.BigEndian.Uint16(payload[next+8 : next+10]))
		rdataStart := next + 10
		if rdataStart+rdlength > len(payload) {
			break
		}
		switch atype {
		case 1: // A
			if rdlength == 4 {
				ip := netip.AddrFrom4([4]byte{
					payload[rdataStart],
					payload[rdataStart+1],
					payload[rdataStart+2],
					payload[rdataStart+3],
				})
				resp.Answers = append(resp.Answers, DNSAnswer{
					Name: strings.TrimSuffix(name, "."),
					IP:   ip.String(),
				})
			}
		case 28: // AAAA
			if rdlength == 16 {
				var raw [16]byte
				copy(raw[:], payload[rdataStart:rdataStart+16])
				resp.Answers = append(resp.Answers, DNSAnswer{
					Name: strings.TrimSuffix(name, "."),
					IP:   netip.AddrFrom16(raw).String(),
				})
			}
		}
		offset = rdataStart + rdlength
	}
	return resp, true
}

func readName(payload []byte, offset int) (string, int, bool) {
	var name strings.Builder
	// Guard against pointer loops by limiting how many compression
	// jumps we'll follow.
	jumps := 0
	original := offset
	final := -1
	for {
		if offset >= len(payload) {
			return "", 0, false
		}
		length := int(payload[offset])
		if length == 0 {
			offset++
			break
		}
		if length&0xC0 == 0xC0 {
			if offset+1 >= len(payload) {
				return "", 0, false
			}
			target := int(binary.BigEndian.Uint16(payload[offset:offset+2])) & 0x3FFF
			if final < 0 {
				final = offset + 2
			}
			offset = target
			jumps++
			if jumps > 8 {
				return "", 0, false
			}
			continue
		}
		offset++
		if offset+length > len(payload) {
			return "", 0, false
		}
		name.Write(payload[offset : offset+length])
		name.WriteByte('.')
		offset += length
	}
	if final < 0 {
		final = offset
	}
	_ = original
	return name.String(), final, true
}

func dnsTypeName(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 28:
		return "AAAA"
	case 5:
		return "CNAME"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 33:
		return "SRV"
	case 12:
		return "PTR"
	case 2:
		return "NS"
	case 6:
		return "SOA"
	default:
		return fmt.Sprintf("TYPE%d", t)
	}
}
