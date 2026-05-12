package protocol

import "testing"

func TestParseDNSResponseAnswers(t *testing.T) {
	// Hand-crafted minimal DNS response for example.com -> 93.184.216.34
	payload := []byte{
		0x12, 0x34, // id
		0x81, 0x80, // flags: response, recursion available
		0x00, 0x01, // qdcount
		0x00, 0x01, // ancount
		0x00, 0x00, // nscount
		0x00, 0x00, // arcount
		// QNAME: example.com
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		3, 'c', 'o', 'm',
		0,
		0x00, 0x01, // QTYPE A
		0x00, 0x01, // QCLASS IN
		// Answer: pointer to QNAME at offset 12
		0xc0, 0x0c,
		0x00, 0x01, // TYPE A
		0x00, 0x01, // CLASS IN
		0x00, 0x00, 0x00, 0x3c, // TTL 60
		0x00, 0x04, // RDLENGTH 4
		93, 184, 216, 34,
	}

	resp, ok := ParseDNSResponse(payload)
	if !ok {
		t.Fatal("expected response to parse")
	}
	if resp.Status != "ok" {
		t.Fatalf("status: %q", resp.Status)
	}
	if len(resp.Questions) != 1 || resp.Questions[0].Name != "example.com" || resp.Questions[0].Type != "A" {
		t.Fatalf("unexpected questions: %#v", resp.Questions)
	}
	if len(resp.Answers) != 1 || resp.Answers[0].IP != "93.184.216.34" || resp.Answers[0].Name != "example.com" {
		t.Fatalf("unexpected answers: %#v", resp.Answers)
	}
}

func TestParseDNSResponseRejectsQueries(t *testing.T) {
	// flags=0 means query, not response
	payload := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	if _, ok := ParseDNSResponse(payload); ok {
		t.Fatal("expected query to be rejected")
	}
}

func TestParseDNSResponseAAAA(t *testing.T) {
	// Hand-crafted DNS response: localhost. -> ::1 (AAAA)
	payload := []byte{
		0x00, 0x01, // id
		0x81, 0x80, // flags: response, recursion available
		0x00, 0x01, // qdcount
		0x00, 0x01, // ancount
		0x00, 0x00, // nscount
		0x00, 0x00, // arcount
		// QNAME: localhost
		9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't',
		0,
		0x00, 0x1c, // QTYPE AAAA
		0x00, 0x01, // QCLASS IN
		// Answer: pointer to QNAME at offset 12
		0xc0, 0x0c,
		0x00, 0x1c, // TYPE AAAA
		0x00, 0x01, // CLASS IN
		0x00, 0x00, 0x00, 0x3c, // TTL 60
		0x00, 0x10, // RDLENGTH 16
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // ::1
	}

	resp, ok := ParseDNSResponse(payload)
	if !ok {
		t.Fatal("expected response to parse")
	}
	if len(resp.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answers))
	}
	if resp.Answers[0].IP != "::1" {
		t.Fatalf("expected ::1, got %q", resp.Answers[0].IP)
	}
	if resp.Answers[0].Name != "localhost" {
		t.Fatalf("expected localhost, got %q", resp.Answers[0].Name)
	}
}

func TestParseDNSResponseNXDOMAIN(t *testing.T) {
	// flags: response (0x8000) + RCODE=3 (NXDOMAIN) = 0x8003
	payload := []byte{
		0x00, 0x01, // id
		0x80, 0x03, // flags: response + NXDOMAIN
		0x00, 0x00, // qdcount
		0x00, 0x00, // ancount
		0x00, 0x00, // nscount
		0x00, 0x00, // arcount
	}
	resp, ok := ParseDNSResponse(payload)
	if !ok {
		t.Fatal("expected response to parse")
	}
	if resp.Status != "error" {
		t.Fatalf("expected status error, got %q", resp.Status)
	}
}
