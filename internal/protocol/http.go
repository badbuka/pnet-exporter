package protocol

import (
	"bytes"
	"strconv"
	"strings"
)

type HTTPRequest struct {
	Method string
	Path   string
	// URL is the full request URL used as a metric label: the Host header
	// joined with the request path (e.g. "example.com/api"). When the
	// request carries no Host header it falls back to the path alone.
	// The query string is stripped to keep label cardinality bounded.
	URL string
}

func ParseHTTPRequest(payload []byte) (HTTPRequest, bool) {
	line, rest, ok := bytes.Cut(payload, []byte("\r\n"))
	if !ok {
		return HTTPRequest{}, false
	}
	parts := strings.SplitN(string(line), " ", 3)
	if len(parts) != 3 || !strings.HasPrefix(parts[2], "HTTP/") {
		return HTTPRequest{}, false
	}

	path := parts[1]
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}

	url := path
	if host := parseHostHeader(rest); host != "" {
		url = host + path
	}

	return HTTPRequest{Method: parts[0], Path: parts[1], URL: url}, true
}

// parseHostHeader scans the header section of an HTTP/1.x request (the bytes
// following the request line) for the first "Host" header and returns its
// value. The match is case-insensitive per RFC 7230. It returns "" when no
// Host header is present within the captured payload, which can happen if the
// header was pushed beyond the fixed payload capture window.
func parseHostHeader(headers []byte) string {
	for len(headers) > 0 {
		line, rest, _ := bytes.Cut(headers, []byte("\r\n"))
		if len(line) == 0 {
			break
		}
		headers = rest
		name, value, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(string(name)), "host") {
			return strings.TrimSpace(string(value))
		}
	}
	return ""
}

func ParseHTTPStatus(payload []byte) (string, bool) {
	line, _, ok := bytes.Cut(payload, []byte("\r\n"))
	if !ok {
		return "", false
	}
	parts := strings.SplitN(string(line), " ", 3)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/") {
		return "", false
	}
	// status-code is exactly 3DIGIT (RFC 9110 section 15). Enforcing the
	// length keeps arbitrary integers out of the `status` metric label,
	// which would otherwise be an unbounded cardinality source controlled
	// by remote servers.
	if len(parts[1]) != 3 {
		return "", false
	}
	if _, err := strconv.Atoi(parts[1]); err != nil {
		return "", false
	}
	return parts[1], true
}

// http2Preface is the fixed 24-byte client connection preface that opens
// every cleartext (h2c) HTTP/2 connection (RFC 7540 section 3.5).
const http2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// IsHTTP2Preface reports whether payload begins with the HTTP/2 client
// connection preface, which is the most reliable signal that a flow is
// cleartext HTTP/2. TLS-wrapped HTTP/2 never exposes this in plaintext.
func IsHTTP2Preface(payload []byte) bool {
	return bytes.HasPrefix(payload, []byte(http2Preface))
}

const (
	http2FrameHeaderLen = 9
	http2FrameTypeHeads = 0x1
	http2FlagPadded     = 0x8
	http2FlagPriority   = 0x20
	// hpackStatusNameIndex is the HPACK static table index of the
	// ":status" pseudo-header (RFC 7541 appendix A).
	hpackStatusNameIndex = 8
)

// http2StaticStatus maps the HPACK static table indices that carry a fully
// indexed ":status" value to the corresponding HTTP status code.
var http2StaticStatus = map[int]string{
	8:  "200",
	9:  "204",
	10: "206",
	11: "304",
	12: "400",
	13: "404",
	14: "500",
}

// ParseHTTP2Status extracts the HTTP status code from a cleartext HTTP/2
// response on a best-effort basis. It walks the binary frame layer to the
// first HEADERS frame and resolves the HPACK ":status" pseudo-header across
// its three encodings: the HPACK-indexed codes (200/204/206/304/400/404/500),
// plain literal values, and Huffman literal values. Literal values - for any
// status code - are matched against precomputed tables rather than decoded.
//
// Statuses split across CONTINUATION frames yield ("", false); the caller
// normalizes that to "unknown". The 256-byte payload capture may also
// truncate a large header block, in which case detection silently fails.
func ParseHTTP2Status(payload []byte) (string, bool) {
	buf := payload
	if bytes.HasPrefix(buf, []byte(http2Preface)) {
		buf = buf[len(http2Preface):]
	}

	for iter := 0; len(buf) >= http2FrameHeaderLen && iter < 16; iter++ {
		length := int(buf[0])<<16 | int(buf[1])<<8 | int(buf[2])
		ftype := buf[3]
		flags := buf[4]
		body := buf[http2FrameHeaderLen:]
		if length > len(body) {
			// Capture was truncated mid-frame; parse what we have.
			length = len(body)
		}
		frame := body[:length]

		if ftype == http2FrameTypeHeads {
			block := frame
			if flags&http2FlagPadded != 0 && len(block) > 0 {
				padLen := int(block[0])
				block = block[1:]
				if padLen <= len(block) {
					block = block[:len(block)-padLen]
				}
			}
			if flags&http2FlagPriority != 0 && len(block) >= 5 {
				block = block[5:]
			}
			return hpackFindStatus(block)
		}

		adv := http2FrameHeaderLen + length
		if adv >= len(buf) {
			break
		}
		buf = buf[adv:]
	}
	return "", false
}

// hpackFindStatus walks an HPACK header block field by field and returns the
// ":status" value when it can be decoded. It advances correctly over fields
// it does not care about so the scan stays aligned.
func hpackFindStatus(block []byte) (string, bool) {
	for i, iter := 0, 0; i < len(block) && iter < 64; iter++ {
		b := block[i]
		switch {
		case b&0x80 != 0: // 1xxxxxxx indexed header field
			idx, n, ok := hpackInt(block[i:], 7)
			if !ok {
				return "", false
			}
			if status, found := http2StaticStatus[idx]; found {
				return status, true
			}
			i += n
		case b&0xc0 == 0x40: // 01xxxxxx literal with incremental indexing
			status, n, ok := hpackLiteralStatus(block[i:], 6)
			if ok {
				return status, true
			}
			if n == 0 {
				return "", false
			}
			i += n
		case b&0xe0 == 0x20: // 001xxxxx dynamic table size update (no value)
			_, n, ok := hpackInt(block[i:], 5)
			if !ok {
				return "", false
			}
			i += n
		default: // 0000xxxx / 0001xxxx literal without / never indexed
			status, n, ok := hpackLiteralStatus(block[i:], 4)
			if ok {
				return status, true
			}
			if n == 0 {
				return "", false
			}
			i += n
		}
	}
	return "", false
}

// hpackLiteralStatus parses a single literal header field whose name-index
// uses the given prefix width. When the field names ":status" (static index
// 8) and carries a plain numeric value it returns that status. The second
// return value is the number of bytes consumed so the walker can advance even
// when the field is not a usable status; a zero count signals a parse error.
func hpackLiteralStatus(buf []byte, prefixBits uint8) (string, int, bool) {
	nameIdx, n, ok := hpackInt(buf, prefixBits)
	if !ok {
		return "", 0, false
	}
	pos := n
	isStatus := nameIdx == hpackStatusNameIndex
	if nameIdx == 0 {
		// Literal name string precedes the value; we don't match names by
		// content, so this field is never treated as :status.
		_, _, nameLen, ok := hpackString(buf[pos:])
		if !ok {
			return "", 0, false
		}
		pos += nameLen
		isStatus = false
	}

	val, huffman, valLen, ok := hpackString(buf[pos:])
	if !ok {
		return "", 0, false
	}
	pos += valLen

	if isStatus {
		if status, ok := hpackStatusValue(val, huffman); ok {
			return status, pos, true
		}
	}
	return "", pos, false
}

// httpStatusCodes enumerates every syntactically valid HTTP status code.
// HTTP mandates a three-digit code, so this is the 100-599 range.
var httpStatusCodes = buildHTTPStatusCodes()

// huffmanStatusTable maps the HPACK Huffman encoding of each status code to
// the code string. It is precomputed for every code in httpStatusCodes, so a
// Huffman-coded ":status" value is resolved by an exact byte-slice lookup
// instead of a runtime Huffman decoder.
var huffmanStatusTable = buildHuffmanStatusTable()

func buildHTTPStatusCodes() map[string]struct{} {
	codes := make(map[string]struct{}, 500)
	for code := 100; code <= 599; code++ {
		codes[strconv.Itoa(code)] = struct{}{}
	}
	return codes
}

func buildHuffmanStatusTable() map[string]string {
	table := make(map[string]string, len(httpStatusCodes))
	for code := range httpStatusCodes {
		table[string(huffmanEncodeDigits(code))] = code
	}
	return table
}

// huffmanEncodeDigits returns the HPACK Huffman encoding of a numeric string.
// Each ASCII digit 0-9 maps to the 5-bit code equal to its value (RFC 7541
// appendix B); the trailing partial byte is padded with 1-bits per HPACK.
func huffmanEncodeDigits(s string) []byte {
	var (
		out   []byte
		bits  uint
		count uint
	)
	for _, c := range s {
		bits = bits<<5 | uint(c-'0')
		count += 5
		for count >= 8 {
			count -= 8
			out = append(out, byte(bits>>count))
		}
	}
	if count > 0 {
		pad := 8 - count
		out = append(out, byte(bits<<pad)|byte((1<<pad)-1))
	}
	return out
}

// hpackStatusValue resolves an HPACK ":status" value against the precomputed
// status tables: plain values are checked against the set of valid codes and
// Huffman values are matched by their exact encoding. No runtime Huffman
// decoding is performed.
func hpackStatusValue(value []byte, huffman bool) (string, bool) {
	if huffman {
		code, ok := huffmanStatusTable[string(value)]
		return code, ok
	}
	if _, ok := httpStatusCodes[string(value)]; ok {
		return string(value), true
	}
	return "", false
}

// hpackInt decodes an HPACK variable-length integer with an n-bit prefix
// (RFC 7541 section 5.1) from the front of buf. It returns the value and the
// number of bytes consumed.
func hpackInt(buf []byte, prefixBits uint8) (int, int, bool) {
	if len(buf) == 0 {
		return 0, 0, false
	}
	mask := (1 << prefixBits) - 1
	value := int(buf[0]) & mask
	if value < mask {
		return value, 1, true
	}
	shift := 0
	for i := 1; ; i++ {
		if i >= len(buf) || i > 6 {
			return 0, 0, false
		}
		b := buf[i]
		value += int(b&0x7f) << shift
		if b&0x80 == 0 {
			return value, i + 1, true
		}
		shift += 7
	}
}

// hpackString decodes an HPACK string literal (RFC 7541 section 5.2) from the
// front of buf. It reports whether the value was Huffman-encoded and the
// number of bytes consumed; the raw (still Huffman-encoded) bytes are returned
// so callers can match them against a precomputed table.
func hpackString(buf []byte) (value []byte, huffman bool, consumed int, ok bool) {
	if len(buf) == 0 {
		return nil, false, 0, false
	}
	huffman = buf[0]&0x80 != 0
	length, intLen, ok := hpackInt(buf, 7)
	if !ok {
		return nil, false, 0, false
	}
	end := intLen + length
	if end > len(buf) {
		return nil, false, 0, false
	}
	return buf[intLen:end], huffman, end, true
}
