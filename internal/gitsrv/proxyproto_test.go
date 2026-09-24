package gitsrv

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
)

func v2Header(cmd, fam byte, body []byte) []byte {
	b := append([]byte(nil), proxyV2Sig...)
	b = append(b, 0x20|cmd, fam, 0, 0)
	binary.BigEndian.PutUint16(b[14:], uint16(len(body)))
	return append(b, body...)
}

func TestReadProxyHeader(t *testing.T) {
	v4 := append(append(netip.MustParseAddr("203.0.113.9").AsSlice(), netip.MustParseAddr("10.0.0.5").AsSlice()...), 0xd4, 0x31, 0x00, 0x16)
	v6 := append(append(netip.MustParseAddr("2001:db8::7").AsSlice(), netip.MustParseAddr("2001:db8::1").AsSlice()...), 0x04, 0xd2, 0x00, 0x16)
	cases := []struct {
		name    string
		in      []byte
		want    string // "" = no client named
		wantErr bool
	}{
		{"v1 tcp4", []byte("PROXY TCP4 203.0.113.9 10.0.0.5 54321 22\r\n"), "203.0.113.9:54321", false},
		{"v1 tcp6", []byte("PROXY TCP6 2001:db8::7 2001:db8::1 1234 22\r\n"), "[2001:db8::7]:1234", false},
		{"v1 unknown", []byte("PROXY UNKNOWN\r\n"), "", false},
		{"v1 family mismatch", []byte("PROXY TCP4 2001:db8::7 10.0.0.5 1 22\r\n"), "", true},
		{"v1 bad port", []byte("PROXY TCP4 203.0.113.9 10.0.0.5 99999 22\r\n"), "", true},
		{"v1 missing field", []byte("PROXY TCP4 203.0.113.9 10.0.0.5 1\r\n"), "", true},
		{"v1 too long", []byte("PROXY TCP4 " + strings.Repeat("1", 120) + "\r\n"), "", true},
		{"v1 truncated", []byte("PROXY TCP4 203.0.113.9"), "", true},
		{"v2 tcp4", v2Header(1, 0x11, v4), "203.0.113.9:54321", false},
		{"v2 tcp6", v2Header(1, 0x21, v6), "[2001:db8::7]:1234", false},
		{"v2 tcp4 with TLVs", v2Header(1, 0x11, append(append([]byte(nil), v4...), 0x04, 0x00, 0x01, 0x00)), "203.0.113.9:54321", false},
		{"v2 local", v2Header(0, 0x00, nil), "", false},
		{"v2 tcp6 carrying a mapped IPv4 source", v2Header(1, 0x21, append(append(netip.MustParseAddr("::ffff:203.0.113.9").AsSlice(), netip.MustParseAddr("2001:db8::1").AsSlice()...), 0x00, 0x50, 0x00, 0x16)), "203.0.113.9:80", false},
		{"v1 tcp6 carrying a mapped IPv4 source", []byte("PROXY TCP6 ::ffff:203.0.113.9 2001:db8::1 80 22\r\n"), "203.0.113.9:80", false},
		{"v2 version 1 refused", append(append([]byte(nil), proxyV2Sig...), 0x11, 0x11, 0, 12), "", true},
		{"v2 length past the data", append(v2Header(1, 0x11, v4)[:16:16], v4[:4]...), "", true},
		{"v2 short ipv4 block", v2Header(1, 0x11, v4[:8]), "", true},
		{"v2 udp refused", v2Header(1, 0x12, v4), "", true},
		{"v2 bad command", v2Header(3, 0x11, v4), "", true},
		{"ssh banner, no header", []byte("SSH-2.0-OpenSSH_9.9\r\n"), "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr, ok, err := readProxyHeader(bytes.NewReader(tc.in))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("accepted %q as %v", tc.in, addr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got := ""
			if ok {
				got = addr.String()
			}
			if got != tc.want {
				t.Fatalf("client = %q, want %q", got, tc.want)
			}
		})
	}
}

// The header is read exactly: the SSH banner after it is left for the
// handshake.
func TestReadProxyHeaderConsumesOnlyTheHeader(t *testing.T) {
	for _, hdr := range [][]byte{
		[]byte("PROXY TCP4 203.0.113.9 10.0.0.5 54321 22\r\n"),
		v2Header(1, 0x11, append(append(netip.MustParseAddr("203.0.113.9").AsSlice(), 10, 0, 0, 5), 0, 1, 0, 22)),
	} {
		r := bytes.NewReader(append(append([]byte(nil), hdr...), "SSH-2.0-client\r\n"...))
		if _, _, err := readProxyHeader(r); err != nil {
			t.Fatal(err)
		}
		rest := make([]byte, r.Len())
		_, _ = r.Read(rest)
		if string(rest) != "SSH-2.0-client\r\n" {
			t.Fatalf("left %q for the handshake", rest)
		}
	}
}
