package gitsrv

// PROXY protocol on the SSH listener (agentry#492). Behind a TCP proxy (the
// site's edge on production) every SSH connection's peer is the proxy, so
// the key-offer budget (agentry#410) keyed on the peer would be one budget
// for every client. The proxy prepends a PROXY header naming the client;
// this file reads it, from trusted peers only, and nothing else.
//
// Both versions of the header are read (haproxy's proxy-protocol.txt): v1,
// the text line nginx's stream `proxy_protocol on` sends, and v2, the binary
// form most balancers send. The reader never consumes a byte past the
// header, so the SSH handshake that follows reads the connection untouched.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// proxyV2Sig opens every v2 header.
var proxyV2Sig = []byte("\r\n\r\n\x00\r\nQUIT\n")

// proxyV1Max is the longest v1 line the specification allows, CRLF included.
const proxyV1Max = 107

// errNoProxyHeader is a connection from a trusted peer that did not start
// with a PROXY header.
var errNoProxyHeader = errors.New("no PROXY protocol header")

// readProxyHeader reads one PROXY header from r and returns the client's
// address. ok is false for a header that names no client (v1 UNKNOWN, v2
// LOCAL: a proxy's own health check), in which case the caller keeps the
// peer. Anything that is not a well-formed header is an error.
func readProxyHeader(r io.Reader) (addr netip.AddrPort, ok bool, err error) {
	head := make([]byte, 12)
	if _, err := io.ReadFull(r, head); err != nil {
		return netip.AddrPort{}, false, fmt.Errorf("proxy header: %w", err)
	}
	if bytes.Equal(head, proxyV2Sig) {
		return readProxyV2(r)
	}
	if !bytes.HasPrefix(head, []byte("PROXY ")) {
		return netip.AddrPort{}, false, errNoProxyHeader
	}
	return readProxyV1(r, head)
}

// readProxyV1 finishes a v1 line whose first bytes are head.
func readProxyV1(r io.Reader, head []byte) (netip.AddrPort, bool, error) {
	line := append([]byte(nil), head...)
	one := make([]byte, 1)
	for !bytes.HasSuffix(line, []byte("\r\n")) {
		if len(line) >= proxyV1Max {
			return netip.AddrPort{}, false, errors.New("proxy header: v1 line too long")
		}
		if _, err := io.ReadFull(r, one); err != nil {
			return netip.AddrPort{}, false, fmt.Errorf("proxy header: %w", err)
		}
		line = append(line, one[0])
	}
	f := strings.Split(strings.TrimSuffix(string(line), "\r\n"), " ")
	if len(f) >= 2 && f[1] == "UNKNOWN" {
		return netip.AddrPort{}, false, nil
	}
	if len(f) != 6 || (f[1] != "TCP4" && f[1] != "TCP6") {
		return netip.AddrPort{}, false, errors.New("proxy header: malformed v1 line")
	}
	src, err := netip.ParseAddr(f[2])
	if err != nil || src.Zone() != "" || (f[1] == "TCP4") != src.Is4() {
		return netip.AddrPort{}, false, errors.New("proxy header: bad v1 source address")
	}
	if _, err := netip.ParseAddr(f[3]); err != nil {
		return netip.AddrPort{}, false, errors.New("proxy header: bad v1 destination address")
	}
	sport, err := strconv.ParseUint(f[4], 10, 16)
	if err != nil {
		return netip.AddrPort{}, false, errors.New("proxy header: bad v1 source port")
	}
	if _, err := strconv.ParseUint(f[5], 10, 16); err != nil {
		return netip.AddrPort{}, false, errors.New("proxy header: bad v1 destination port")
	}
	return netip.AddrPortFrom(src.Unmap(), uint16(sport)), true, nil
}

// readProxyV2 finishes a v2 header after its signature.
func readProxyV2(r io.Reader) (netip.AddrPort, bool, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return netip.AddrPort{}, false, fmt.Errorf("proxy header: %w", err)
	}
	if hdr[0]>>4 != 2 {
		return netip.AddrPort{}, false, errors.New("proxy header: unsupported v2 version")
	}
	cmd, fam := hdr[0]&0x0f, hdr[1]
	n := int(binary.BigEndian.Uint16(hdr[2:]))
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return netip.AddrPort{}, false, fmt.Errorf("proxy header: %w", err)
	}
	switch cmd {
	case 0: // LOCAL: the proxy speaking for itself
		return netip.AddrPort{}, false, nil
	case 1: // PROXY
	default:
		return netip.AddrPort{}, false, errors.New("proxy header: unsupported v2 command")
	}
	switch fam {
	case 0x11: // TCP over IPv4: src(4) dst(4) sport(2) dport(2)
		if n < 12 {
			return netip.AddrPort{}, false, errors.New("proxy header: short v2 IPv4 block")
		}
		src := netip.AddrFrom4([4]byte(body[0:4]))
		return netip.AddrPortFrom(src, binary.BigEndian.Uint16(body[8:10])), true, nil
	case 0x21: // TCP over IPv6: src(16) dst(16) sport(2) dport(2)
		if n < 36 {
			return netip.AddrPort{}, false, errors.New("proxy header: short v2 IPv6 block")
		}
		src := netip.AddrFrom16([16]byte(body[0:16])).Unmap()
		return netip.AddrPortFrom(src, binary.BigEndian.Uint16(body[32:34])), true, nil
	case 0x00: // UNSPEC: no address to believe
		return netip.AddrPort{}, false, nil
	default:
		return netip.AddrPort{}, false, errors.New("proxy header: unsupported v2 address family")
	}
}

// proxiedConn is a connection whose RemoteAddr is the client a trusted
// PROXY header named, so everything downstream (the SSH handshake's
// ConnMetadata, the key-offer budget, the log lines) sees the client.
type proxiedConn struct {
	net.Conn
	remote net.Addr
}

func (c *proxiedConn) RemoteAddr() net.Addr { return c.remote }
