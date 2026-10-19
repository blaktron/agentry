package egressguard

import (
	"net/netip"
	"testing"
)

// The special-purpose registries the guard follows:
//
//	IPv4: https://www.iana.org/assignments/iana-ipv4-special-registry/
//	IPv6: https://www.iana.org/assignments/iana-ipv6-special-registry/
//	IPv6 global unicast space: https://www.iana.org/assignments/ipv6-address-space/
//
// Every row of those registries whose "Globally Reachable" value is False is
// refused, whole, with the loopback rows (127.0.0.0/8, ::1/128) left to the
// guard's loopback seam. A row with globally reachable sub-allocations
// (192.0.0.0/24 and 2001::/23 hold anycast service addresses such as the PCP
// and TURN anycast addresses) is refused whole: no endpoint someone names
// there is a host to deliver to.

// specialCases is one row per range the guard refuses: a prefix, the
// registry entry that makes it non-public, an address inside it and, where
// the neighbouring space is public, the closest public address on each side.
var specialCases = []struct {
	prefix  string
	source  string
	inside  []string
	outside []string
}{
	// IPv4 special-purpose registry.
	{"0.0.0.0/8", `"This network" (RFC 791)`, []string{"0.0.0.0", "0.1.2.3", "0.255.255.255"}, []string{"1.0.0.0"}},
	{"10.0.0.0/8", "Private-Use (RFC 1918)", []string{"10.0.0.1", "10.255.255.255"}, []string{"9.255.255.255", "11.0.0.0"}},
	{"100.64.0.0/10", "Shared Address Space (RFC 6598)", []string{"100.64.0.1", "100.127.255.255"}, []string{"100.63.255.255", "100.128.0.0"}},
	{"169.254.0.0/16", "Link Local (RFC 3927)", []string{"169.254.0.1", "169.254.169.254"}, []string{"169.253.255.255", "169.255.0.0"}},
	{"172.16.0.0/12", "Private-Use (RFC 1918)", []string{"172.16.0.1", "172.31.255.255"}, []string{"172.15.255.255", "172.32.0.0"}},
	{"192.0.0.0/24", "IETF Protocol Assignments (RFC 6890)", []string{"192.0.0.1", "192.0.0.9", "192.0.0.170", "192.0.0.255"}, []string{"191.255.255.255", "192.0.1.0"}},
	{"192.0.2.0/24", "Documentation, TEST-NET-1 (RFC 5737)", []string{"192.0.2.1", "192.0.2.255"}, []string{"192.0.1.255", "192.0.3.0"}},
	{"192.88.99.0/24", "Deprecated 6to4 Relay Anycast (RFC 7526)", []string{"192.88.99.1", "192.88.99.255"}, []string{"192.88.98.255", "192.88.100.0"}},
	{"192.168.0.0/16", "Private-Use (RFC 1918)", []string{"192.168.0.1", "192.168.255.255"}, []string{"192.167.255.255", "192.169.0.0"}},
	{"198.18.0.0/15", "Benchmarking (RFC 2544)", []string{"198.18.0.1", "198.19.255.255"}, []string{"198.17.255.255", "198.20.0.0"}},
	{"198.51.100.0/24", "Documentation, TEST-NET-2 (RFC 5737)", []string{"198.51.100.1", "198.51.100.255"}, []string{"198.51.99.255", "198.51.101.0"}},
	{"203.0.113.0/24", "Documentation, TEST-NET-3 (RFC 5737)", []string{"203.0.113.1", "203.0.113.255"}, []string{"203.0.112.255", "203.0.114.0"}},
	{"224.0.0.0/4", "Multicast (RFC 5771)", []string{"224.0.0.1", "239.255.255.255"}, []string{"223.255.255.255"}},
	{"240.0.0.0/4", "Reserved and Limited Broadcast (RFC 1112, RFC 8190)", []string{"240.0.0.1", "250.1.2.3", "255.255.255.255"}, nil},

	// IPv6 special-purpose registry.
	{"::/128", "Unspecified Address (RFC 4291)", []string{"::"}, nil},
	{"100::/64", "Discard-Only Address Block (RFC 6666)", []string{"100::1", "100::ffff:ffff:ffff:ffff"}, nil},
	{"100:0:0:1::/64", "Dummy IPv6 Prefix (RFC 9780)", []string{"100:0:0:1::1"}, nil},
	{"2001::/23", "IETF Protocol Assignments, with Teredo, benchmarking (RFC 5180) and ORCHID (RFC 2928, RFC 5180, RFC 7343)",
		[]string{"2001::1", "2001:0:4136:e378:8000:63bf:3fff:fdd2", "2001:2::1", "2001:10::1", "2001:1::1", "2001:1ff:ffff::1"}, []string{"2001:200::1"}},
	{"2001:db8::/32", "Documentation (RFC 3849)", []string{"2001:db8::1", "2001:db8:ffff::1"}, []string{"2001:db7:ffff::1", "2001:db9::1"}},
	{"3fff::/20", "Documentation (RFC 9637)", []string{"3fff::1", "3fff:fff:ffff::1"}, []string{"3ffe:ffff::1", "3fff:1000::1"}},
	{"5f00::/16", "Segment Routing SIDs (RFC 9602)", []string{"5f00::1"}, nil},
	{"64:ff9b:1::/48", "Local-Use IPv4/IPv6 Translation (RFC 8215)", []string{"64:ff9b:1::a00:1", "64:ff9b:1::808:808"}, nil},
	{"fc00::/7", "Unique-Local (RFC 4193)", []string{"fc00::1", "fdff:ffff::1"}, nil},
	{"fe80::/10", "Link-Local Unicast (RFC 4291)", []string{"fe80::1", "febf::1"}, nil},
	{"fec0::/10", "Deprecated Site-Local Unicast (RFC 3879)", []string{"fec0::1", "feff:ffff::1"}, nil},
	{"ff00::/8", "Multicast (RFC 4291)", []string{"ff02::1", "ff0e::1"}, nil},
}

func TestEverySpecialPurposeRangeIsRefused(t *testing.T) {
	g := Guard{}
	for _, c := range specialCases {
		for _, s := range c.inside {
			if g.IsAllowedIP(netip.MustParseAddr(s)) {
				t.Errorf("%s (%s) inside %s: allowed, want refused", s, c.source, c.prefix)
			}
		}
		for _, s := range c.outside {
			if !g.IsAllowedIP(netip.MustParseAddr(s)) {
				t.Errorf("%s next to %s: refused, want allowed", s, c.prefix)
			}
		}
	}
}

func TestUnallocatedIPv6SpaceIsRefused(t *testing.T) {
	g := Guard{}
	for _, s := range []string{"4000::1", "8000::1", "a000::1", "c000::1", "e000::1", "1000::1", "200::1", "6000::1"} {
		if g.IsAllowedIP(netip.MustParseAddr(s)) {
			t.Errorf("%s is outside 2000::/3: allowed, want refused", s)
		}
	}
	for _, s := range []string{"2000::1", "2606:4700:4700::1111", "2a00:1450:4001::1", "3ffe:ffff::1"} {
		if !g.IsAllowedIP(netip.MustParseAddr(s)) {
			t.Errorf("%s is inside 2000::/3: refused, want allowed", s)
		}
	}
}

// An address that embeds an IPv4 one is judged by the address it embeds.
func TestEmbeddedIPv4FormsDecideOnTheEmbeddedAddress(t *testing.T) {
	g := Guard{}
	cases := []struct {
		ip      string
		form    string
		allowed bool
	}{
		{"::ffff:0:a00:1", "IPv4-translated (RFC 2765) of 10.0.0.1", false},
		{"::ffff:0:7f00:1", "IPv4-translated of 127.0.0.1", false},
		{"::ffff:0:a9fe:a9fe", "IPv4-translated of 169.254.169.254", false},
		{"::ffff:0:c612:1", "IPv4-translated of 198.18.0.1", false},
		{"::ffff:0:f000:1", "IPv4-translated of 240.0.0.1", false},
		{"::ffff:0:808:808", "IPv4-translated of 8.8.8.8", true},
		{"2606:4700::5efe:a00:1", "ISATAP (RFC 5214) of 10.0.0.1", false},
		{"2606:4700::200:5efe:a00:1", "ISATAP, global-scope identifier, of 10.0.0.1", false},
		{"2606:4700::5efe:7f00:1", "ISATAP of 127.0.0.1", false},
		{"2606:4700::5efe:c0a8:1", "ISATAP of 192.168.0.1", false},
		{"2606:4700::5efe:c000:201", "ISATAP of 192.0.2.1", false},
		{"2606:4700::5efe:808:808", "ISATAP of 8.8.8.8 under a public prefix", true},
		{"fe80::5efe:808:808", "ISATAP of 8.8.8.8 under a link-local prefix", false},
		{"2002:c612:1::1", "6to4 of 198.18.0.1", false},
		{"2002:f000:1::1", "6to4 of 240.0.0.1", false},
		{"2002:c000:201::1", "6to4 of 192.0.2.1", false},
		{"64:ff9b::c612:1", "NAT64 of 198.18.0.1", false},
		{"64:ff9b::f000:1", "NAT64 of 240.0.0.1", false},
		{"::c612:1", "IPv4-compatible of 198.18.0.1", false},
		{"::f000:1", "IPv4-compatible of 240.0.0.1", false},
		{"::ffff:198.18.0.1", "IPv4-mapped of 198.18.0.1", false},
		{"2001:0:4136:e378:8000:63bf:3fff:fdd2", "Teredo (RFC 4380)", false},
	}
	for _, c := range cases {
		if got := g.IsAllowedIP(netip.MustParseAddr(c.ip)); got != c.allowed {
			t.Errorf("IsAllowedIP(%s) = %v, want %v (%s)", c.ip, got, c.allowed, c.form)
		}
	}
	// The seam that admits loopback admits it in its embedded forms too, and
	// nothing else changes.
	lo := Guard{AllowLoopback: true}
	if !lo.IsAllowedIP(netip.MustParseAddr("::ffff:0:7f00:1")) {
		t.Error("loopback seam: IPv4-translated 127.0.0.1 refused")
	}
	if lo.IsAllowedIP(netip.MustParseAddr("::ffff:0:a00:1")) {
		t.Error("loopback seam: IPv4-translated 10.0.0.1 allowed")
	}
}

// netip.Prefix.Contains is false for an address that carries a zone, so a
// zone must not let an address slip past the ranges.
func TestAZoneDoesNotHideARange(t *testing.T) {
	g := Guard{}
	for _, s := range []string{"fec0::1%eth0", "fe80::1%eth0", "fc00::1%lo", "2001:db8::1%x", "2001::1%x", "ff02::1%eth0", "2606:4700::5efe:a00:1%eth0"} {
		if g.IsAllowedIP(netip.MustParseAddr(s)) {
			t.Errorf("%s: allowed, want refused", s)
		}
	}
	if !g.IsAllowedIP(netip.MustParseAddr("2606:4700:4700::1111%eth0")) {
		t.Error("a public address with a zone was refused")
	}
}

// The test table and the guard's table name the same ranges: a range added to
// one without the other fails here.
func TestTheTestTableNamesEveryRangeTheGuardRefuses(t *testing.T) {
	cases := map[string]bool{}
	for _, c := range specialCases {
		cases[c.prefix] = true
	}
	guard := map[string]bool{}
	for _, r := range specialPurpose {
		guard[r.prefix.String()] = true
		if !cases[r.prefix.String()] {
			t.Errorf("%s (%s) has no case in specialCases", r.prefix, r.source)
		}
	}
	for p := range cases {
		if !guard[p] {
			t.Errorf("specialCases names %s, which the guard does not refuse", p)
		}
	}
}

// Each range is refused by its own row: with that row taken out, the
// addresses inside it are no longer refused by the table, so no other row or
// check shadows it and a deleted row cannot go unnoticed.
func TestEachSpecialPurposeRangeIsRefusedByItsOwnRow(t *testing.T) {
	for i, r := range specialPurpose {
		rest := append(append([]specialRange{}, specialPurpose[:i]...), specialPurpose[i+1:]...)
		for _, c := range specialCases {
			if c.prefix != r.prefix.String() {
				continue
			}
			for _, s := range c.inside {
				ip := netip.MustParseAddr(s)
				if !inSpecialPurpose(ip, specialPurpose) {
					t.Errorf("%s inside %s: not in the table", s, r.prefix)
				}
				if inSpecialPurpose(ip, rest) {
					t.Errorf("%s inside %s: another row also refuses it, so a deleted %s row would go unnoticed", s, r.prefix, r.prefix)
				}
			}
		}
	}
}

// The 2000::/3 check is IPv6's alone.
func TestTheGlobalUnicastSpaceIsIPv6sOnly(t *testing.T) {
	if globalUnicastSpace.String() != "2000::/3" {
		t.Fatalf("globalUnicastSpace = %s, want 2000::/3", globalUnicastSpace)
	}
	if !(Guard{}).IsAllowedIP(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("an IPv4 address was judged against 2000::/3")
	}
}
