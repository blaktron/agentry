package dnsx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
)

type fakeResolver struct{ txt map[string][]string }

func (f fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	return f.txt[name], nil
}

// namedResolver answers one fixed list for every name and records the name it
// was asked for.
type namedResolver struct {
	records []string
	asked   []string
}

func (n *namedResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	n.asked = append(n.asked, name)
	return n.records, nil
}

// errResolver fails every lookup with err.
type errResolver struct{ err error }

func (e errResolver) LookupTXT(context.Context, string) ([]string, error) { return nil, e.err }

func TestVerifyTXT(t *testing.T) {
	domain := "acme.example"
	token := "tok-123"
	name := TXTName(domain)

	// Absent → not verified.
	absent := fakeResolver{txt: map[string][]string{}}
	if ok, err := VerifyTXT(context.Background(), absent, domain, token); err != nil || ok {
		t.Fatalf("absent record: ok=%v err=%v, want false/nil", ok, err)
	}

	// Present (bare token) → verified.
	bare := fakeResolver{txt: map[string][]string{name: {"unrelated", token}}}
	if ok, err := VerifyTXT(context.Background(), bare, domain, token); err != nil || !ok {
		t.Fatalf("bare token: ok=%v err=%v, want true/nil", ok, err)
	}

	// Present (prefixed form) → verified.
	prefixed := fakeResolver{txt: map[string][]string{name: {"agentry-domain-verification=" + token}}}
	if ok, err := VerifyTXT(context.Background(), prefixed, domain, token); err != nil || !ok {
		t.Fatalf("prefixed token: ok=%v err=%v, want true/nil", ok, err)
	}

	// Wrong token present → not verified.
	wrong := fakeResolver{txt: map[string][]string{name: {"some-other-token"}}}
	if ok, _ := VerifyTXT(context.Background(), wrong, domain, token); ok {
		t.Fatal("wrong token should not verify")
	}

	// The name asked for is the dedicated challenge subdomain: spelled out,
	// lower-cased, and without the trailing dot of an absolute name.
	for in, want := range map[string]string{
		"acme.example":       "_agentry-challenge.acme.example",
		"ACME.Example":       "_agentry-challenge.acme.example",
		"acme.example.":      "_agentry-challenge.acme.example",
		"Corp.ACME.example.": "_agentry-challenge.corp.acme.example",
	} {
		if got := TXTName(in); got != want {
			t.Errorf("TXTName(%q) = %q, want %q", in, got, want)
		}
		asked := &namedResolver{}
		if _, err := VerifyTXT(context.Background(), asked, in, token); err != nil {
			t.Fatal(err)
		}
		if len(asked.asked) != 1 || asked.asked[0] != want {
			t.Errorf("VerifyTXT(%q) looked up %v, want only %q", in, asked.asked, want)
		}
	}

	// Only the whole token is proof, bare or behind the verification prefix,
	// with white space around the record or the token ignored.
	const prefix = "agentry-domain-verification="
	for name, tc := range map[string]struct {
		records []string
		token   string
		want    bool
	}{
		"bare":                          {[]string{"tok-123"}, "tok-123", true},
		"prefixed":                      {[]string{prefix + "tok-123"}, "tok-123", true},
		"among others":                  {[]string{"v=spf1 -all", "tok-123", "x"}, "tok-123", true},
		"last of several":               {[]string{"a", "b", prefix + "tok-123"}, "tok-123", true},
		"padded record":                 {[]string{"  tok-123\t"}, "tok-123", true},
		"padded prefixed record":        {[]string{" " + prefix + "tok-123 "}, "tok-123", true},
		"padded token":                  {[]string{"tok-123"}, "  tok-123 ", true},
		"padded token, prefixed record": {[]string{prefix + "tok-123"}, " tok-123\n", true},
		"no records":                    {nil, "tok-123", false},
		"a longer token":                {[]string{"tok-1234"}, "tok-123", false},
		"a shorter token":               {[]string{"tok-12"}, "tok-123", false},
		"token inside the record":       {[]string{"xtok-123x"}, "tok-123", false},
		"token after other text":        {[]string{"verify tok-123"}, "tok-123", false},
		"token before other text":       {[]string{"tok-123 verify"}, "tok-123", false},
		"prefixed, longer token":        {[]string{prefix + "tok-1234"}, "tok-123", false},
		"prefixed, shorter token":       {[]string{prefix + "tok-12"}, "tok-123", false},
		"prefixed, other token":         {[]string{prefix + "other"}, "tok-123", false},
		"prefix alone":                  {[]string{prefix}, "tok-123", false},
		"another prefix":                {[]string{"agentry-verification=tok-123"}, "tok-123", false},
		"prefix twice":                  {[]string{prefix + prefix + "tok-123"}, "tok-123", false},
		"another case":                  {[]string{"TOK-123"}, "tok-123", false},
		"empty token":                   {[]string{"", "tok-123", prefix}, "", false},
		"empty token, no records":       {nil, "", false},
	} {
		got, err := VerifyTXT(context.Background(), &namedResolver{records: tc.records}, domain, tc.token)
		if err != nil || got != tc.want {
			t.Errorf("%s: VerifyTXT = %v, %v; want %v, nil", name, got, err, tc.want)
		}
	}

	// A name with no TXT records is "not verified yet"; any other failure is
	// the lookup's own error and never a verification.
	notFound := &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	if ok, err := VerifyTXT(context.Background(), errResolver{notFound}, domain, token); ok || err != nil {
		t.Errorf("a name with no records: %v, %v; want false, nil", ok, err)
	}
	for what, e := range map[string]error{
		"a timeout":                  &net.DNSError{Err: "i/o timeout", Name: name, IsTimeout: true},
		"a temporary failure":        &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: true},
		"a DNS failure":              &net.DNSError{Err: "server failure", Name: name},
		"an error that is not DNS's": errors.New("connection refused"),
		"a wrapped not-found":        fmt.Errorf("lookup: %w", notFound),
	} {
		ok, err := VerifyTXT(context.Background(), errResolver{e}, domain, token)
		if ok || err == nil || !errors.Is(err, e) {
			t.Errorf("%s: %v, %v; want false and that error", what, ok, err)
		}
	}
}

// The system resolver asks the operating system's resolver, under the context
// it is given, for exactly the name it is given: a query is captured on the
// wire, and a context that is already cancelled ends the lookup with its
// cancellation, whatever the network offers.
func TestSystemResolverLooksUpUnderTheContext(t *testing.T) {
	var r Resolver = NewSystemResolver()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	txt, err := r.LookupTXT(ctx, TXTName("acme.example"))
	if err == nil || !errors.Is(err, context.Canceled) || len(txt) != 0 {
		t.Fatalf("LookupTXT under a cancelled context = %v, %v; want the cancellation", txt, err)
	}

	asked := make(chan string, 64)
	old := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer func() { _ = server.Close() }()
			buf := make([]byte, 1024)
			n, err := server.Read(buf)
			if err != nil {
				return
			}
			select {
			case asked <- queryName(buf[:n]):
			default:
			}
		}()
		return client, nil
	}}
	t.Cleanup(func() { net.DefaultResolver = old })
	// Every attempt on this connection ends without an answer, so the lookup
	// returns an error once the resolver has tried its candidates.
	if _, err := r.LookupTXT(context.Background(), "_agentry-challenge.acme.example"); err == nil {
		t.Fatal("a resolver that never answers returned records")
	}
	var names []string
	for len(asked) > 0 {
		names = append(names, <-asked)
	}
	// Search domains may add candidates, but the name itself is always asked
	// for as given.
	if !slices.Contains(names, "_agentry-challenge.acme.example") {
		t.Fatalf("the resolver was asked for %q, want the name it was given", names)
	}
}

// queryName reads the question name out of a DNS query (a 12-byte header,
// then length-prefixed labels), as dotted text. The resolver frames a query
// on a connection that is not a packet connection with a two-byte length.
func queryName(packet []byte) string {
	start := 12
	if len(packet) > 2 && int(packet[0])<<8|int(packet[1]) == len(packet)-2 {
		start += 2
	}
	var labels []string
	for i := start; i < len(packet) && packet[i] != 0; {
		n := int(packet[i])
		if i+1+n > len(packet) {
			break
		}
		labels = append(labels, string(packet[i+1:i+1+n]))
		i += 1 + n
	}
	return strings.Join(labels, ".")
}
