package gitsrv

// White-box: the receive-pack command section a push is read from, and the
// bounded copy of it the post-push bookkeeping works from.

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// pkt renders one pkt-line.
func pkt(payload string) string { return fmt.Sprintf("%04x%s", len(payload)+4, payload) }

func TestParseReceiveCommands(t *testing.T) {
	a, b := strings.Repeat("a", 40), strings.Repeat("b", 40)
	c := strings.Repeat("c", 40)
	for _, tc := range []struct {
		name string
		in   string
		want []RefUpdate
	}{
		{"one command with its capabilities", pkt(a+" "+b+" refs/heads/main\x00report-status side-band-64k\n") + "0000PACK",
			[]RefUpdate{{Old: a, New: b, Ref: "refs/heads/main"}}},
		{"two commands, only the first carries capabilities", pkt(a+" "+b+" refs/heads/main\x00report-status") + pkt(b+" "+c+" refs/tags/v1.0.0\n") + "0000",
			[]RefUpdate{{Old: a, New: b, Ref: "refs/heads/main"}, {Old: b, New: c, Ref: "refs/tags/v1.0.0"}}},
		{"the trailing newline is not part of the ref", pkt(a + " " + b + " refs/heads/main\n"),
			[]RefUpdate{{Old: a, New: b, Ref: "refs/heads/main"}}},
		{"a command that ends the data exactly is read", pkt(a + " " + b + " refs/heads/last"),
			[]RefUpdate{{Old: a, New: b, Ref: "refs/heads/last"}}},
		{"the flush packet ends the section", pkt(a+" "+b+" refs/heads/one") + "0000" + pkt(a+" "+c+" refs/heads/two"),
			[]RefUpdate{{Old: a, New: b, Ref: "refs/heads/one"}}},
		{"a packet longer than the data stops the reading", pkt(a+" "+b+" refs/heads/one") + "00ffnot-all-here",
			[]RefUpdate{{Old: a, New: b, Ref: "refs/heads/one"}}},
		{"a length below four stops the reading", pkt(a+" "+b+" refs/heads/one") + "0003" + pkt(a+" "+c+" refs/heads/two"),
			[]RefUpdate{{Old: a, New: b, Ref: "refs/heads/one"}}},
		{"a length that is not hex stops the reading", pkt(a+" "+b+" refs/heads/one") + "zzzz" + pkt(a+" "+c+" refs/heads/two"),
			[]RefUpdate{{Old: a, New: b, Ref: "refs/heads/one"}}},
		{"an old id of the wrong length is skipped", pkt(a[:39]+" "+b+" refs/heads/short-old") + pkt(a+" "+b+" refs/heads/ok"),
			[]RefUpdate{{Old: a, New: b, Ref: "refs/heads/ok"}}},
		{"a new id of the wrong length is skipped", pkt(a+" "+b[:39]+" refs/heads/short-new") + pkt(a+" "+b+" refs/heads/ok"),
			[]RefUpdate{{Old: a, New: b, Ref: "refs/heads/ok"}}},
		{"a line without three fields is skipped", pkt(a+" "+b) + pkt(a+" "+b+" refs/heads/ok"),
			[]RefUpdate{{Old: a, New: b, Ref: "refs/heads/ok"}}},
		{"a ref with a space keeps it", pkt(a + " " + b + " refs/heads/with space"),
			[]RefUpdate{{Old: a, New: b, Ref: "refs/heads/with space"}}},
		{"nothing", "", nil},
		{"fewer than four bytes", "00", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseReceiveCommands([]byte(tc.in)); !slices.Equal(got, tc.want) {
				t.Fatalf("parsed %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestCommandCaptureKeepsOnlyTheCommands: the copy of a push's request ends
// when the pack begins and never grows past its cap, whatever the client
// sends, and never makes the stream it watches fail.
func TestCommandCaptureKeepsOnlyTheCommands(t *testing.T) {
	t.Run("stops at the pack", func(t *testing.T) {
		var buf bytes.Buffer
		c := newCommandCapture(&buf)
		cmd := pkt(strings.Repeat("a", 40)+" "+strings.Repeat("b", 40)+" refs/heads/main") + "0000"
		if n, err := c.Write([]byte(cmd + "PACK")); n != len(cmd)+4 || err != nil {
			t.Fatalf("Write = %d, %v; the stream must see every byte", n, err)
		}
		before := buf.Len()
		if n, err := c.Write([]byte("more pack data")); n != len("more pack data") || err != nil {
			t.Fatalf("Write after the pack = %d, %v", n, err)
		}
		if buf.Len() != before {
			t.Fatalf("the copy grew from %d to %d bytes after the pack began", before, buf.Len())
		}
		if !strings.HasPrefix(buf.String(), cmd) {
			t.Fatalf("the copy does not start with the command section: %q", buf.String())
		}
	})

	t.Run("never exceeds its cap", func(t *testing.T) {
		for _, chunk := range []int{1000, 4096, 10000, 65536, 200000} {
			var buf bytes.Buffer
			c := newCommandCapture(&buf)
			piece := bytes.Repeat([]byte("x"), chunk)
			for sent := 0; sent < 300000; sent += chunk {
				if n, err := c.Write(piece); n != chunk || err != nil {
					t.Fatalf("chunk %d: Write = %d, %v", chunk, n, err)
				}
			}
			if buf.Len() != 64<<10 {
				t.Fatalf("chunk %d: the copy holds %d bytes, want exactly the %d byte cap", chunk, buf.Len(), 64<<10)
			}
		}
	})

	t.Run("a pack word split across writes is still the end", func(t *testing.T) {
		var buf bytes.Buffer
		c := newCommandCapture(&buf)
		_, _ = c.Write([]byte("0000PA"))
		_, _ = c.Write([]byte("CK-and-the-rest"))
		before := buf.Len()
		_, _ = c.Write([]byte("later"))
		if buf.Len() != before {
			t.Fatalf("the copy kept growing after PACK completed (%d → %d)", before, buf.Len())
		}
	})
}
