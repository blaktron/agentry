package scan

import (
	"crypto/sha256"
	"encoding/base64"
	"slices"
	"strings"
	"testing"
)

// TestS2ArchiveReportsEveryMatchOnALine pins that the archive scan reads
// every match of a rule on a line, each a finding with its own column, and
// that a match too plain to be a secret does not hide a later one on the
// same line.
func TestS2ArchiveReportsEveryMatchOnALine(t *testing.T) {
	const (
		first  = "AKIAI44QH8DHBEXAMPLE"
		second = "AKIAJ5ZCLPN4EXAMPLE0"
	)
	cases := []struct {
		name, line, scanner string
		columns             []int
	}{
		{"two keys of one rule", "old " + first + " new " + second, "S2/aws-access-key", []int{5, 30}},
		{"a placeholder before a secret", `token="aaaaaaaaaaaaaaaa" password="` + fakeBase64("password", 20) + `"`, "S2/generic-assignment", []int{36}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := S2Secrets{}.Run(stageContext{ctx: t.Context()}, &Input{Files: []FileEntry{{Path: "keys.txt", IsText: true, Content: []byte("x\n" + c.line + "\n")}}})
			var columns []int
			for _, f := range res.Findings {
				if f.Scanner != c.scanner {
					continue
				}
				if f.LineStart != 2 {
					t.Errorf("finding on line %d, want 2", f.LineStart)
				}
				if strings.Contains(f.Excerpt, first) || strings.Contains(f.Excerpt, second) {
					t.Errorf("excerpt is not redacted: %q", f.Excerpt)
				}
				columns = append(columns, f.Detail["column"].(int))
			}
			slices.Sort(columns)
			if !slices.Equal(columns, c.columns) {
				t.Fatalf("%s findings at columns %v, want %v", c.scanner, columns, c.columns)
			}
		})
	}
}

// fakeBase64 is n characters of base64 derived from seed: random-looking
// enough to pass the entropy gates, made at run time so this file holds no
// secret-shaped literal.
func fakeBase64(seed string, n int) string {
	var out []byte
	for block := sha256.Sum256([]byte(seed)); len(out) < n; block = sha256.Sum256(block[:]) {
		out = append(out, base64.StdEncoding.EncodeToString(block[:])[:40]...)
	}
	return string(out[:n])
}

// pemKey is a private key in PEM form with the given body. The marker lines
// are split in the source so this file is not itself a key.
func pemKey(kind, body string) string {
	return "-----BEGIN " + kind + "PRIVATE KEY-----\n" + body + "\n-----END " + kind + "PRIVATE KEY-----\n"
}

// TestS2HistoryTellsPrivateKeysApart pins that the history scan tells two
// private keys apart by their bodies, however they were committed, and
// that one key committed again, even re-wrapped or quoted, stays one
// finding.
func TestS2HistoryTellsPrivateKeysApart(t *testing.T) {
	keyA := fakeBase64("key a", 64) + "\n" + fakeBase64("key a, line 2", 64)
	keyB := fakeBase64("key b", 64) + "\n" + fakeBase64("key b, line 2", 64)
	oneLine := func(body string) string {
		return `"` + strings.ReplaceAll(strings.TrimSuffix(pemKey("", body), "\n"), "\n", `\n`) + `"`
	}
	cases := []struct {
		name  string
		steps []map[string]*string
		want  int
	}{
		{"two keys in two files", []map[string]*string{
			{"a.pem": textOf(pemKey("RSA ", keyA)), "b.pem": textOf(pemKey("RSA ", keyB))},
			{"a.pem": nil, "b.pem": nil},
		}, 2},
		{"two keys in two commits of one file", []map[string]*string{
			{"id.pem": textOf(pemKey("RSA ", keyA))},
			{"id.pem": textOf(pemKey("EC ", keyB))},
			{"id.pem": nil},
		}, 2},
		{"two keys in one file", []map[string]*string{
			{"keys.pem": textOf(pemKey("RSA ", keyA) + pemKey("RSA ", keyB))},
			{"keys.pem": nil},
		}, 2},
		{"two keys on one line", []map[string]*string{
			{"creds.json": textOf(`{"a": ` + oneLine(keyA) + `, "b": ` + oneLine(keyB) + "}\n")},
			{"creds.json": nil},
		}, 2},
		{"one key committed twice", []map[string]*string{
			{"a.pem": textOf(pemKey("RSA ", keyA))},
			{"b.pem": textOf(pemKey("RSA ", keyA))},
			{"a.pem": nil, "b.pem": nil},
		}, 1},
		{"one key as PEM and as a JSON string", []map[string]*string{
			{"a.pem": textOf(pemKey("", keyA))},
			{"creds.json": textOf(`{"key": ` + oneLine(keyA) + "}\n")},
		}, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			patch := gitHistoryOf(t, c.steps...)
			findings, truncated, err := scanHistoryPatch(strings.NewReader(patch))
			if err != nil || truncated {
				t.Fatalf("err=%v truncated=%v", err, truncated)
			}
			n := 0
			for _, f := range findings {
				if f.Scanner != "S2/history-private-key" {
					continue
				}
				n++
				if f.Detail["commit"] == "" || f.FilePath == "" || f.Detail["column"] == nil {
					t.Errorf("finding does not say where the key was committed: %+v", f)
				}
				if strings.Contains(f.Excerpt, keyA[:20]) || strings.Contains(f.Excerpt, keyB[:20]) {
					t.Errorf("excerpt shows the key: %q", f.Excerpt)
				}
			}
			if n != c.want {
				t.Fatalf("%d private-key findings, want %d: %+v", n, c.want, findings)
			}
		})
	}
}
