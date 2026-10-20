package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHTTPOSVQuery(t *testing.T) {
	var batchCalls, vulnCalls int
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Accept"); got != "application/json" {
			t.Errorf("Accept = %q", got)
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/querybatch":
			batchCalls++
			var req osvQueryBatch
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatal(err)
			}
			results := make([]map[string]any, len(req.Queries))
			for i, q := range req.Queries {
				asked = append(asked, q.Package.Ecosystem+"/"+q.Package.Name+"@"+q.Version)
				vulns := []map[string]string{}
				if q.Package.Name == "lodash" && q.Version == "4.17.20" {
					vulns = append(vulns, map[string]string{"id": "GHSA-35jh-r3h4-6jhm"}, map[string]string{"id": "GHSA-35jh-r3h4-6jhm"})
				}
				if q.Package.Name == "minimist" {
					vulns = append(vulns, map[string]string{"id": "GHSA-xvch-5gv4-984h"})
				}
				if q.Package.Name == "trestle" {
					// Out of order on purpose: the answer is sorted by id.
					vulns = append(vulns, map[string]string{"id": "PYSEC-2026-1"}, map[string]string{"id": "GHSA-r4vp-3vw6-r2x5"})
				}
				results[i] = map[string]any{"vulns": vulns}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/vulns/GHSA-35jh-r3h4-6jhm":
			vulnCalls++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "GHSA-35jh-r3h4-6jhm", "summary": "Command Injection in lodash",
				"aliases": []string{"CVE-2020-8203"}, "database_specific": map[string]any{"severity": "HIGH"},
				"affected":   []map[string]any{{"package": map[string]string{"name": "lodash", "ecosystem": "npm"}, "ranges": []map[string]any{{"type": "ECOSYSTEM", "events": []map[string]string{{"introduced": "0"}, {"fixed": "4.17.21"}}}}}},
				"references": []map[string]string{{"type": "ADVISORY", "url": "https://example.test/adv"}},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/vulns/GHSA-xvch-5gv4-984h":
			vulnCalls++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "GHSA-xvch-5gv4-984h", "details": "Prototype Pollution in minimist\nlong text",
				"severity": []map[string]string{{"type": "CVSS_V3", "score": "9.8"}},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/vulns/GHSA-r4vp-3vw6-r2x5":
			// The database's word is HIGH; its two vectors score 8.4 (v3.1)
			// and 7.3 (v4.0), and the higher one is kept.
			vulnCalls++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "GHSA-r4vp-3vw6-r2x5", "summary": "high, scored 8.4", "database_specific": map[string]any{"severity": "HIGH"},
				"severity": []map[string]string{
					{"type": "CVSS_V4", "score": "CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
					{"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
				},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/vulns/PYSEC-2026-1":
			// No word of the database's own: the vector's band is the
			// advisory's severity (9.8, critical). A vector
			// is read, so this is not medium.
			vulnCalls++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "PYSEC-2026-1", "summary": "vector only",
				"severity": []map[string]string{{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := &HTTPOSV{BaseURL: srv.URL + "/"}
	res, err := c.Query(context.Background(), []OSVPackage{
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"},
		{Ecosystem: "npm", Name: "minimist", Version: "1.2.5"},
		{Ecosystem: "npm", Name: "react", Version: "18.3.1"},
		{Ecosystem: "PyPI", Name: "trestle", Version: "1.0.0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if batchCalls != 1 || vulnCalls != 4 {
		t.Fatalf("calls: batch=%d vulns=%d", batchCalls, vulnCalls)
	}
	// Each package is asked about by its ecosystem, name and exact version.
	if strings.Join(asked, " ") != "npm/lodash@4.17.20 npm/minimist@1.2.5 npm/react@18.3.1 PyPI/trestle@1.0.0" {
		t.Fatalf("asked %v", asked)
	}
	lo := res["npm/lodash@4.17.20"]
	if len(lo) != 1 || lo[0].ID != "GHSA-35jh-r3h4-6jhm" || lo[0].Severity != "high" || lo[0].Summary != "Command Injection in lodash" || len(lo[0].References) != 1 {
		t.Fatalf("lodash: %+v", lo)
	}
	// A HIGH with no score keeps no score, and the gate rates it high.
	if lo[0].CVSSScore != nil || AdvisoryGateSeverity(lo[0]) != SevHigh {
		t.Fatalf("lodash score: %+v", lo[0])
	}
	mi := res["npm/minimist@1.2.5"]
	if len(mi) != 1 || mi[0].Severity != "critical" || mi[0].Summary != "Prototype Pollution in minimist" || mi[0].CVSSScore == nil || *mi[0].CVSSScore != 9.8 {
		t.Fatalf("minimist: %+v", mi)
	}
	// The stored severity is the database's word; the score sits beside it,
	// and only the gate's rating moves.
	tr := res["PyPI/trestle@1.0.0"]
	if len(tr) != 2 {
		t.Fatalf("trestle: %+v", tr)
	}
	if tr[0].ID != "GHSA-r4vp-3vw6-r2x5" || tr[1].ID != "PYSEC-2026-1" {
		t.Fatalf("advisories are sorted by id: %s, %s", tr[0].ID, tr[1].ID)
	}
	high, vec := tr[0], tr[1]
	if high.Severity != "high" || high.CVSSScore == nil || *high.CVSSScore != 8.4 || AdvisoryGateSeverity(high) != SevMedium {
		t.Fatalf("HIGH scored 8.4: %+v", high)
	}
	if vec.Severity != "critical" || vec.CVSSScore == nil || *vec.CVSSScore != 9.8 || AdvisoryGateSeverity(vec) != SevCritical {
		t.Fatalf("vector-only advisory: %+v", vec)
	}
	if _, ok := res["npm/react@18.3.1"]; ok {
		t.Fatal("react should be absent")
	}
	if !osvEnabled(c) {
		t.Fatal("HTTPOSV must count as enabled")
	}
	if osvEnabled(OfflineOSV{}) || osvEnabled(nil) {
		t.Fatal("the offline client and no client are not enabled")
	}
	// What the advisory says about the package: the fix, the aliases, the
	// reference.
	if len(lo[0].FixedIn) != 1 || lo[0].FixedIn[0] != "4.17.21" || len(lo[0].Aliases) != 1 || lo[0].Aliases[0] != "CVE-2020-8203" || lo[0].References[0] != "https://example.test/adv" {
		t.Fatalf("lodash record: %+v", lo[0])
	}
	if c.httpClient().Timeout != 20*time.Second {
		t.Fatalf("default client timeout %v", c.httpClient().Timeout)
	}
}

func TestHTTPOSVErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusBadGateway)
	}))
	defer srv.Close()
	c := &HTTPOSV{BaseURL: srv.URL}
	if _, err := c.Query(context.Background(), []OSVPackage{{Ecosystem: "npm", Name: "x", Version: "1"}}); err == nil {
		t.Fatal("expected an error on HTTP 502")
	}
	if _, err := (&HTTPOSV{}).Query(context.Background(), nil); err == nil {
		t.Fatal("expected an error with no base url")
	}
	_, err := c.Query(context.Background(), []OSVPackage{{Ecosystem: "npm", Name: "x", Version: "1"}})
	if err == nil || err.Error() != "osv: /v1/querybatch answered 502" {
		t.Fatalf("the error names the path and the status: %v", err)
	}
	gone := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	gone.Close()
	if _, err := (&HTTPOSV{BaseURL: gone.URL}).Query(context.Background(), []OSVPackage{{Ecosystem: "npm", Name: "x", Version: "1"}}); err == nil || !strings.HasPrefix(err.Error(), "osv: ") {
		t.Fatalf("an unreachable database: %v", err)
	}
}

// osvFake answers /v1/querybatch from vulns (package name to advisory ids)
// and /v1/vulns/<id> with a bare advisory, recording every call.
type osvFake struct {
	mu      sync.Mutex
	batches []int    // queries in each batch call
	fetched []string // advisory ids fetched, in order
	vulns   func(name string) []string
	status  map[string]int // advisory id to a status to answer with
	short   int            // results to leave out of every batch answer
	extra   int            // results to add to every batch answer
	pad     int            // bytes of padding in every batch answer
}

func (f *osvFake) serve(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case r.URL.Path == "/v1/querybatch":
			var req osvQueryBatch
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Error(err)
			}
			f.batches = append(f.batches, len(req.Queries))
			results := []map[string]any{}
			for _, q := range req.Queries {
				ids := []map[string]string{}
				for _, id := range f.vulns(q.Package.Name) {
					ids = append(ids, map[string]string{"id": id})
				}
				results = append(results, map[string]any{"vulns": ids})
			}
			results = results[:len(results)-f.short]
			for i := 0; i < f.extra; i++ {
				results = append(results, map[string]any{"vulns": []any{}})
			}
			doc := map[string]any{"results": results}
			if f.pad > 0 {
				doc["pad"] = strings.Repeat("a", f.pad)
			}
			_ = json.NewEncoder(w).Encode(doc)
		case strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
			id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
			f.fetched = append(f.fetched, id)
			if st := f.status[id]; st != 0 {
				w.WriteHeader(st)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "summary": "advisory " + id})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func osvPackages(n int) []OSVPackage {
	pkgs := make([]OSVPackage, n)
	for i := range pkgs {
		pkgs[i] = OSVPackage{Ecosystem: "npm", Name: fmt.Sprintf("p%04d", i), Version: "1.0.0"}
	}
	return pkgs
}

// The batching, bounds and failure modes of a query, against a fake that
// answers from a function.
func TestHTTPOSVQueryBatchesAndBounds(t *testing.T) {
	ctx := context.Background()
	one := func(name string) []string { return []string{"GHSA-" + name} }

	t.Run("queries go in batches of 500", func(t *testing.T) {
		for n, want := range map[int][]int{1: {1}, 499: {499}, 500: {500}, 501: {500, 1}, 1000: {500, 500}, 1001: {500, 500, 1}} {
			f := &osvFake{vulns: func(name string) []string { return nil }}
			if _, err := (&HTTPOSV{BaseURL: f.serve(t).URL}).Query(ctx, osvPackages(n)); err != nil {
				t.Fatal(err)
			}
			if fmt.Sprint(f.batches) != fmt.Sprint(want) {
				t.Errorf("%d packages went in batches %v, want %v", n, f.batches, want)
			}
		}
	})
	t.Run("a package past the first batch gets its own answer", func(t *testing.T) {
		f := &osvFake{vulns: func(name string) []string {
			if name == "p0500" || name == "p0000" {
				return one(name)
			}
			return nil
		}}
		res, err := (&HTTPOSV{BaseURL: f.serve(t).URL}).Query(ctx, osvPackages(501))
		if err != nil || len(res) != 2 || res["npm/p0500@1.0.0"][0].ID != "GHSA-p0500" || res["npm/p0000@1.0.0"][0].ID != "GHSA-p0000" {
			t.Fatalf("results %v err %v", res, err)
		}
	})
	t.Run("an answer with another number of results than queries is an error", func(t *testing.T) {
		for name, f := range map[string]*osvFake{
			"one short": {vulns: func(string) []string { return nil }, short: 1},
			"one extra": {vulns: func(string) []string { return nil }, extra: 1},
		} {
			_, err := (&HTTPOSV{BaseURL: f.serve(t).URL}).Query(ctx, osvPackages(3))
			if err == nil || !strings.Contains(err.Error(), "querybatch returned") {
				t.Errorf("%s: %v", name, err)
			}
		}
	})
	t.Run("an advisory with no id is skipped, not fetched", func(t *testing.T) {
		f := &osvFake{vulns: func(name string) []string { return []string{"", "GHSA-real"} }}
		res, err := (&HTTPOSV{BaseURL: f.serve(t).URL}).Query(ctx, osvPackages(1))
		if err != nil || len(res["npm/p0000@1.0.0"]) != 1 || fmt.Sprint(f.fetched) != "[GHSA-real]" {
			t.Fatalf("results %v fetched %v err %v", res, f.fetched, err)
		}
	})
	t.Run("advisories are fetched once each, in id order", func(t *testing.T) {
		f := &osvFake{vulns: func(name string) []string { return []string{"GHSA-b", "GHSA-a", "GHSA-b"} }}
		if _, err := (&HTTPOSV{BaseURL: f.serve(t).URL}).Query(ctx, osvPackages(3)); err != nil {
			t.Fatal(err)
		}
		if fmt.Sprint(f.fetched) != "[GHSA-a GHSA-b]" {
			t.Fatalf("fetched %v", f.fetched)
		}
	})
	t.Run("at most MaxAdvisories bodies are fetched; the rest are named without a summary", func(t *testing.T) {
		f := &osvFake{vulns: func(name string) []string { return one(name) }}
		res, err := (&HTTPOSV{BaseURL: f.serve(t).URL, MaxAdvisories: 2}).Query(ctx, osvPackages(3))
		if err != nil || len(f.fetched) != 2 {
			t.Fatalf("fetched %v err %v", f.fetched, err)
		}
		if got := res["npm/p0002@1.0.0"][0]; got.ID != "GHSA-p0002" || got.Summary != "advisory not hydrated (per-scan advisory cap)" || got.Severity != "medium" {
			t.Fatalf("the advisory past the cap: %+v", got)
		}
		if got := res["npm/p0001@1.0.0"][0]; got.Summary != "advisory GHSA-p0001" {
			t.Fatalf("an advisory inside the cap: %+v", got)
		}
	})
	t.Run("the default cap is 200 bodies", func(t *testing.T) {
		f := &osvFake{vulns: func(name string) []string { return one(name) }}
		res, err := (&HTTPOSV{BaseURL: f.serve(t).URL}).Query(ctx, osvPackages(201))
		if err != nil || len(f.fetched) != 200 || res["npm/p0200@1.0.0"][0].Summary != "advisory not hydrated (per-scan advisory cap)" || res["npm/p0199@1.0.0"][0].Summary != "advisory GHSA-p0199" {
			t.Fatalf("fetched %d err %v", len(f.fetched), err)
		}
	})
	t.Run("an advisory that cannot be fetched fails the query", func(t *testing.T) {
		f := &osvFake{vulns: func(name string) []string { return one(name) }, status: map[string]int{"GHSA-p0001": http.StatusInternalServerError}}
		_, err := (&HTTPOSV{BaseURL: f.serve(t).URL}).Query(ctx, osvPackages(3))
		if err == nil || !strings.Contains(err.Error(), "/v1/vulns/GHSA-p0001 answered 500") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("only a 200 is an answer, and it must be JSON", func(t *testing.T) {
		for _, status := range []int{http.StatusNotFound, http.StatusNoContent, http.StatusFound} {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				_, _ = w.Write([]byte(`{"results":[{}]}`))
			}))
			_, err := (&HTTPOSV{BaseURL: srv.URL}).Query(ctx, osvPackages(1))
			srv.Close()
			if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("answered %d", status)) {
				t.Errorf("status %d: %v", status, err)
			}
		}
		junk := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("not json")) }))
		defer junk.Close()
		if _, err := (&HTTPOSV{BaseURL: junk.URL}).Query(ctx, osvPackages(1)); err == nil || !strings.Contains(err.Error(), "osv: decode /v1/querybatch") {
			t.Fatalf("an answer that is not JSON: %v", err)
		}
	})
	t.Run("an answer over 8 MiB is cut and so is not an answer", func(t *testing.T) {
		f := &osvFake{vulns: func(string) []string { return nil }, pad: 8<<20 + 1024}
		if _, err := (&HTTPOSV{BaseURL: f.serve(t).URL}).Query(ctx, osvPackages(1)); err == nil {
			t.Fatal("a response past the read bound must be an error")
		}
	})
}

// TestOSVToFinding pins how an advisory becomes a finding's record: the
// severity word the database gives, else the band of the highest CVSS score,
// else medium; the fixes and aliases that are the package's own; and the
// summary.
func TestOSVToFinding(t *testing.T) {
	type want struct {
		severity string
		score    float64 // -1 for none
		summary  string
	}
	score := func(a OSVVulnerability) float64 {
		if a.CVSSScore == nil {
			return -1
		}
		return *a.CVSSScore
	}
	sev := func(word string, scores ...string) string {
		var b strings.Builder
		b.WriteString(`{"id":"X-1","summary":"s"`)
		if word != "" {
			fmt.Fprintf(&b, `,"database_specific":{"severity":%q}`, word)
		}
		if len(scores) > 0 {
			b.WriteString(`,"severity":[`)
			for i, sc := range scores {
				if i > 0 {
					b.WriteString(",")
				}
				fmt.Fprintf(&b, `{"type":"CVSS_V3","score":%q}`, sc)
			}
			b.WriteString("]")
		}
		b.WriteString("}")
		return b.String()
	}
	for name, c := range map[string]struct {
		doc  string
		want want
	}{
		"CRITICAL":                         {sev("CRITICAL"), want{"critical", -1, "s"}},
		"HIGH":                             {sev("HIGH"), want{"high", -1, "s"}},
		"MODERATE":                         {sev("MODERATE"), want{"medium", -1, "s"}},
		"MEDIUM":                           {sev("MEDIUM"), want{"medium", -1, "s"}},
		"LOW":                              {sev("LOW"), want{"low", -1, "s"}},
		"a word in any case":               {sev("critical"), want{"critical", -1, "s"}},
		"a word the database made up":      {sev("SEVERE"), want{"medium", -1, "s"}},
		"no word and no score":             {sev(""), want{"medium", -1, "s"}},
		"9.0 is critical":                  {sev("", "9.0"), want{"critical", 9, "s"}},
		"10 is critical":                   {sev("", "10"), want{"critical", 10, "s"}},
		"8.9 is high":                      {sev("", "8.9"), want{"high", 8.9, "s"}},
		"7.0 is high":                      {sev("", "7.0"), want{"high", 7, "s"}},
		"6.9 is medium":                    {sev("", "6.9"), want{"medium", 6.9, "s"}},
		"4.0 is medium":                    {sev("", "4.0"), want{"medium", 4, "s"}},
		"3.9 is low":                       {sev("", "3.9"), want{"low", 3.9, "s"}},
		"0 is low":                         {sev("", "0"), want{"low", 0, "s"}},
		"the highest of several":           {sev("", "5.0", "9.1", "2.0"), want{"critical", 9.1, "s"}},
		"the word wins, the score is kept": {sev("LOW", "9.8"), want{"low", 9.8, "s"}},
		"an unreadable score is none":      {sev("", "not a score"), want{"medium", -1, "s"}},
		"MODERATE over a high score":       {sev("MODERATE", "9.8"), want{"medium", 9.8, "s"}},
		"MEDIUM over a high score":         {sev("MEDIUM", "9.8"), want{"medium", 9.8, "s"}},
		"HIGH over a low score":            {sev("HIGH", "1.0"), want{"high", 1, "s"}},
		"CRITICAL over a low score":        {sev("CRITICAL", "1.0"), want{"critical", 1, "s"}},
	} {
		var v osvVuln
		if err := json.Unmarshal([]byte(c.doc), &v); err != nil {
			t.Fatal(err)
		}
		got := osvToFinding(v, OSVPackage{Ecosystem: "npm", Name: "lodash", Version: "1"})
		if got.Severity != c.want.severity || score(got) != c.want.score || got.Summary != c.want.summary {
			t.Errorf("%s: severity %q score %v summary %q, want %+v", name, got.Severity, score(got), got.Summary, c.want)
		}
	}

	var v osvVuln
	doc := `{"id":"GHSA-1","aliases":["CVE-2","CVE-1"],"summary":"  padded summary  ",
	  "references":[{"type":"WEB","url":""},{"type":"ADVISORY","url":"https://a.example/1"}],
	  "affected":[
	    {"package":{"name":"Lodash","ecosystem":"NPM"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.5"},{"fixed":"2.0.0"},{"fixed":""}]}]},
	    {"package":{"name":"other","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"fixed":"9.9.9"}]}]},
	    {"package":{"name":"lodash","ecosystem":"PyPI"},"ranges":[{"type":"SEMVER","events":[{"fixed":"8.8.8"}]}]}
	  ]}`
	if err := json.Unmarshal([]byte(doc), &v); err != nil {
		t.Fatal(err)
	}
	got := osvToFinding(v, OSVPackage{Ecosystem: "npm", Name: "lodash", Version: "1"})
	if fmt.Sprint(got.FixedIn) != "[2.0.0 4.17.5]" {
		t.Errorf("fixedIn %v: only the package's own fixes, sorted, none empty", got.FixedIn)
	}
	if fmt.Sprint(got.Aliases) != "[CVE-1 CVE-2]" || fmt.Sprint(got.References) != "[https://a.example/1]" || got.Summary != "padded summary" {
		t.Errorf("aliases %v references %v summary %q", got.Aliases, got.References, got.Summary)
	}

	// With no summary the first line of the details stands in, bounded at 200
	// bytes with an ellipsis.
	for name, c := range map[string]struct{ details, want string }{
		"the first line":     {"line one\nline two", "line one"},
		"a line of 200":      {strings.Repeat("d", 200), strings.Repeat("d", 200)},
		"a line of 201":      {strings.Repeat("d", 201), strings.Repeat("d", 200) + "\u2026"},
		"details of padding": {"  \n  text  \n", "text"},
	} {
		var d osvVuln
		_ = json.Unmarshal([]byte(`{"id":"X","details":`+strconv.Quote(c.details)+`}`), &d)
		if got := osvToFinding(d, OSVPackage{}).Summary; got != c.want {
			t.Errorf("%s: summary %q, want %q", name, got, c.want)
		}
	}

	// The ecosystem names S7 asks about.
	for in, want := range map[string]string{"npm": "npm", "NPM": "npm", "pypi": "PyPI", "PyPI": "PyPI", "cargo": "", "": ""} {
		if got := osvEcosystem(in); got != want {
			t.Errorf("osvEcosystem(%q) = %q, want %q", in, got, want)
		}
	}
	if k := (OSVPackage{Ecosystem: "npm", Name: "a", Version: "1"}).Key(); k != "npm/a@1" {
		t.Errorf("key %q", k)
	}
}
