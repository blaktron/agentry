package scan

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPOSVQuery(t *testing.T) {
	var batchCalls, vulnCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/querybatch":
			batchCalls++
			var req osvQueryBatch
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatal(err)
			}
			results := make([]map[string]any, len(req.Queries))
			for i, q := range req.Queries {
				vulns := []map[string]string{}
				if q.Package.Name == "lodash" && q.Version == "4.17.20" {
					vulns = append(vulns, map[string]string{"id": "GHSA-35jh-r3h4-6jhm"}, map[string]string{"id": "GHSA-35jh-r3h4-6jhm"})
				}
				if q.Package.Name == "minimist" {
					vulns = append(vulns, map[string]string{"id": "GHSA-xvch-5gv4-984h"})
				}
				if q.Package.Name == "trestle" {
					vulns = append(vulns, map[string]string{"id": "GHSA-r4vp-3vw6-r2x5"}, map[string]string{"id": "PYSEC-2026-1"})
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
			// advisory's severity (9.8, critical). Before agentry#774 a
			// vector was not read at all and this was medium.
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
	// and only the gate's rating moves (invariant 5 of the tweaks plan).
	tr := res["PyPI/trestle@1.0.0"]
	if len(tr) != 2 {
		t.Fatalf("trestle: %+v", tr)
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
}
