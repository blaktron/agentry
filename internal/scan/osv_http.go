package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// HTTPOSV is the OSVClient that consults an OSV API (api.osv.dev or a
// mirror). Lookups are batched through /v1/querybatch and the advisory
// bodies fetched once per distinct id, so N declared servers cost
// ceil(N/queryBatchSize) + distinct-advisory requests.
type HTTPOSV struct {
	// BaseURL is the API origin, e.g. https://api.osv.dev.
	BaseURL string
	// Client is the HTTP client; nil uses a 20s-timeout default.
	Client *http.Client
	// MaxAdvisories caps the advisory bodies fetched per Query (0 = 200);
	// beyond it, advisories are reported by id with no summary.
	MaxAdvisories int
}

const osvQueryBatchSize = 500

// osvQueryBatch is the request body of POST /v1/querybatch.
type osvQueryBatch struct {
	Queries []osvQuery `json:"queries"`
}

type osvQuery struct {
	Package osvQueryPackage `json:"package"`
	Version string          `json:"version"`
}

type osvQueryPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvQueryBatchResponse struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	} `json:"results"`
}

// osvVuln is the subset of the OSV schema the finding needs.
type osvVuln struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced"`
				Fixed      string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
	DatabaseSpecific map[string]any `json:"database_specific"`
}

func (c *HTTPOSV) httpClient() *http.Client {
	if c.Client != nil {
		return c.Client
	}
	return &http.Client{Timeout: 20 * time.Second}
}

// Query implements OSVClient.
func (c *HTTPOSV) Query(ctx context.Context, pkgs []OSVPackage) (map[string][]OSVVulnerability, error) {
	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		return nil, fmt.Errorf("osv: no base url")
	}
	// Package → advisory ids, and the distinct id set to hydrate.
	byPkg := map[string][]string{}
	ids := map[string]bool{}
	for start := 0; start < len(pkgs); start += osvQueryBatchSize {
		end := min(start+osvQueryBatchSize, len(pkgs))
		chunk := pkgs[start:end]
		req := osvQueryBatch{}
		for _, p := range chunk {
			req.Queries = append(req.Queries, osvQuery{Package: osvQueryPackage{Name: p.Name, Ecosystem: p.Ecosystem}, Version: p.Version})
		}
		var resp osvQueryBatchResponse
		if err := c.postJSON(ctx, base+"/v1/querybatch", req, &resp); err != nil {
			return nil, err
		}
		if len(resp.Results) != len(chunk) {
			return nil, fmt.Errorf("osv: querybatch returned %d results for %d queries", len(resp.Results), len(chunk))
		}
		for i, r := range resp.Results {
			key := chunk[i].Key()
			for _, v := range r.Vulns {
				if v.ID == "" {
					continue
				}
				byPkg[key] = append(byPkg[key], v.ID)
				ids[v.ID] = true
			}
		}
	}
	if len(ids) == 0 {
		return map[string][]OSVVulnerability{}, nil
	}
	// Hydrate advisories in a deterministic order.
	sorted := make([]string, 0, len(ids))
	for id := range ids {
		sorted = append(sorted, id)
	}
	sort.Strings(sorted)
	capN := c.MaxAdvisories
	if capN <= 0 {
		capN = 200
	}
	detail := map[string]osvVuln{}
	for i, id := range sorted {
		if i >= capN {
			detail[id] = osvVuln{ID: id, Summary: "advisory not hydrated (per-scan advisory cap)"}
			continue
		}
		var v osvVuln
		if err := c.getJSON(ctx, base+"/v1/vulns/"+id, &v); err != nil {
			return nil, err
		}
		detail[id] = v
	}
	out := map[string][]OSVVulnerability{}
	byKey := map[string]OSVPackage{}
	for _, p := range pkgs {
		byKey[p.Key()] = p
	}
	for key, list := range byPkg {
		seen := map[string]bool{}
		for _, id := range list {
			if seen[id] {
				continue
			}
			seen[id] = true
			out[key] = append(out[key], osvToFinding(detail[id], byKey[key]))
		}
		sort.Slice(out[key], func(a, b int) bool { return out[key][a].ID < out[key][b].ID })
	}
	return out, nil
}

// osvToFinding maps an OSV advisory onto the finding vocabulary. Severity
// prefers the database's own word (GHSA: CRITICAL/HIGH/MODERATE/LOW), then
// a CVSS base score if the record carries a plain number, else medium — an
// advisory with no severity is still an advisory (D2).
func osvToFinding(v osvVuln, pkg OSVPackage) OSVVulnerability {
	sev := ""
	if s, ok := v.DatabaseSpecific["severity"].(string); ok {
		switch strings.ToUpper(s) {
		case "CRITICAL":
			sev = string(SevCritical)
		case "HIGH":
			sev = string(SevHigh)
		case "MODERATE", "MEDIUM":
			sev = string(SevMedium)
		case "LOW":
			sev = string(SevLow)
		}
	}
	if sev == "" {
		for _, s := range v.Severity {
			if score := cvssBaseScore(s.Score); score >= 0 {
				switch {
				case score >= 9:
					sev = string(SevCritical)
				case score >= 7:
					sev = string(SevHigh)
				case score >= 4:
					sev = string(SevMedium)
				default:
					sev = string(SevLow)
				}
				break
			}
		}
	}
	if sev == "" {
		sev = string(SevMedium)
	}
	summary := strings.TrimSpace(v.Summary)
	if summary == "" {
		summary = firstLine(v.Details)
	}
	var refs []string
	for _, r := range v.References {
		if r.URL != "" {
			refs = append(refs, r.URL)
		}
	}
	var fixed []string
	for _, a := range v.Affected {
		if !strings.EqualFold(a.Package.Ecosystem, pkg.Ecosystem) || !strings.EqualFold(a.Package.Name, pkg.Name) {
			continue
		}
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					fixed = append(fixed, e.Fixed)
				}
			}
		}
	}
	sort.Strings(fixed)
	aliases := append([]string(nil), v.Aliases...)
	sort.Strings(aliases)
	return OSVVulnerability{ID: v.ID, Aliases: aliases, Summary: summary, Severity: sev, FixedIn: fixed, References: refs}
}

// cvssBaseScore extracts a numeric base score when the OSV severity "score"
// field is a plain number (some databases put the score there instead of a
// vector). A vector string yields -1.
func cvssBaseScore(score string) float64 {
	var f float64
	if _, err := fmt.Sscanf(strings.TrimSpace(score), "%g", &f); err != nil || strings.Contains(score, ":") {
		return -1
	}
	if f < 0 || f > 10 {
		return -1
	}
	return f
}

func (c *HTTPOSV) postJSON(ctx context.Context, url string, body any, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, out)
}

func (c *HTTPOSV) getJSON(ctx context.Context, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	return c.do(req, out)
}

func (c *HTTPOSV) do(req *http.Request, out any) error {
	req.Header.Set("Accept", "application/json")
	res, err := c.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("osv: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return fmt.Errorf("osv: read: %w", err)
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("osv: %s answered %d", req.URL.Path, res.StatusCode)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("osv: decode %s: %w", req.URL.Path, err)
	}
	return nil
}
