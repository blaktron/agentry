package ui

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// The operator surface (DEV-091, plan core-web-split §3.2): the review
// queue and its decisions, abuse triage, quarantine/block/reinstate and
// ruleset releases — the pages a headless registry needs to publish and to
// moderate. Every page reads and posts through the API's own handlers, so
// reviewer and staff authorization is the API's matrix, not a copy.

type reviewItem struct {
	ID        string     `json:"id"`
	Queue     string     `json:"queue"`
	State     string     `json:"state"`
	Version   string     `json:"version"`
	Agent     string     `json:"agent"`
	Namespace string     `json:"namespace"`
	CreatedAt *time.Time `json:"createdAt"`
}

type finding struct {
	ID            string `json:"id"`
	Scanner       string `json:"scanner"`
	Severity      string `json:"severity"`
	Confidence    string `json:"confidence"`
	Title         string `json:"title"`
	FilePath      string `json:"filePath"`
	LineStart     int    `json:"lineStart"`
	LineEnd       int    `json:"lineEnd"`
	Excerpt       string `json:"excerpt"`
	Verdict       string `json:"verdict"`
	VerdictReason string `json:"verdictReason"`
}

type reviewBundle struct {
	Item     reviewItem     `json:"item"`
	Findings []finding      `json:"findings"`
	Manifest map[string]any `json:"manifest"`
}

type reviewFile struct {
	Path      string `json:"path"`
	Size      int    `json:"size"`
	Binary    bool   `json:"binary"`
	Truncated bool   `json:"truncated"`
	Content   string `json:"content"`
}

type queueData struct {
	Queue string
	Org   string
	Orgs  []userOrg // the caller's reviewer orgs, from GET /user
	Items []reviewItem
	Error string
}

func (h *handler) reviewQueue(w http.ResponseWriter, r *http.Request) {
	u := h.requireUser(w, r)
	if u == nil {
		return
	}
	q := r.URL.Query()
	d := queueData{Queue: "platform", Org: strings.TrimSpace(q.Get("org"))}
	for _, o := range u.Orgs {
		if o.Role == "owner" || o.Role == "admin" || o.Role == "security_reviewer" {
			d.Orgs = append(d.Orgs, o)
		}
	}
	if q.Get("queue") == "org" || d.Org != "" {
		d.Queue = "org"
	}
	path := "/review-queue?limit=100&queue=" + d.Queue
	if d.Queue == "org" {
		path += "&org=" + url.QueryEscape(d.Org)
	}
	res, err := h.call(r).do(http.MethodGet, path, nil)
	switch {
	case err != nil:
		d.Error = "the server could not be reached"
	case res.OK():
		_ = res.decode(&d.Items)
	default:
		d.Error = res.detail()
	}
	h.render(w, r, http.StatusOK, "review_queue", page{Title: "Review queue", User: u, Data: d})
}

type reviewData struct {
	Bundle   reviewBundle
	Files    []reviewFile
	File     *reviewFile
	Lines    []fileLine
	Verdicts []string
	Manifest string
}

type fileLine struct {
	N    int
	Text string
	Hit  bool
}

var verdicts = []string{"confirmed", "dismissed_false_positive", "dismissed_accepted_risk"}

func (h *handler) reviewItemPage(w http.ResponseWriter, r *http.Request) {
	u := h.requireUser(w, r)
	if u == nil {
		return
	}
	id := r.PathValue("id")
	c := h.call(r)
	res, err := c.do(http.MethodGet, "/review-items/"+url.PathEscape(id), nil)
	if err != nil {
		h.render(w, r, http.StatusBadGateway, "message", page{Title: "Review", User: u, Error: "the server could not be reached"})
		return
	}
	if !res.OK() {
		h.render(w, r, res.Status, "message", page{Title: "Review", User: u, Error: res.detail()})
		return
	}
	d := reviewData{Verdicts: verdicts}
	if err := res.decode(&d.Bundle); err != nil {
		h.render(w, r, http.StatusBadGateway, "message", page{Title: "Review", User: u, Error: "unreadable review item"})
		return
	}
	if fres, err := c.do(http.MethodGet, "/review-items/"+url.PathEscape(id)+"/files", nil); err == nil && fres.OK() {
		var list struct {
			Files []reviewFile `json:"files"`
		}
		_ = fres.decode(&list)
		d.Files = list.Files
	}
	if fp := r.URL.Query().Get("file"); fp != "" {
		if fres, err := c.do(http.MethodGet, "/review-items/"+url.PathEscape(id)+"/file?path="+url.QueryEscape(fp), nil); err == nil && fres.OK() {
			var f reviewFile
			if fres.decode(&f) == nil {
				d.File = &f
				hits := map[int]bool{}
				for _, fd := range d.Bundle.Findings {
					if fd.FilePath == f.Path && fd.LineStart > 0 {
						end := fd.LineEnd
						if end < fd.LineStart {
							end = fd.LineStart
						}
						for n := fd.LineStart; n <= end; n++ {
							hits[n] = true
						}
					}
				}
				if !f.Binary {
					for i, line := range strings.Split(f.Content, "\n") {
						d.Lines = append(d.Lines, fileLine{N: i + 1, Text: line, Hit: hits[i+1]})
					}
				}
			}
		}
	}
	if len(d.Bundle.Manifest) > 0 {
		d.Manifest = manifestSummary(d.Bundle.Manifest)
	}
	h.render(w, r, http.StatusOK, "review_item", page{Title: d.Bundle.Item.Namespace + "/" + d.Bundle.Item.Agent + "@" + d.Bundle.Item.Version, User: u, Data: d})
}

// manifestSummary is the few manifest keys a reviewer scans first, as
// text: the page is plain and the whole manifest is in the file view.
func manifestSummary(m map[string]any) string {
	var b strings.Builder
	for _, k := range []string{"name", "version", "summary", "modes", "capabilities"} {
		if v, ok := m[k]; ok {
			b.WriteString(k + ": " + strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(fmtAny(v), "\n", " "), "  ", " ")) + "\n")
		}
	}
	return b.String()
}

func fmtAny(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []any:
		parts := make([]string, 0, len(t))
		for _, e := range t {
			parts = append(parts, fmtAny(e))
		}
		return strings.Join(parts, ", ")
	case map[string]any:
		parts := make([]string, 0, len(t))
		for k, e := range t {
			parts = append(parts, k+"="+fmtAny(e))
		}
		return "{" + strings.Join(parts, " ") + "}"
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	case nil:
		return ""
	}
	return "…"
}

func (h *handler) reviewDecide(w http.ResponseWriter, r *http.Request) {
	if !h.acceptForm(w, r) {
		return
	}
	id := r.PathValue("id")
	backTo := "/ui/review/" + url.PathEscape(id)
	decision := r.PostFormValue("decision")
	if decision != "approve" && decision != "reject" {
		back(w, r, backTo, "", "decision must be approve or reject")
		return
	}
	res, err := h.call(r).do(http.MethodPost, "/review-items/"+url.PathEscape(id)+"/decision", map[string]string{"decision": decision, "rationale": strings.TrimSpace(r.PostFormValue("rationale"))})
	if err != nil || !res.OK() {
		back(w, r, backTo, "", failMsg(res, err))
		return
	}
	if decision == "approve" {
		back(w, r, "/ui/review", "Approved. The version is publishing and signing now.", "")
		return
	}
	back(w, r, "/ui/review", "Rejected.", "")
}

func (h *handler) findingVerdict(w http.ResponseWriter, r *http.Request) {
	if !h.acceptForm(w, r) {
		return
	}
	id, fid := r.PathValue("id"), r.PathValue("fid")
	backTo := "/ui/review/" + url.PathEscape(id)
	v := r.PostFormValue("verdict")
	ok := false
	for _, x := range verdicts {
		ok = ok || x == v
	}
	if !ok {
		back(w, r, backTo, "", "pick a verdict")
		return
	}
	res, err := h.call(r).do(http.MethodPost, "/findings/"+url.PathEscape(fid)+"/verdict", map[string]string{"verdict": v, "reason": strings.TrimSpace(r.PostFormValue("reason"))})
	if err != nil || !res.OK() {
		back(w, r, backTo, "", failMsg(res, err))
		return
	}
	back(w, r, backTo, "Verdict recorded.", "")
}

type abuseReport struct {
	ID        string     `json:"id"`
	Namespace string     `json:"namespace"`
	Agent     string     `json:"agent"`
	Version   string     `json:"version"`
	Category  string     `json:"category"`
	Detail    string     `json:"detail"`
	State     string     `json:"state"`
	CreatedAt *time.Time `json:"createdAt"`
}

type rulesetRelease struct {
	ID           string     `json:"id"`
	Semver       string     `json:"semver"`
	BundleDigest string     `json:"bundleDigest"`
	Notes        string     `json:"notes"`
	PublishedAt  *time.Time `json:"publishedAt"`
}

type staffData struct {
	Queue     []reviewItem
	Reports   []abuseReport
	State     string
	States    []string
	Releases  []rulesetRelease
	Forbidden bool
}

func (h *handler) staffPage(w http.ResponseWriter, r *http.Request) {
	u := h.requireUser(w, r)
	if u == nil {
		return
	}
	c := h.call(r)
	d := staffData{State: r.URL.Query().Get("state"), States: []string{"open", "triaged", "actioned", "dismissed"}}
	if d.State == "" {
		d.State = "open"
	}
	if res, err := c.do(http.MethodGet, "/review-queue?queue=platform&limit=100", nil); err == nil {
		if res.OK() {
			_ = res.decode(&d.Queue)
		} else if res.Status == http.StatusForbidden {
			d.Forbidden = true
		}
	}
	if res, err := c.do(http.MethodGet, "/platform/abuse-reports?limit=100&state="+url.QueryEscape(d.State), nil); err == nil && res.OK() {
		_ = res.decode(&d.Reports)
	}
	if res, err := c.do(http.MethodGet, "/platform/ruleset-releases", nil); err == nil && res.OK() {
		_ = res.decode(&d.Releases)
	}
	status := http.StatusOK
	if d.Forbidden {
		status = http.StatusForbidden
	}
	h.render(w, r, status, "staff", page{Title: "Staff", User: u, Data: d})
}

func (h *handler) staffAbuseTriage(w http.ResponseWriter, r *http.Request) {
	if !h.acceptForm(w, r) {
		return
	}
	id, state := r.PostFormValue("reportId"), r.PostFormValue("state")
	if id == "" || (state != "triaged" && state != "actioned" && state != "dismissed") {
		back(w, r, "/ui/staff", "", "which report, and to which state?")
		return
	}
	res, err := h.call(r).do(http.MethodPost, "/platform/abuse-reports/"+url.PathEscape(id), map[string]string{"state": state, "resolution": strings.TrimSpace(r.PostFormValue("resolution"))})
	if err != nil || !res.OK() {
		back(w, r, "/ui/staff", "", failMsg(res, err))
		return
	}
	back(w, r, "/ui/staff", "Report "+state+".", "")
}

func (h *handler) staffAgentAction(w http.ResponseWriter, r *http.Request) {
	if !h.acceptForm(w, r) {
		return
	}
	ref, action, reason := strings.TrimSpace(r.PostFormValue("ref")), r.PostFormValue("action"), strings.TrimSpace(r.PostFormValue("reason"))
	ns, name, ok := strings.Cut(ref, "/")
	if !ok || ns == "" || name == "" || (action != "quarantine" && action != "block" && action != "reinstate") || reason == "" {
		back(w, r, "/ui/staff", "", "an agent as namespace/name, an action and a reason are all required")
		return
	}
	res, err := h.call(r).do(http.MethodPost, "/platform/agents/"+url.PathEscape(ns)+"/"+url.PathEscape(name)+"/"+action, map[string]string{"reason": reason})
	if err != nil || !res.OK() {
		back(w, r, "/ui/staff", "", failMsg(res, err))
		return
	}
	back(w, r, "/ui/staff", ref+" "+action+"d.", "")
}

func (h *handler) staffRulesetRelease(w http.ResponseWriter, r *http.Request) {
	if !h.acceptForm(w, r) {
		return
	}
	body := map[string]any{}
	for _, k := range []string{"semver", "bundleDigest", "notes"} {
		if v := strings.TrimSpace(r.PostFormValue(k)); v != "" {
			body[k] = v
		}
	}
	res, err := h.call(r).do(http.MethodPost, "/platform/ruleset-releases", body)
	if err != nil || !res.OK() {
		back(w, r, "/ui/staff", "", failMsg(res, err))
		return
	}
	back(w, r, "/ui/staff", "Ruleset release recorded.", "")
}
