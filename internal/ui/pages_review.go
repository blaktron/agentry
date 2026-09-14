package ui

import (
	"net/http"
	"net/url"
	"sort"
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
	Report   *reviewReport  `json:"report"`
}

// reviewReport is the slice of the scan report the page shows beside the
// findings: which judge ran and, for platform staff, what it cost in tokens
// (the API sends judgeUsage to staff only).
type reviewReport struct {
	JudgeModel string      `json:"judgeModel"`
	JudgeUsage *judgeUsage `json:"judgeUsage"`
}

type judgeUsage struct {
	PromptTokens     int `json:"promptTokens"`
	CompletionTokens int `json:"completionTokens"`
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
		d.Error = notSent
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
	Verdicts []verdictOption
	Manifest string
}

type fileLine struct {
	N    int
	Text string
	Hit  bool
}

// verdictOption is one finding verdict as the page offers it: the API's value,
// which is the enum SetFindingVerdict accepts and must not change, and a label
// a reviewer can read. The select used to print the value as its own label, so
// a reviewer chose between "dismissed_false_positive" and
// "dismissed_accepted_risk". The accepted-risk label carries the ceiling the
// API enforces (severity medium and below, §8.5).
type verdictOption struct {
	Value string
	Label string
}

var verdicts = []verdictOption{
	{"confirmed", "Confirmed"},
	{"dismissed_false_positive", "False positive"},
	{"dismissed_accepted_risk", "Accepted risk (medium and below)"},
}

func (h *handler) reviewItemPage(w http.ResponseWriter, r *http.Request) {
	u := h.requireUser(w, r)
	if u == nil {
		return
	}
	id := r.PathValue("id")
	c := h.call(r)
	res, err := c.do(http.MethodGet, "/review-items/"+url.PathEscape(id), nil)
	if err != nil {
		h.render(w, r, http.StatusBadGateway, "message", page{Title: "Review", User: u, Error: notSent})
		return
	}
	if !res.OK() {
		h.render(w, r, res.Status, "message", page{Title: "Review", User: u, Error: res.detail()})
		return
	}
	d := reviewData{Verdicts: verdicts}
	if err := res.decode(&d.Bundle); err != nil {
		h.render(w, r, http.StatusBadGateway, "message", page{Title: "Review", User: u, Error: "This review item could not be read."})
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
		// Sorted, so a declared server's env (or any object) reads the
		// same on every render.
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(t))
		for _, k := range keys {
			parts = append(parts, k+"="+fmtAny(t[k]))
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
		h.back(w, r, backTo, "", "Nothing was decided: the decision must be approve or reject.")
		return
	}
	res, err := h.call(r).do(http.MethodPost, "/review-items/"+url.PathEscape(id)+"/decision", map[string]string{"decision": decision, "rationale": strings.TrimSpace(r.PostFormValue("rationale"))})
	if err != nil || !res.OK() {
		h.back(w, r, backTo, "", failMsg(res, err))
		return
	}
	if decision == "approve" {
		h.back(w, r, "/ui/review", "Approved. The version is publishing and signing now.", "")
		return
	}
	// What a reject does depends on where the version was, and this page
	// cannot see that: the API sends a pending version to `rejected`, but a
	// QUARANTINED one to `yanked` instead — the rejected edge does not exist
	// for it (internal/api/handlers_reviews.go) — and a yanked version still
	// resolves for an exact pin (internal/registry/resolve.go). The rescan
	// path files exactly those items, so "will not publish" was false for
	// them. The flash says what the decision recorded and leaves publication
	// to the version's own state (agentry#273 carries that seam).
	h.back(w, r, "/ui/review", "Rejected. The decision and rationale are recorded with the version.", "")
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
		ok = ok || x.Value == v
	}
	if !ok {
		h.back(w, r, backTo, "", "Nothing was recorded: that is not a verdict.")
		return
	}
	res, err := h.call(r).do(http.MethodPost, "/findings/"+url.PathEscape(fid)+"/verdict", map[string]string{"verdict": v, "reason": strings.TrimSpace(r.PostFormValue("reason"))})
	if err != nil || !res.OK() {
		h.back(w, r, backTo, "", failMsg(res, err))
		return
	}
	h.back(w, r, backTo, "Verdict recorded.", "")
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
		h.back(w, r, "/ui/staff", "", "Nothing was recorded: pick a report and a triage state.")
		return
	}
	res, err := h.call(r).do(http.MethodPost, "/platform/abuse-reports/"+url.PathEscape(id), map[string]string{"state": state, "resolution": strings.TrimSpace(r.PostFormValue("resolution"))})
	if err != nil || !res.OK() {
		h.back(w, r, "/ui/staff", "", failMsg(res, err))
		return
	}
	h.back(w, r, "/ui/staff", "Report marked "+state+".", "")
}

// agentActionDone is what a consumer meets after each enforcement action, and
// it doubles as the set of actions the form may post. Read out of the handlers
// rather than remembered: quarantine moves the latest published version and
// only that one, and only when there is one — an agent with nothing published
// keeps the flag and moves no version, and a failed move is logged and still
// answers 204 (internal/api/handlers_policy.go) — so the flash states what
// quarantine does to a published version rather than asserting this call
// moved one. A quarantined version's downloads answer 409
// (handlers_versions.go, handlers_version_files.go); block walks every live
// version to `blocked` and every download answers 410 Gone; search and browse
// exclude `blocked` and nothing else (internal/store/queries/agents.sql), so a
// quarantined BriefAgent stays listed with its state on it. Reinstate walks
// blocked and quarantined versions back to published (internal/scan/worker.go)
// and never touches a yanked one. The flash used to be built as action + "d.",
// which said "blockd" and named the action rather than its consequence.
var agentActionDone = map[string]string{
	"quarantine": "quarantined. A published version under quarantine answers 409 on download; the BriefAgent stays in search, carrying the state.",
	"block":      "blocked. Every download for it answers 410 Gone.",
	"reinstate":  "reinstated. Quarantined and blocked versions are published again; yanked ones stay yanked.",
}

func (h *handler) staffAgentAction(w http.ResponseWriter, r *http.Request) {
	if !h.acceptForm(w, r) {
		return
	}
	ref, action, reason := strings.TrimSpace(r.PostFormValue("ref")), r.PostFormValue("action"), strings.TrimSpace(r.PostFormValue("reason"))
	ns, name, cut := strings.Cut(ref, "/")
	done, known := agentActionDone[action]
	if !cut || ns == "" || name == "" || !known || reason == "" {
		h.back(w, r, "/ui/staff", "", "Nothing was done: a BriefAgent as namespace/name, an action and a reason are all required.")
		return
	}
	res, err := h.call(r).do(http.MethodPost, "/platform/agents/"+url.PathEscape(ns)+"/"+url.PathEscape(name)+"/"+action, map[string]string{"reason": reason})
	if err != nil || !res.OK() {
		h.back(w, r, "/ui/staff", "", failMsg(res, err))
		return
	}
	h.back(w, r, "/ui/staff", ref+" "+done, "")
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
		h.back(w, r, "/ui/staff", "", failMsg(res, err))
		return
	}
	// 201 recorded a release; 200 is the row already on file, which changes
	// nothing (internal/api/handlers_ruleset.go). One flash for both claimed a
	// record that had not happened. The sweep is not in either flash: the API
	// enqueues it only when the insert was genuinely new, and a 201 over an
	// existing row (the upsert's other branch) starts none.
	if res.Status == http.StatusCreated {
		h.back(w, r, "/ui/staff", "Ruleset release recorded.", "")
		return
	}
	h.back(w, r, "/ui/staff", "That ruleset release was already recorded. Nothing changed.", "")
}
