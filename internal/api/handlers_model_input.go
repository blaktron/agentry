package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/blaktron/agentry/internal/logevent"
	"github.com/blaktron/agentry/internal/ratelimit"
	"github.com/blaktron/agentry/internal/registry"
	"github.com/blaktron/agentry/pkg/draftcheck"
	"github.com/blaktron/agentry/pkg/judge"
	"github.com/blaktron/agentry/pkg/websearch"
)

// The model-input routes (agentry#608; plan builder-rework.md D20–D24):
// AI Review of text a model is about to read, and web search brokered by
// the registry with every result scanned before it is returned. They spend
// the deployment's own judge and search keys, so no account's token reaches
// them whatever its scopes. Two callers do:
//   - platform staff, by session: the instance admin on a self-host, and
//     how a person checks the routes by hand;
//   - a hosted job, by the credential an extension minted for it and names
//     in X-Agentry-Job-Token (ModelInputCallers). The job is the budget,
//     and the use is recorded against it.
//
// Nothing of the text, the query or a result's address is kept or logged.

const (
	// jobTokenHeader carries a hosted job's credential. It is never a PAT,
	// and the principal middleware never reads it.
	jobTokenHeader = "X-Agentry-Job-Token"
	// modelInputMaxBytes is the most text one scan takes: eight chunks. A
	// page is at most four (D24); a longer input is sent in parts.
	modelInputMaxBytes = 8 * judge.ChunkSize
	// modelInputTimeout bounds one call: a chunk the judge has not answered
	// by then is not scanned, and a caller withholds it.
	modelInputTimeout = 45 * time.Second
	// modelInputAddressFactor is how much more a client address may spend
	// on presenting job credentials than one job may: it bounds guessing at
	// credentials without starving the hosts behind one NAT.
	modelInputAddressFactor = 10
	// judgeRequestsPerSecond and judgeBurst bound the model-input routes'
	// requests to the judge across the whole replica, under Jev's 1,200 a
	// minute, leaving the publication pipeline its share of the key.
	judgeRequestsPerSecond = 15
	judgeBurst             = 20
	// searchScanParallel is how many of a search's results are scanned at
	// once; each scan asks its own chunks in parallel too, and the pacer
	// above bounds the sum.
	searchScanParallel = 4
)

// ModelInputScanner scans text as model input: *judge.ModelInputScanner.
type ModelInputScanner interface {
	Scan(ctx context.Context, source judge.Source, text string) judge.ScanResult
	Model() string
	QuestionSet() string
}

// ModelInputOp is which model-input route a call is.
type ModelInputOp string

// The model-input operations.
const (
	ModelInputOpScan   ModelInputOp = "scan"
	ModelInputOpSearch ModelInputOp = "search"
	// ModelInputOpCheck is AI Review of a finished draft (agentry#708):
	// the release rubric and the draft question set over its package.
	ModelInputOpCheck ModelInputOp = "check"
)

// ModelInputCall is what a job credential is asking to do, for the
// extension to admit or refuse (a job past its searches, say).
type ModelInputCall struct {
	Op ModelInputOp
	// Source is the scan's source; empty for a search or a check.
	Source judge.Source
	// Bytes is the scan's text length, or a check's over every file;
	// Count the search's result count.
	Bytes int
	Count int
}

// ModelInputUse is what one admitted call spent, for the record against
// its job. It is a count, never a price: AI Review is 1 credit an
// operation, however many scans it makes (DEV-150).
type ModelInputUse struct {
	Op ModelInputOp
	// Requests and InputTokens are the judge's.
	Requests    int
	InputTokens int
	// Scanned counts the texts scanned (1 for a scan or a check, one per
	// result for a search); Withheld those withheld, flagged or not
	// scanned.
	Scanned  int
	Withheld int
	// Searches is 1 for a search the provider answered.
	Searches int
}

// ModelInputCallers is the seam through which an extension admits hosted
// jobs to the model-input routes (pkg/extension AdmitsModelInput). The core
// has none, so on a core registry only platform staff reach the routes.
type ModelInputCallers interface {
	// AdmitModelInput names the job a credential acts for, or refuses the
	// call: a Refusal the route answers in its own status and words, or ""
	// with no refusal for a credential that names no job, which is 401.
	// An error is "unknown", and the route fails closed with 503.
	AdmitModelInput(ctx context.Context, credential string, call ModelInputCall) (job string, refusal *registry.Refusal, err error)
	// RecordModelInput records an admitted call's use against its job.
	RecordModelInput(ctx context.Context, job string, use ModelInputUse)
}

// modelInputState is the server's model-input wiring.
type modelInputState struct {
	mu      sync.RWMutex
	scanner ModelInputScanner
	checker DraftChecker
	search  websearch.Provider
	callers ModelInputCallers
}

// DraftChecker reads a finished draft with the release rubric and the
// draft question set: *draftcheck.Checker.
type DraftChecker interface {
	Check(ctx context.Context, p draftcheck.Package) (draftcheck.Result, error)
}

// SetDraftChecker sets the checker the check route asks; nil turns it off
// (503). New sets it from the judge configuration when the judge is Jev.
func (s *Server) SetDraftChecker(c DraftChecker) {
	s.modelInput.mu.Lock()
	defer s.modelInput.mu.Unlock()
	s.modelInput.checker = c
}

func (s *Server) draftChecker() DraftChecker {
	s.modelInput.mu.RLock()
	defer s.modelInput.mu.RUnlock()
	return s.modelInput.checker
}

// SetModelInputScanner sets the scanner the routes ask; nil turns them off
// (503). New sets it from the judge configuration when the judge is Jev.
func (s *Server) SetModelInputScanner(sc ModelInputScanner) {
	s.modelInput.mu.Lock()
	defer s.modelInput.mu.Unlock()
	s.modelInput.scanner = sc
}

// SetWebSearch sets the provider the search route brokers; nil turns it
// off (503).
func (s *Server) SetWebSearch(p websearch.Provider) {
	s.modelInput.mu.Lock()
	defer s.modelInput.mu.Unlock()
	s.modelInput.search = p
}

// SetModelInputCallers sets the extension that admits hosted jobs.
func (s *Server) SetModelInputCallers(c ModelInputCallers) {
	s.modelInput.mu.Lock()
	defer s.modelInput.mu.Unlock()
	s.modelInput.callers = c
}

// ModelInputCallers is the extension that admits hosted jobs, or nil.
func (s *Server) ModelInputCallers() ModelInputCallers {
	_, _, c := s.modelInputWiring()
	return c
}

func (s *Server) modelInputWiring() (ModelInputScanner, websearch.Provider, ModelInputCallers) {
	s.modelInput.mu.RLock()
	defer s.modelInput.mu.RUnlock()
	return s.modelInput.scanner, s.modelInput.search, s.modelInput.callers
}

// judgeTypeSafe is the judge provider the model-input question set is for.
const judgeTypeSafe = "typesafe"

// newModelInputScanner builds the deployment's model-input scanner and
// draft checker over one paced client: Jev alone, since the question sets
// are Jev's. Any other judge, or none, leaves the routes off.
func newModelInputScanner(provider, model, baseURL, apiKey string) (ModelInputScanner, DraftChecker, error) {
	if provider != judgeTypeSafe {
		return nil, nil, nil
	}
	c, err := judge.New(judge.Config{BaseURL: baseURL, APIKey: apiKey, Model: model})
	if err != nil {
		return nil, nil, err
	}
	paced := &pacedAsker{asker: c, lim: rate.NewLimiter(judgeRequestsPerSecond, judgeBurst)}
	return judge.NewModelInputScanner(paced), draftcheck.New(paced), nil
}

// pacedAsker holds a replica's model-input requests to the judge under
// its rate; a request that cannot start before the call's deadline fails
// as a timeout, and its chunk is not scanned.
type pacedAsker struct {
	asker judge.Asker
	lim   *rate.Limiter
}

func (p *pacedAsker) Model() string { return p.asker.Model() }

func (p *pacedAsker) Ask(ctx context.Context, state map[string]string, qs []judge.Question) (map[string]float64, judge.Usage, error) {
	if err := p.lim.Wait(ctx); err != nil {
		if ctx.Err() != nil {
			return nil, judge.Usage{}, ctx.Err() // cancelled, or the deadline passed while waiting
		}
		// The limiter saw the request could not start before the deadline.
		return nil, judge.Usage{}, fmt.Errorf("%w: %v", context.DeadlineExceeded, err)
	}
	return p.asker.Ask(ctx, state, qs)
}

// modelInputJobRequest reports whether r presents a job credential to a
// model-input route on a registry that admits jobs. Such a request is not
// drawn from the anonymous class by address — every sandbox host behind a
// NAT shares one — and the route draws it from its own budgets instead.
func (s *Server) modelInputJobRequest(r *http.Request) bool {
	if r.Method != http.MethodPost || r.Header.Get(jobTokenHeader) == "" {
		return false
	}
	switch r.URL.Path {
	case "/api/v1/model-input/scan", "/api/v1/model-input/search", "/api/v1/model-input/check":
	default:
		return false
	}
	_, _, callers := s.modelInputWiring()
	return callers != nil
}

// callerKind is who a model-input call is for.
type callerKind string

const (
	callerStaff callerKind = "staff"
	callerJob   callerKind = "job"
)

// modelInputCaller is who a model-input call is for: a staff member, or a
// job once the extension has named it.
type modelInputCaller struct {
	kind callerKind
	cred string // the job credential, until the job is named
	job  string
}

// gateModelInput decides who is calling before the body is read, and
// draws the call from a budget there and then, so a caller cannot spend
// the server's parsing for free with a body that will be refused. A staff
// session spends the staff member's model-input budget; a job credential
// spends its address's larger one, since the job it names is not known
// until the extension says. It answers the refusal itself when there is
// one.
func (s *Server) gateModelInput(w http.ResponseWriter, r *http.Request) (modelInputCaller, bool) {
	p := principalFrom(r.Context())
	perMin := s.cfg.Limits.ModelInputPerMin
	if cred := r.Header.Get(jobTokenHeader); cred != "" {
		if !p.Anonymous {
			problemBadRequest(w, r, "Present one credential: a session or a token, or a job credential, not both.")
			return modelInputCaller{}, false
		}
		if _, _, callers := s.modelInputWiring(); callers == nil {
			problemUnauthorized(w, r, "This registry admits no job credentials.")
			return modelInputCaller{}, false
		}
		if !s.allowModelInput(w, r, "address:"+clientIP(r), perMin*modelInputAddressFactor,
			"This address has presented too many job credentials. Wait for the Retry-After interval.") {
			return modelInputCaller{}, false
		}
		return modelInputCaller{kind: callerJob, cred: cred}, true
	}
	if p.Anonymous {
		problemUnauthorized(w, r, "Sign in as platform staff, or present a hosted job's credential.")
		return modelInputCaller{}, false
	}
	if p.Via != "session" {
		problemForbidden(w, r, "A token cannot call this route, whatever its scopes: it spends the deployment's own judge and search keys. Sign in as platform staff, or present a hosted job's credential.")
		return modelInputCaller{}, false
	}
	if !p.PlatformStaff {
		problemForbidden(w, r, "This route is open to platform staff and hosted jobs only.")
		return modelInputCaller{}, false
	}
	if !s.allowModelInput(w, r, "user:"+p.UserID.String(), perMin,
		"This caller has made too many model-input calls. Wait for the Retry-After interval.") {
		return modelInputCaller{}, false
	}
	return modelInputCaller{kind: callerStaff}, true
}

// admitModelInput asks the extension which job a job credential acts for
// and whether this call fits it, then draws the call from the job's own
// budget. A staff caller was admitted by the gate.
func (s *Server) admitModelInput(w http.ResponseWriter, r *http.Request, c modelInputCaller, call ModelInputCall) (modelInputCaller, bool) {
	if c.kind != callerJob {
		return c, true
	}
	_, _, callers := s.modelInputWiring()
	job, refusal, err := callers.AdmitModelInput(r.Context(), c.cred, call)
	switch {
	case err != nil:
		s.log.WarnContext(r.Context(), "model input: admission", "op", string(call.Op), "err", err)
		writeProblem(w, r, http.StatusServiceUnavailable, "model-input-admission-unavailable", "Job check unavailable",
			"The registry could not check this job credential. Nothing was scanned; retry shortly.")
		return modelInputCaller{}, false
	case refusal != nil:
		writeProblemWith(w, r, refusal.Status, refusal.Slug, refusal.Title, refusal.Detail, refusal.Fields)
		return modelInputCaller{}, false
	case job == "":
		problemUnauthorized(w, r, "This job credential is not valid, or its job has ended.")
		return modelInputCaller{}, false
	}
	if !s.allowModelInput(w, r, "job:"+job, s.cfg.Limits.ModelInputPerMin,
		"This job has made too many model-input calls. Wait for the Retry-After interval.") {
		return modelInputCaller{}, false
	}
	return modelInputCaller{kind: callerJob, job: job}, true
}

// allowModelInput draws one call from a model-input budget, answering 429
// with detail when it is spent.
func (s *Server) allowModelInput(w http.ResponseWriter, r *http.Request, key string, perMin int, detail string) bool {
	res := s.limits.Allow("model-input", key, ratelimit.PerMinute(perMin), perMin)
	writeRateLimitHeaders(w, res)
	if !res.OK {
		s.rateLimited(r, "model-input")
		problemTooMany(w, r, detail)
		return false
	}
	return true
}

func (s *Server) problemModelInputOff(w http.ResponseWriter, r *http.Request) {
	writeProblem(w, r, http.StatusServiceUnavailable, "model-input-unavailable", "AI Review of model input off",
		"This registry's judge is not TypeSafe's Jev, so it cannot scan text as model input. A caller withholds what it could not have scanned.")
}

// ScanModelInput implements POST /model-input/scan.
func (s *Server) ScanModelInput(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.gateModelInput(w, r)
	if !ok {
		return
	}
	var req ModelInputScanRequest
	if !readJSON(w, r, &req) {
		return
	}
	src := judge.Source(req.Source)
	if !judge.ValidSource(src) {
		problemValidation(w, r, "The source must be one of "+sourceList()+".")
		return
	}
	if len(req.Text) > modelInputMaxBytes {
		writeProblemWith(w, r, http.StatusRequestEntityTooLarge, "model-input-too-large", "Text too long",
			fmt.Sprintf("One scan takes at most %d bytes of text. Send a longer text in parts.", modelInputMaxBytes), map[string]any{"max": modelInputMaxBytes})
		return
	}
	if caller, ok = s.admitModelInput(w, r, caller, ModelInputCall{Op: ModelInputOpScan, Source: src, Bytes: len(req.Text)}); !ok {
		return
	}
	scanner, _, callers := s.modelInputWiring()
	if scanner == nil {
		s.problemModelInputOff(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), modelInputTimeout)
	defer cancel()
	res := scanner.Scan(ctx, src, req.Text)
	s.logModelInputChunkErrors(r.Context(), res)

	use := ModelInputUse{Op: ModelInputOpScan, Requests: res.Usage.Requests, InputTokens: res.Usage.InputTokens, Scanned: 1}
	if res.Verdict != judge.VerdictPass {
		use.Withheld = 1
	}
	s.recordModelInput(r.Context(), callers, caller, use, res.Verdict, src)
	writeJSON(w, http.StatusOK, modelInputScanBody(res))
}

// SearchModelInput implements POST /model-input/search.
func (s *Server) SearchModelInput(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.gateModelInput(w, r)
	if !ok {
		return
	}
	var req WebSearchRequest
	if !readJSON(w, r, &req) {
		return
	}
	query, err := websearch.CleanQuery(req.Query)
	if err != nil {
		problemValidation(w, r, fmt.Sprintf("The query must be 1 to %d characters of text, with no line breaks or other control characters.", websearch.MaxQuery))
		return
	}
	count := websearch.DefaultCount
	if req.Count != nil {
		count = websearch.ClampCount(*req.Count)
	}
	if caller, ok = s.admitModelInput(w, r, caller, ModelInputCall{Op: ModelInputOpSearch, Count: count}); !ok {
		return
	}
	scanner, provider, callers := s.modelInputWiring()
	if provider == nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "web-search-unavailable", "Web search off",
			"This registry brokers no web search: it has no search provider configured.")
		return
	}
	if scanner == nil {
		// A result that cannot be scanned cannot be returned, so the search
		// is not spent.
		s.problemModelInputOff(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), modelInputTimeout)
	defer cancel()
	found, err := provider.Search(ctx, query, count)
	if err != nil {
		s.log.WarnContext(r.Context(), "model input: web search", "provider", provider.Name(), "failure", searchFailure(err))
		writeProblem(w, r, http.StatusBadGateway, "web-search-failed", "Web search failed",
			"The search provider did not answer. Nothing was returned; retry shortly.")
		return
	}
	results := websearch.Clean(found, count)
	scans := make([]judge.ScanResult, len(results))
	var wg sync.WaitGroup
	sem := make(chan struct{}, searchScanParallel)
	for i, res := range results {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			scans[i] = scanner.Scan(ctx, judge.SourceSearchResult, searchResultText(res))
		}()
	}
	wg.Wait()

	body := WebSearchResults{Provider: provider.Name(), Results: make([]WebSearchResult, 0, len(results)),
		Model: scanner.Model(), QuestionSet: scanner.QuestionSet()}
	use := ModelInputUse{Op: ModelInputOpSearch, Searches: 1, Scanned: len(results)}
	for i, res := range results {
		sc := scans[i]
		s.logModelInputChunkErrors(r.Context(), sc)
		body.Usage.Requests += sc.Usage.Requests
		body.Usage.InputTokens += sc.Usage.InputTokens
		item := WebSearchResult{Url: res.URL, Verdict: ModelInputVerdict(sc.Verdict), Score: sc.Score}
		if len(sc.Chunks) > 0 && sc.Verdict != judge.VerdictNotScanned {
			scores := modelInputScores(sc.Scores)
			item.Scores = &scores
		}
		if flagged := modelInputFlagged(sc.Flagged); len(flagged) > 0 {
			f := make([]WebSearchResultFlagged, len(flagged))
			for j, id := range flagged {
				f[j] = WebSearchResultFlagged(id)
			}
			item.Flagged = &f
		}
		if sc.Verdict == judge.VerdictPass {
			title, snippet := res.Title, res.Snippet
			item.Title, item.Snippet = &title, &snippet
		} else {
			// The address was scanned with the rest, and a path or a query
			// can carry an instruction: a result that did not pass keeps
			// only its origin.
			item.Url = websearch.Origin(res.URL)
			body.Withheld++
		}
		body.Results = append(body.Results, item)
	}
	use.Requests, use.InputTokens, use.Withheld = body.Usage.Requests, body.Usage.InputTokens, body.Withheld
	verdict := judge.VerdictPass
	if body.Withheld > 0 {
		verdict = judge.VerdictWithheld
	}
	s.recordModelInput(r.Context(), callers, caller, use, verdict, judge.SourceSearchResult)
	writeJSON(w, http.StatusOK, body)
}

// CheckDraft implements POST /model-input/check (agentry#708): AI Review
// of a finished draft's package, with the release rubric S5 asks and the
// draft question set, before the person submits it.
func (s *Server) CheckDraft(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.gateModelInput(w, r)
	if !ok {
		return
	}
	var req DraftCheckRequest
	if !readJSON(w, r, &req) {
		return
	}
	if len(req.Description) > judge.DraftMaxDescription {
		problemValidation(w, r, fmt.Sprintf("The description must be at most %d bytes.", judge.DraftMaxDescription))
		return
	}
	pkg := draftcheck.Package{Description: req.Description, Files: make([]draftcheck.File, len(req.Files))}
	total := 0
	for i, f := range req.Files {
		pkg.Files[i] = draftcheck.File{Path: f.Path, Content: f.Content}
		total += len(f.Content)
	}
	// Refuse what the check will not read before the job is charged a
	// call: Read is the checker's own reading.
	if _, err := draftcheck.Read(pkg); err != nil {
		switch {
		case errors.Is(err, draftcheck.ErrTooLarge):
			writeProblemWith(w, r, http.StatusRequestEntityTooLarge, "draft-too-large", "Draft too large",
				fmt.Sprintf("A check reads at most %d files and %d bytes of text: a draft's package.", draftcheck.MaxFiles, draftcheck.MaxBytes),
				map[string]any{"maxFiles": draftcheck.MaxFiles, "maxBytes": draftcheck.MaxBytes})
		case errors.Is(err, draftcheck.ErrNotADraft):
			writeProblem(w, r, http.StatusUnprocessableEntity, "draft-unreadable", "Not a draft",
				"The files are not a draft's package: it needs an agent.yaml that parses and the instruction file it names.")
		default:
			problemValidation(w, r, "Each file needs a relative, clean path named once, and UTF-8 text.")
		}
		return
	}
	if caller, ok = s.admitModelInput(w, r, caller, ModelInputCall{Op: ModelInputOpCheck, Bytes: total}); !ok {
		return
	}
	_, _, callers := s.modelInputWiring()
	checker := s.draftChecker()
	if checker == nil {
		s.problemModelInputOff(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), modelInputTimeout)
	defer cancel()
	res, err := checker.Check(ctx, pkg)
	if err != nil {
		// Read accepted the package above, so this is the checker's own
		// failure: nothing was asked.
		s.log.WarnContext(r.Context(), "model input: check", "err", err)
		writeProblem(w, r, http.StatusServiceUnavailable, "model-input-unavailable", "AI Review of the draft failed",
			"The registry could not read this draft. Nothing was asked; retry shortly.")
		return
	}
	s.logDraftCheckErrors(r.Context(), res)
	use := ModelInputUse{Op: ModelInputOpCheck, Requests: res.Usage.Requests, InputTokens: res.Usage.InputTokens, Scanned: 1}
	verdict := judge.VerdictPass
	switch {
	case res.Rubric.Verdict == judge.VerdictFlagged || res.Draft.Verdict == judge.VerdictFlagged:
		verdict = judge.VerdictFlagged
	case res.Rubric.Verdict == judge.VerdictNotScanned || res.Draft.Verdict == judge.VerdictNotScanned:
		verdict = judge.VerdictNotScanned
	}
	if verdict != judge.VerdictPass {
		use.Withheld = 1
	}
	s.recordModelInput(r.Context(), callers, caller, use, verdict, "")
	writeJSON(w, http.StatusOK, draftCheckBody(res))
}

// logDraftCheckErrors logs why a half of a check was not scanned, as
// logModelInputChunkErrors does: a vendor's answer by its status alone.
func (s *Server) logDraftCheckErrors(ctx context.Context, res draftcheck.Result) {
	for half, err := range map[string]error{"rubric": res.Rubric.Err, "draft": res.Draft.Err} {
		if err == nil {
			continue
		}
		var se *judge.StatusError
		if errors.As(err, &se) {
			s.log.WarnContext(ctx, "model input: check not scanned", "half", half, "status", se.Status)
			continue
		}
		s.log.WarnContext(ctx, "model input: check not scanned", "half", half, "err", err)
	}
}

func draftCheckBody(res draftcheck.Result) DraftCheck {
	rb := DraftRubricCheck{Verdict: DraftCheckVerdict(res.Rubric.Verdict), RubricHash: res.Rubric.Hash, Findings: []DraftRubricFinding{}}
	if res.Rubric.Verdict == judge.VerdictNotScanned {
		rb.Failure = draftCheckFailure(res.Rubric.Failure)
	} else {
		sc := res.Rubric.Scores
		rb.Scores = &DraftRubricScores{
			C1Injection: sc[judge.RubricIDInjection], C2Exfiltration: sc[judge.RubricIDExfiltration],
			C3UndeclaredCapability: sc[judge.RubricIDUndeclaredCapability], C4UserDeception: sc[judge.RubricIDDeception],
			C5Obfuscation: sc[judge.RubricIDObfuscation], C6DestructiveActions: sc[judge.RubricIDDestructive],
		}
		for _, f := range res.Rubric.Findings {
			rb.Findings = append(rb.Findings, DraftRubricFinding{Id: DraftRubricFindingId(f.ID), Score: f.Score, Path: f.Path,
				Severity: DraftRubricFindingSeverity(f.Severity)})
		}
	}
	ds := DraftSetCheck{Verdict: DraftCheckVerdict(res.Draft.Verdict), Score: res.Draft.Score, QuestionSet: res.Draft.QuestionSet,
		Flagged: []DraftSetCheckFlagged{}}
	if res.Draft.Verdict == judge.VerdictNotScanned {
		ds.Failure = draftCheckFailure(res.Draft.Failure)
	} else {
		sc := res.Draft.Scores
		ds.Scores = &DraftSetScores{OffTask: sc[judge.DraftIDOffTask]}
		for _, id := range res.Draft.Flagged {
			ds.Flagged = append(ds.Flagged, DraftSetCheckFlagged(id))
		}
	}
	return DraftCheck{Rubric: rb, Draft: ds, Model: res.Model,
		Usage: ModelInputUsage{Requests: res.Usage.Requests, InputTokens: res.Usage.InputTokens}}
}

// draftCheckFailure is the spec's word for a half not scanned; only its
// three words travel.
func draftCheckFailure(f string) *DraftCheckFailure {
	w := DraftCheckFailure(judge.FailureJudgeError)
	switch f {
	case judge.FailureTimeout, judge.FailureTooLarge:
		w = DraftCheckFailure(f)
	}
	return &w
}

// searchResultText is what a search result is scanned as: everything of
// it a model would be shown, its address included, since an address can
// carry an instruction too.
func searchResultText(r websearch.Result) string {
	return "Title: " + r.Title + "\nURL: " + r.URL + "\nSnippet: " + r.Snippet
}

// recordModelInput records a call against its job, counts it, and writes
// its one log line: counts and verdicts, never the text, the query or an
// address.
func (s *Server) recordModelInput(ctx context.Context, callers ModelInputCallers, c modelInputCaller, use ModelInputUse, verdict judge.Verdict, source judge.Source) {
	if c.kind == callerJob && callers != nil {
		callers.RecordModelInput(ctx, c.job, use)
	}
	s.mx.RecordModelInput(ctx, string(use.Op), string(verdict), use.InputTokens)
	attrs := []any{logevent.ModelInput.Attr(), "op", string(use.Op), "caller", string(c.kind), "verdict", string(verdict), "source", string(source),
		"scanned", use.Scanned, "withheld", use.Withheld, "requests", use.Requests, "input_tokens", use.InputTokens}
	if c.job != "" {
		attrs = append(attrs, "job", c.job)
	}
	s.log.InfoContext(ctx, "model input", attrs...)
}

// logModelInputChunkErrors logs why chunks were not scanned. A vendor's
// answer is logged by its status alone: its body can echo the scanned text,
// which no line carries. Other errors (a transport error, an answer out of
// shape, a model mismatch) are the client's own words, the key redacted.
func (s *Server) logModelInputChunkErrors(ctx context.Context, res judge.ScanResult) {
	for _, c := range res.Chunks {
		if c.Err == nil {
			continue
		}
		var se *judge.StatusError
		if errors.As(c.Err, &se) {
			s.log.WarnContext(ctx, "model input: chunk not scanned", "chunk", c.Index, "failure", c.Failure, "status", se.Status)
			continue
		}
		s.log.WarnContext(ctx, "model input: chunk not scanned", "chunk", c.Index, "failure", c.Failure, "err", c.Err)
	}
}

// searchFailure is what a provider's failure is logged as: its status, or
// that it did not answer. Neither its body nor its error text is logged,
// since either can echo the query.
func searchFailure(err error) string {
	var se *websearch.StatusError
	if errors.As(err, &se) {
		return fmt.Sprintf("status %d", se.Status)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	return "no answer"
}

// sourceList is the sources a scan takes, for a refusal's words.
func sourceList() string {
	srcs := judge.Sources()
	parts := make([]string, len(srcs))
	for i, src := range srcs {
		parts[i] = string(src)
	}
	return strings.Join(parts[:len(parts)-1], ", ") + " or " + parts[len(parts)-1]
}

func modelInputScanBody(res judge.ScanResult) ModelInputScan {
	body := ModelInputScan{
		Verdict: ModelInputVerdict(res.Verdict), Score: res.Score, Scores: modelInputScores(res.Scores),
		Flagged: []ModelInputScanFlagged{}, Chunks: make([]ModelInputChunk, 0, len(res.Chunks)),
		Model: res.Model, QuestionSet: res.QuestionSet,
		Usage: ModelInputUsage{Requests: res.Usage.Requests, InputTokens: res.Usage.InputTokens},
	}
	for _, id := range modelInputFlagged(res.Flagged) {
		body.Flagged = append(body.Flagged, ModelInputScanFlagged(id))
	}
	for _, c := range res.Chunks {
		ch := ModelInputChunk{Index: c.Index, Bytes: c.Bytes, Verdict: ModelInputVerdict(c.Verdict)}
		if c.Verdict == judge.VerdictNotScanned {
			// Only the spec's two words travel; the generated constants'
			// names are the generator's to change, so the words are pkg/judge's.
			f := ModelInputChunkFailure(judge.FailureJudgeError)
			if c.Failure == judge.FailureTimeout {
				f = ModelInputChunkFailure(judge.FailureTimeout)
			}
			ch.Failure = &f
		} else {
			sc := modelInputScores(c.Scores)
			ch.Scores = &sc
		}
		body.Chunks = append(body.Chunks, ch)
	}
	return body
}

func modelInputScores(m map[string]int) ModelInputScores {
	return ModelInputScores{
		Injection: m[judge.ModelInputIDInjection], Exfiltration: m[judge.ModelInputIDExfiltration],
		Deception: m[judge.ModelInputIDDeception], Obfuscation: m[judge.ModelInputIDObfuscation],
	}
}

// modelInputFlagged keeps only the four question ids the spec names, in
// order, so an id a future scanner adds never reaches an enum it breaks.
func modelInputFlagged(ids []string) []string {
	known := map[string]bool{}
	for _, q := range judge.ModelInputQuestions() {
		known[q.ID] = true
	}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if known[id] {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}
