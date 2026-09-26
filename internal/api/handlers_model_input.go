package api

import (
	"context"
	"net/http"
	"sort"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/blaktron/agentry/internal/logevent"
	"github.com/blaktron/agentry/internal/ratelimit"
	"github.com/blaktron/agentry/internal/registry"
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
)

// ModelInputCall is what a job credential is asking to do, for the
// extension to admit or refuse (a job past its searches, say).
type ModelInputCall struct {
	Op ModelInputOp
	// Source is the scan's source; empty for a search.
	Source judge.Source
	// Bytes is the scan's text length; Count the search's result count.
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
	// Scanned counts the texts scanned (1 for a scan, one per result for
	// a search); Withheld those withheld or not scanned.
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
	search  websearch.Provider
	callers ModelInputCallers
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

// newModelInputScanner builds the deployment's model-input scanner: Jev
// alone, since the question set is Jev's. Any other judge, or none, leaves
// the routes off.
func newModelInputScanner(provider, model, baseURL, apiKey string) (ModelInputScanner, error) {
	if provider != "typesafe" {
		return nil, nil
	}
	c, err := judge.New(judge.Config{BaseURL: baseURL, APIKey: apiKey, Model: model})
	if err != nil {
		return nil, err
	}
	return judge.NewModelInputScanner(&pacedAsker{asker: c, lim: rate.NewLimiter(judgeRequestsPerSecond, judgeBurst)}), nil
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
		return nil, judge.Usage{}, context.DeadlineExceeded
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
	if r.URL.Path != "/api/v1/model-input/scan" && r.URL.Path != "/api/v1/model-input/search" {
		return false
	}
	_, _, callers := s.modelInputWiring()
	return callers != nil
}

// modelInputCaller is who a model-input call is for.
type modelInputCaller struct {
	kind string // "staff" | "job"
	key  string // the budget's key: the staff user, or the job
	job  string
}

// admitModelInput resolves and budgets the caller, answering the refusal
// itself when there is one.
func (s *Server) admitModelInput(w http.ResponseWriter, r *http.Request, call ModelInputCall) (modelInputCaller, bool) {
	p := principalFrom(r.Context())
	perMin := s.cfg.Limits.ModelInputPerMin
	cred := r.Header.Get(jobTokenHeader)
	if cred != "" {
		if !p.Anonymous {
			problemBadRequest(w, r, "Present one credential: a session, or a job credential, not both.")
			return modelInputCaller{}, false
		}
		_, _, callers := s.modelInputWiring()
		if callers == nil {
			problemUnauthorized(w, r, "This registry admits no job credentials.")
			return modelInputCaller{}, false
		}
		res := s.limits.Allow("model-input-address", clientIP(r), ratelimit.PerMinute(perMin*modelInputAddressFactor), perMin*modelInputAddressFactor)
		writeRateLimitHeaders(w, res)
		if !res.OK {
			s.rateLimited(r, "model-input")
			problemTooMany(w, r, "This address has presented too many job credentials. Wait for the Retry-After interval.")
			return modelInputCaller{}, false
		}
		job, refusal, err := callers.AdmitModelInput(r.Context(), cred, call)
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
		c := modelInputCaller{kind: "job", key: "job:" + job, job: job}
		return c, s.allowModelInput(w, r, c, perMin)
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
	c := modelInputCaller{kind: "staff", key: "user:" + p.UserID.String()}
	return c, s.allowModelInput(w, r, c, perMin)
}

// allowModelInput draws one call from the caller's model-input budget.
func (s *Server) allowModelInput(w http.ResponseWriter, r *http.Request, c modelInputCaller, perMin int) bool {
	res := s.limits.Allow("model-input", c.key, ratelimit.PerMinute(perMin), perMin)
	writeRateLimitHeaders(w, res)
	if !res.OK {
		s.rateLimited(r, "model-input")
		problemTooMany(w, r, "This caller has made too many model-input calls. Wait for the Retry-After interval.")
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
	var req ModelInputScanRequest
	if !readJSON(w, r, &req) {
		return
	}
	src := judge.Source(req.Source)
	if !judge.ValidSource(src) {
		problemValidation(w, r, "source must be one of description, search_result, page, registry or input_file.")
		return
	}
	if len(req.Text) > modelInputMaxBytes {
		writeProblemWith(w, r, http.StatusRequestEntityTooLarge, "model-input-too-large", "Text too long",
			"One scan takes at most 65,536 bytes of text. Send a longer text in parts.", map[string]any{"max": modelInputMaxBytes})
		return
	}
	caller, ok := s.admitModelInput(w, r, ModelInputCall{Op: ModelInputOpScan, Source: src, Bytes: len(req.Text)})
	if !ok {
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
	s.recordModelInput(r.Context(), callers, caller, use, string(res.Verdict), string(src))
	writeJSON(w, http.StatusOK, modelInputScanBody(res))
}

// SearchModelInput implements POST /model-input/search.
func (s *Server) SearchModelInput(w http.ResponseWriter, r *http.Request) {
	var req WebSearchRequest
	if !readJSON(w, r, &req) {
		return
	}
	query, err := websearch.CleanQuery(req.Query)
	if err != nil {
		problemValidation(w, r, "The query must be 1 to 400 characters of text.")
		return
	}
	count := websearch.DefaultCount
	if req.Count != nil {
		count = websearch.ClampCount(*req.Count)
	}
	caller, ok := s.admitModelInput(w, r, ModelInputCall{Op: ModelInputOpSearch, Count: count})
	if !ok {
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
		s.log.WarnContext(r.Context(), "model input: web search", "provider", provider.Name(), "err", err)
		writeProblem(w, r, http.StatusBadGateway, "web-search-failed", "Web search failed",
			"The search provider did not answer. Nothing was returned; retry shortly.")
		return
	}
	results := websearch.Clean(found, count)
	scans := make([]judge.ScanResult, len(results))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
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
			body.Withheld++
		}
		body.Results = append(body.Results, item)
	}
	use.Requests, use.InputTokens, use.Withheld = body.Usage.Requests, body.Usage.InputTokens, body.Withheld
	verdict := "pass"
	if body.Withheld > 0 {
		verdict = "withheld"
	}
	s.recordModelInput(r.Context(), callers, caller, use, verdict, string(judge.SourceSearchResult))
	writeJSON(w, http.StatusOK, body)
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
func (s *Server) recordModelInput(ctx context.Context, callers ModelInputCallers, c modelInputCaller, use ModelInputUse, verdict, source string) {
	if c.kind == "job" && callers != nil {
		callers.RecordModelInput(ctx, c.job, use)
	}
	s.mx.RecordModelInput(ctx, string(use.Op), verdict, use.InputTokens)
	attrs := []any{logevent.ModelInput.Attr(), "op", string(use.Op), "caller", c.kind, "verdict", verdict, "source", source,
		"scanned", use.Scanned, "withheld", use.Withheld, "requests", use.Requests, "input_tokens", use.InputTokens}
	if c.job != "" {
		attrs = append(attrs, "job", c.job)
	}
	s.log.InfoContext(ctx, "model input", attrs...)
}

// logModelInputChunkErrors logs why chunks were not scanned. The error is
// the judge client's, with the key redacted; it never travels to a caller.
func (s *Server) logModelInputChunkErrors(ctx context.Context, res judge.ScanResult) {
	for _, c := range res.Chunks {
		if c.Err != nil {
			s.log.WarnContext(ctx, "model input: chunk not scanned", "chunk", c.Index, "failure", c.Failure, "err", c.Err)
		}
	}
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
