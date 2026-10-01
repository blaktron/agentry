package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/knowledge"
	"github.com/blaktron/agentry/internal/queue"
	"github.com/blaktron/agentry/internal/registry"
	"github.com/blaktron/agentry/internal/scan"
	"github.com/blaktron/agentry/internal/voice"
	"github.com/blaktron/agentry/pkg/judge"
	"github.com/blaktron/agentry/pkg/ruleset"
)

// The Writing Voice (agentry#809) through its routes: a version is put,
// reviewed by the worker, made live only on a clean verdict, kept pending
// when flagged, kept in review when the judge cannot answer, restored,
// sealed at rest, and the caller's own.

// voiceMarker is a line no real voice holds, so that finding it anywhere at
// rest is finding a voice in the clear.
const voiceMarker = "Write like a lighthouse keeper: plain words, zircon-heron-809."

func voiceText(n int) string {
	return "# Writing Voice\n\n" + voiceMarker + "\n\n- Short sentences. Version " + strings.Repeat("I", n) + ".\n"
}

// stubVoiceJudge answers the voice set as a test sets it: pass, flagged on
// override, or unavailable.
type stubVoiceJudge struct {
	mu    sync.Mutex
	mode  string
	set   string
	asked int
}

func (j *stubVoiceJudge) to(mode string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.mode = mode
}

func (j *stubVoiceJudge) questionSet(set string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.set = set
}

func (j *stubVoiceJudge) QuestionSet() string {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.set
}

func (j *stubVoiceJudge) Scan(_ context.Context, _ string) judge.VoiceResult {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.asked++
	res := judge.VoiceResult{Model: judge.DefaultModel, QuestionSet: j.set, Usage: judge.Usage{Requests: 1, InputTokens: 100}}
	switch j.mode {
	case "unavailable":
		res.Verdict, res.Failure, res.Err = judge.VerdictNotScanned, judge.FailureJudgeError, errors.New("judge down")
	case "flagged":
		res.Verdict, res.Score, res.Flagged = judge.VerdictFlagged, 3, []string{judge.VoiceIDOverride}
		res.Scores = map[string]int{judge.VoiceIDBeyondStyle: 0, judge.VoiceIDOverride: 3, judge.VoiceIDInsertedContent: 0, judge.VoiceIDTaskChange: 0}
	default:
		res.Verdict = judge.VerdictPass
		res.Scores = map[string]int{judge.VoiceIDBeyondStyle: 0, judge.VoiceIDOverride: 0, judge.VoiceIDInsertedContent: 0, judge.VoiceIDTaskChange: 0}
	}
	return res
}

func newVoiceEnv(t *testing.T) (*testEnv, *stubVoiceJudge) {
	t.Helper()
	j := &stubVoiceJudge{set: "sha256:voice-set-one"}
	env := newTestEnvWith(t, func(s *api.Server) { s.SetVoiceJudge(j) })
	return env, j
}

// drainVoiceReviews runs the queued reviews, as the worker does. A review
// that failed is retried later, not now, so the drain ends after its try.
func drainVoiceReviews(t *testing.T, env *testEnv) {
	t.Helper()
	w := queue.NewRiverClient(env.st, nil)
	w.SetTestOnly(true)
	env.srvObj.Voice().RegisterHandlers(w)
	w.Drain(context.Background(), "sandbox")
}

type voiceVersionBody struct {
	ID          string `json:"id"`
	Slot        string `json:"slot"`
	Review      string `json:"review"`
	Source      string `json:"source"`
	Digest      string `json:"digest"`
	Bytes       int    `json:"bytes"`
	Text        string `json:"text"`
	QuestionSet string `json:"questionSet"`
	Report      *struct {
		Verdict  string `json:"verdict"`
		Findings []struct {
			Scanner  string `json:"scanner"`
			Question string `json:"question"`
			Score    int    `json:"score"`
			Flags    bool   `json:"flags"`
		} `json:"findings"`
		AIReview struct {
			Failure string         `json:"failure"`
			Scores  map[string]int `json:"scores"`
		} `json:"aiReview"`
	} `json:"report"`
}

type voiceBody struct {
	AlwaysAttach bool              `json:"alwaysAttach"`
	QuestionSet  string            `json:"questionSet"`
	Live         *voiceVersionBody `json:"live"`
	Pending      *voiceVersionBody `json:"pending"`
	Previous     *voiceVersionBody `json:"previous"`
}

func newVoiceOwner(env *testEnv, name string) knowledgeOwner {
	h := env.register(name)
	env.verifyEmail(h)
	sess := env.login(h)
	_, tok := env.mintPAT(sess, "voice", "voice:read", "voice:write")
	return knowledgeOwner{handle: h, sess: sess, pat: caller{name: name + "-pat", pat: tok}}
}

func putVoice(t *testing.T, env *testEnv, o knowledgeOwner, text string) voiceBody {
	t.Helper()
	var v voiceBody
	env.doJSON(o.pat, http.MethodPut, "/api/v1/voice", map[string]any{"text": text, "source": "upload"}, &v, http.StatusAccepted)
	return v
}

func getVoice(t *testing.T, env *testEnv, o knowledgeOwner) voiceBody {
	t.Helper()
	var v voiceBody
	env.doJSON(o.pat, http.MethodGet, "/api/v1/voice", nil, &v, http.StatusOK)
	return v
}

// Plan §3 invariant 3: a version is live only on a clean verdict; a flag
// keeps it pending with its findings and the live one live; a judge that
// cannot answer leaves it in review, and the sweep asks again.
func TestAVoiceIsReviewedBeforeItIsLive(t *testing.T) {
	env, j := newVoiceEnv(t)
	alice := newVoiceOwner(env, "voice-alice")

	env.doJSON(alice.pat, http.MethodGet, "/api/v1/voice", nil, nil, http.StatusNotFound)
	v := putVoice(t, env, alice, voiceText(1))
	if v.Live != nil || v.Pending == nil || v.Pending.Review != "reviewing" || v.Pending.Source != "upload" || v.Pending.Text != voiceText(1) ||
		v.Pending.Digest != voice.Digest([]byte(voiceText(1))) || v.AlwaysAttach {
		t.Fatalf("after the first put: %+v %+v", v, v.Pending)
	}
	drainVoiceReviews(t, env)
	v = getVoice(t, env, alice)
	if v.Live == nil || v.Pending != nil || v.Live.Text != voiceText(1) || v.Live.Review != "passed" || v.Live.QuestionSet != "sha256:voice-set-one" ||
		v.Live.Report == nil || v.Live.Report.Verdict != "pass" {
		t.Fatalf("a clean review did not make the version live: %+v", v)
	}
	if !v.AlwaysAttach {
		t.Fatal("always-attach is on when a voice first goes live (D11)")
	}

	// The person turns always-attach off; the next version to go live
	// leaves it off.
	env.doJSON(alice.pat, http.MethodPut, "/api/v1/voice/settings", map[string]any{"alwaysAttach": false}, &v, http.StatusOK)
	env.doJSON(alice.pat, http.MethodPut, "/api/v1/voice/settings", map[string]any{}, &v, http.StatusOK)
	if v.AlwaysAttach {
		t.Fatal("a settings call without the field changed it")
	}

	// Flagged: the version stays pending with its findings; the live one stays.
	j.to("flagged")
	putVoice(t, env, alice, voiceText(2))
	drainVoiceReviews(t, env)
	v = getVoice(t, env, alice)
	if v.Live == nil || v.Live.Text != voiceText(1) || v.Pending == nil || v.Pending.Review != "flagged" || v.Pending.Report == nil ||
		v.Pending.Report.Verdict != "flagged" {
		t.Fatalf("a flagged version: %+v", v)
	}
	found := false
	for _, f := range v.Pending.Report.Findings {
		found = found || (f.Question == judge.VoiceIDOverride && f.Flags && f.Score == 3)
	}
	if !found {
		t.Fatalf("the flag's finding is not on the report: %+v", v.Pending.Report.Findings)
	}

	// Unavailable: the new version replaces the flagged one and stays in
	// review, never live, with the failure on its report.
	j.to("unavailable")
	putVoice(t, env, alice, voiceText(3))
	drainVoiceReviews(t, env)
	v = getVoice(t, env, alice)
	if v.Live == nil || v.Live.Text != voiceText(1) || v.Pending == nil || v.Pending.Text != voiceText(3) || v.Pending.Review != "reviewing" ||
		v.Pending.Report == nil || v.Pending.Report.Verdict != "incomplete" || v.Pending.Report.AIReview.Failure != judge.FailureJudgeError {
		t.Fatalf("a review the judge could not answer: %+v %+v", v.Live, v.Pending)
	}

	// The judge answers again; the sweep queues the stalled review, which
	// passes: the old live version becomes previous.
	j.to("pass")
	if n, err := env.srvObj.Voice().Sweep(context.Background(), time.Now().Add(time.Hour)); err != nil || n < 1 {
		t.Fatalf("sweep: %d %v", n, err)
	}
	drainVoiceReviews(t, env)
	v = getVoice(t, env, alice)
	if v.Live == nil || v.Live.Text != voiceText(3) || v.Previous == nil || v.Previous.Text != voiceText(1) || v.Pending != nil {
		t.Fatalf("after the sweep: %+v", v)
	}
	if v.AlwaysAttach {
		t.Fatal("always-attach came back on after the person turned it off")
	}

	// Restore under the same question set: live and previous trade places.
	env.doJSON(alice.pat, http.MethodPost, "/api/v1/voice/restore", nil, &v, http.StatusOK)
	if v.Live == nil || v.Live.Text != voiceText(1) || v.Previous == nil || v.Previous.Text != voiceText(3) {
		t.Fatalf("restore: %+v", v)
	}
	// Under another set: the previous version is pending, reviewed again.
	j.questionSet("sha256:voice-set-two")
	asked := j.asked
	env.doJSON(alice.pat, http.MethodPost, "/api/v1/voice/restore", nil, &v, http.StatusAccepted)
	if v.Pending == nil || v.Pending.Source != "restore" || v.Pending.Text != voiceText(3) || v.Live.Text != voiceText(1) {
		t.Fatalf("a restore under a new set: %+v", v)
	}
	drainVoiceReviews(t, env)
	v = getVoice(t, env, alice)
	if j.asked != asked+1 || v.Live == nil || v.Live.Text != voiceText(3) || v.Live.QuestionSet != "sha256:voice-set-two" || v.Previous.Text != voiceText(1) {
		t.Fatalf("after the restore's review: asked %d, %+v", j.asked-asked, v)
	}

	// Discard a pending version; delete the voice.
	j.to("unavailable")
	putVoice(t, env, alice, voiceText(4))
	env.doJSON(alice.pat, http.MethodDelete, "/api/v1/voice/pending", nil, &v, http.StatusOK)
	if v.Pending != nil || v.Live == nil {
		t.Fatalf("discard: %+v", v)
	}
	env.doJSON(alice.pat, http.MethodDelete, "/api/v1/voice/pending", nil, nil, http.StatusNotFound)
	env.doJSON(alice.pat, http.MethodDelete, "/api/v1/voice", nil, nil, http.StatusNoContent)
	env.doJSON(alice.pat, http.MethodGet, "/api/v1/voice", nil, nil, http.StatusNotFound)
}

// A replaced version's queued review does nothing: the version it names is
// gone, and only the newest is reviewed.
func TestOnlyTheNewestPendingVersionIsReviewed(t *testing.T) {
	env, j := newVoiceEnv(t)
	o := newVoiceOwner(env, "voice-newest")
	putVoice(t, env, o, voiceText(1))
	putVoice(t, env, o, voiceText(2))
	// One voice a person, one pending version.
	var voices, pending int
	if err := env.st.Pool().QueryRow(context.Background(), `SELECT (SELECT count(*) FROM voices WHERE user_id = $1),
		(SELECT count(*) FROM voice_versions WHERE user_id = $1)`, userID(t, env, o.handle)).Scan(&voices, &pending); err != nil || voices != 1 || pending != 1 {
		t.Fatalf("after two puts: %d voices, %d versions (%v)", voices, pending, err)
	}
	drainVoiceReviews(t, env)
	v := getVoice(t, env, o)
	if v.Live == nil || v.Live.Text != voiceText(2) || v.Previous != nil || j.asked != 1 {
		t.Fatalf("asked %d, %+v", j.asked, v)
	}
}

// Plan §3 invariant 6: a voice is sealed at rest. No column of either table
// holds its words, and the sealed bytes open only with the person's key.
func TestAVoiceIsSealedAtRest(t *testing.T) {
	env, _ := newVoiceEnv(t)
	o := newVoiceOwner(env, "voice-sealed")
	putVoice(t, env, o, voiceText(1))
	drainVoiceReviews(t, env)
	ctx := context.Background()
	for _, table := range []string{"voices", "voice_versions"} {
		var dump []byte
		if err := env.st.Pool().QueryRow(ctx, `SELECT convert_to(string_agg(t::text, ''), 'UTF8') FROM `+table+` t`).Scan(&dump); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(dump, []byte("zircon-heron-809")) {
			t.Fatalf("%s holds the voice in the clear", table)
		}
	}
	var sealed []byte
	if err := env.st.Pool().QueryRow(ctx, `SELECT v.sealed FROM voice_versions v WHERE v.user_id = $1`, userID(t, env, o.handle)).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("zircon")) || len(sealed) <= len(voiceText(1)) {
		t.Fatal("the stored version is not sealed")
	}
}

// A voice is the caller's own, and the routes ask the voice scopes of a
// token.
func TestAVoiceIsTheCallersOwnAndTheScopesHold(t *testing.T) {
	env, _ := newVoiceEnv(t)
	alice := newVoiceOwner(env, "voice-own-a")
	bob := newVoiceOwner(env, "voice-own-b")
	putVoice(t, env, alice, voiceText(1))
	drainVoiceReviews(t, env)
	env.doJSON(bob.pat, http.MethodGet, "/api/v1/voice", nil, nil, http.StatusNotFound)
	env.doJSON(bob.pat, http.MethodPost, "/api/v1/voice/restore", nil, nil, http.StatusConflict)
	env.doJSON(bob.pat, http.MethodDelete, "/api/v1/voice", nil, nil, http.StatusNotFound)
	if v := getVoice(t, env, alice); v.Live == nil {
		t.Fatal("bob's calls reached alice's voice")
	}

	_, other := env.mintPAT(alice.sess, "knowledge", "knowledge:read", "knowledge:write")
	env.doJSON(caller{name: "a-knowledge", pat: other}, http.MethodGet, "/api/v1/voice", nil, nil, http.StatusForbidden)
	_, readOnly := env.mintPAT(alice.sess, "voice-read", "voice:read")
	ro := caller{name: "a-voice-read", pat: readOnly}
	env.doJSON(ro, http.MethodGet, "/api/v1/voice", nil, nil, http.StatusOK)
	env.doJSON(ro, http.MethodPut, "/api/v1/voice", map[string]any{"text": voiceText(2), "source": "edit"}, nil, http.StatusForbidden)
	env.doJSON(ro, http.MethodDelete, "/api/v1/voice", nil, nil, http.StatusForbidden)
	// A session has the account's authority; nobody signed in has none.
	env.doJSON(alice.sess, http.MethodGet, "/api/v1/voice", nil, nil, http.StatusOK)
	env.doJSON(caller{}, http.MethodGet, "/api/v1/voice", nil, nil, http.StatusUnauthorized)
	env.doJSON(caller{}, http.MethodPut, "/api/v1/voice", map[string]any{"text": voiceText(2), "source": "edit"}, nil, http.StatusUnauthorized)
}

func TestTheVoiceRoutesRefuseWhatIsNotAVoice(t *testing.T) {
	env, _ := newVoiceEnv(t)
	o := newVoiceOwner(env, "voice-refuse")
	put := func(text, source string, status int) {
		t.Helper()
		env.doJSON(o.pat, http.MethodPut, "/api/v1/voice", map[string]any{"text": text, "source": source}, nil, status)
	}
	put(strings.Repeat("a", voice.MaxBytes+1), "edit", http.StatusRequestEntityTooLarge)
	put("  \n", "edit", http.StatusUnprocessableEntity)
	put("a\x00b", "edit", http.StatusUnprocessableEntity)
	put(voiceText(1), "build", http.StatusUnprocessableEntity)
	put(voiceText(1), "restore", http.StatusUnprocessableEntity)
	env.doJSON(o.pat, http.MethodGet, "/api/v1/voice", nil, nil, http.StatusNotFound)
	env.doJSON(o.pat, http.MethodPost, "/api/v1/voice/restore", nil, nil, http.StatusConflict)
	env.doJSON(o.pat, http.MethodDelete, "/api/v1/voice/pending", nil, nil, http.StatusNotFound)
	env.doJSON(o.pat, http.MethodPut, "/api/v1/voice/settings", map[string]any{"alwaysAttach": true}, nil, http.StatusNotFound)
	// The largest voice is taken.
	put(strings.Repeat("a", voice.MaxBytes), "edit", http.StatusAccepted)
}

// With no Jev judge the store is off: nothing could ever pass its review.
func TestWithNoVoiceJudgeTheStoreIsOff(t *testing.T) {
	env := newTestEnv(t)
	o := newVoiceOwner(env, "voice-off")
	env.doJSON(o.pat, http.MethodPut, "/api/v1/voice", map[string]any{"text": voiceText(1), "source": "edit"}, nil, http.StatusServiceUnavailable)
	env.doJSON(o.pat, http.MethodGet, "/api/v1/voice", nil, nil, http.StatusServiceUnavailable)
	var meta struct {
		Features map[string]bool `json:"features"`
	}
	env.doJSON(caller{}, http.MethodGet, "/api/v1/meta", nil, &meta, http.StatusOK)
	if meta.Features["voice"] {
		t.Fatal("meta says the voice store is on with no judge")
	}
	env2, _ := newVoiceEnv(t)
	env2.doJSON(caller{}, http.MethodGet, "/api/v1/meta", nil, &meta, http.StatusOK)
	if !meta.Features["voice"] {
		t.Fatal("meta says the voice store is off with a judge")
	}
}

// stubVoiceAdmitter admits, refuses or fails, and records what it voided.
type stubVoiceAdmitter struct {
	mu       sync.Mutex
	mode     string
	admitted []api.VoiceAdmission
	voided   []string
}

func (a *stubVoiceAdmitter) AdmitVoice(_ context.Context, adm api.VoiceAdmission) (registry.Ticket, *registry.Refusal, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch a.mode {
	case "refuse":
		return registry.Ticket{}, &registry.Refusal{Status: http.StatusPaymentRequired, Slug: "credits-exhausted", Title: "Out of credits", Detail: "No credits left."}, nil
	case "fail":
		return registry.Ticket{}, nil, errors.New("billing down")
	}
	a.admitted = append(a.admitted, adm)
	return registry.Ticket{ID: uuid.NewString()}, nil, nil
}

func (a *stubVoiceAdmitter) VoidVoice(_ context.Context, t registry.Ticket) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.voided = append(a.voided, t.ID)
	return nil
}

// The review of a version a route stores is admitted first (D8): a refusal
// or a failure stores nothing, a text that is not a voice is refused before
// it is admitted, and a Restore under the same question set, which reviews
// nothing, is not admitted at all.
func TestAVoiceReviewIsAdmittedBeforeAnythingIsStored(t *testing.T) {
	env, j := newVoiceEnv(t)
	adm := &stubVoiceAdmitter{}
	env.srvObj.SetVoiceAdmitter(adm)
	o := newVoiceOwner(env, "voice-admit")

	adm.mode = "refuse"
	env.doJSON(o.pat, http.MethodPut, "/api/v1/voice", map[string]any{"text": voiceText(1), "source": "edit"}, nil, http.StatusPaymentRequired)
	adm.mode = "fail"
	env.doJSON(o.pat, http.MethodPut, "/api/v1/voice", map[string]any{"text": voiceText(1), "source": "edit"}, nil, http.StatusServiceUnavailable)
	env.doJSON(o.pat, http.MethodGet, "/api/v1/voice", nil, nil, http.StatusNotFound)

	adm.mode = ""
	env.doJSON(o.pat, http.MethodPut, "/api/v1/voice", map[string]any{"text": "", "source": "edit"}, nil, http.StatusUnprocessableEntity)
	if len(adm.admitted) != 0 {
		t.Fatal("a text that is not a voice was admitted")
	}
	putVoice(t, env, o, voiceText(1))
	drainVoiceReviews(t, env)
	putVoice(t, env, o, voiceText(2))
	drainVoiceReviews(t, env)
	if len(adm.admitted) != 2 || adm.admitted[0].Source != voice.SourceUpload || adm.admitted[0].Bytes != len(voiceText(1)) || len(adm.voided) != 0 {
		t.Fatalf("admitted %+v, voided %v", adm.admitted, adm.voided)
	}
	env.doJSON(o.pat, http.MethodPost, "/api/v1/voice/restore", nil, nil, http.StatusOK)
	if len(adm.admitted) != 2 {
		t.Fatal("a restore that reviews nothing was admitted")
	}
	j.questionSet("sha256:voice-set-moved")
	env.doJSON(o.pat, http.MethodPost, "/api/v1/voice/restore", nil, nil, http.StatusAccepted)
	if len(adm.admitted) != 3 || adm.admitted[2].Source != voice.SourceRestore {
		t.Fatalf("a restore under a new set: %+v", adm.admitted)
	}
}

// A data clear and the account erasure take the voice with them.
func TestClearingDataOrErasingTheAccountTakesTheVoice(t *testing.T) {
	env, _ := newVoiceEnv(t)
	for i, path := range []string{"/api/v1/user/clear-data", "/api/v1/user/delete"} {
		o := newVoiceOwner(env, fmt.Sprintf("voice-clear-%d", i))
		putVoice(t, env, o, voiceText(1))
		drainVoiceReviews(t, env)
		id := userID(t, env, o.handle)
		env.doJSON(o.sess, http.MethodPost, path, nil, nil, http.StatusNoContent)
		var n int
		if err := env.st.Pool().QueryRow(context.Background(), `SELECT count(*) FROM voices WHERE user_id = $1`, id).Scan(&n); err != nil || n != 0 {
			t.Fatalf("%s: voices left: %d (%v)", path, n, err)
		}
	}
}

// userID is the account id of a handle.
func userID(t *testing.T, env *testEnv, handle string) uuid.UUID {
	t.Helper()
	u, err := env.st.Queries().GetUserByHandle(context.Background(), handle)
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}

// eagerQueue runs a job the moment it is enqueued, on another connection,
// as a worker idle on the queue does: the race dev showed on 2026-10-01,
// where a review that ran before the put committed found no version and
// left it in review.
type eagerQueue struct {
	handlers map[string]queue.Handler
	ran      int
}

func (q *eagerQueue) Register(kind string, h queue.Handler) { q.handlers[kind] = h }
func (q *eagerQueue) Work(context.Context, ...string) error { return nil }
func (q *eagerQueue) Enqueue(ctx context.Context, kind, _ string, args any, _ ...queue.EnqueueOption) (uuid.UUID, error) {
	raw, err := json.Marshal(args)
	if err != nil {
		return uuid.Nil, err
	}
	q.ran++
	return uuid.New(), q.handlers[kind](ctx, queue.Job{Kind: kind, Args: raw, Attempt: 1})
}

// A review is queued only once the version it reads has committed, so a
// worker that takes it at once finds it.
func TestAReviewTakenAtOnceFindsItsVersion(t *testing.T) {
	env, j := newVoiceEnv(t)
	o := newVoiceOwner(env, "voice-eager")
	bundle, err := ruleset.Load()
	if err != nil {
		t.Fatal(err)
	}
	q := &eagerQueue{handlers: map[string]queue.Handler{}}
	svc := voice.NewService(voice.Deps{Store: env.st, Jobs: q, Judge: j,
		Rules:   scan.NewOrchestrator(bundle, scan.StaticProvider{}, nil),
		Wrapper: func() knowledge.KeyWrapper { return env.srvObj.Knowledge().Wrapper() }})
	svc.RegisterHandlers(q)
	st, err := svc.Put(context.Background(), userID(t, env, o.handle), []byte(voiceText(1)), voice.SourceUpload)
	if err != nil {
		t.Fatal(err)
	}
	if q.ran != 1 {
		t.Fatalf("the review ran %d times", q.ran)
	}
	v := getVoice(t, env, o)
	if v.Live == nil || v.Live.Text != voiceText(1) || v.Pending != nil {
		t.Fatalf("a review taken at once did not find its version: put answered %+v, now %+v %+v", st.Pending, v.Live, v.Pending)
	}
}
