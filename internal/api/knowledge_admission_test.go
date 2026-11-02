package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/knowledge"
	"github.com/blaktron/agentry/internal/queue"
	"github.com/blaktron/agentry/internal/registry"
)

// stubKnowledgeAdmitter admits, refuses or fails, and records what it
// was asked, admitted and voided. onAdmit, when set, runs as an admission
// is asked, before it answers.
type stubKnowledgeAdmitter struct {
	mu       sync.Mutex
	mode     string
	asked    int
	admitted []api.KnowledgeAdmission
	tickets  []string
	voided   []string
	onAdmit  func()
	// hangup, when set, makes an admission announce itself on entered and
	// wait until the request it answers has been given up.
	hangup  bool
	entered chan struct{}
	// voidErr receives the state of the context each void was made with.
	voidErr chan error
}

func (a *stubKnowledgeAdmitter) AdmitKnowledge(ctx context.Context, adm api.KnowledgeAdmission) (registry.Ticket, *registry.Refusal, error) {
	a.mu.Lock()
	hangup, entered := a.hangup, a.entered
	a.mu.Unlock()
	if hangup {
		entered <- struct{}{}
		<-ctx.Done()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.asked++
	if a.onAdmit != nil {
		a.onAdmit()
	}
	switch a.mode {
	case "refuse":
		return registry.Ticket{}, &registry.Refusal{Status: http.StatusPaymentRequired, Slug: "credits-exhausted", Title: "Out of credits", Detail: "No credits left."}, nil
	case "fail":
		return registry.Ticket{}, nil, errors.New("billing down")
	}
	a.admitted = append(a.admitted, adm)
	id := uuid.NewString()
	a.tickets = append(a.tickets, id)
	return registry.Ticket{ID: id}, nil, nil
}

func (a *stubKnowledgeAdmitter) VoidKnowledge(ctx context.Context, t registry.Ticket) error {
	a.mu.Lock()
	a.voided = append(a.voided, t.ID)
	voidErr := a.voidErr
	a.mu.Unlock()
	if voidErr != nil {
		voidErr <- ctx.Err()
	}
	return nil
}

func (a *stubKnowledgeAdmitter) counts() (admitted, voided int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.admitted), len(a.voided)
}

func knowledgeObjects(t *testing.T, env *testEnv, packID string) int {
	t.Helper()
	var n int
	if err := env.st.Pool().QueryRow(context.Background(), `SELECT count(*) FROM knowledge_objects WHERE pack_id = $1`, packID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestAKnowledgeUploadIsAdmittedBeforeAnythingIsStored: the scan an upload
// queues is admitted once, after the core has read the tree and before it
// is stored. A refusal or a failure stores nothing; an upload the core
// refuses is never asked about; the tree the pack already holds is not
// asked about again; and with no extension nothing is asked at all.
func TestAKnowledgeUploadIsAdmittedBeforeAnythingIsStored(t *testing.T) {
	env := newTestEnv(t)
	adm := &stubKnowledgeAdmitter{}
	env.srvObj.SetKnowledgeAdmitter(adm)
	o := newKnowledgeOwner(env, "kn-admit")
	id, key := newPack(t, env, o, "admitted")
	put := func(body []byte) (int, string) {
		st, _, b := env.raw(o.pat, http.MethodPut, "/api/v1/knowledge/packs/"+id+"/tree", body)
		return st, problemTypeOf(b)
	}
	good, _, _ := sealedPack(t, knowledgeFiles(), key)

	adm.mode = "refuse"
	if st, typ := put(good); st != http.StatusPaymentRequired || typ != "credits-exhausted" {
		t.Fatalf("a refused upload: %d %s, want 402 credits-exhausted", st, typ)
	}
	adm.mode = "fail"
	if st, typ := put(good); st != http.StatusServiceUnavailable || typ != "admission-unavailable" {
		t.Fatalf("an admission that failed: %d %s, want 503", st, typ)
	}
	if n := knowledgeObjects(t, env, id); n != 0 {
		t.Fatalf("a refused upload stored %d objects", n)
	}

	adm.mode = ""
	// A body the core refuses is never asked about.
	if st, _ := put([]byte("not a sealed tree")); st != http.StatusUnprocessableEntity {
		t.Fatalf("an unreadable tree: %d", st)
	}
	if n, _ := adm.counts(); n != 0 {
		t.Fatalf("an upload the core refused was admitted %d times", n)
	}

	if st, typ := put(good); st != http.StatusAccepted {
		t.Fatalf("an admitted upload: %d %s", st, typ)
	}
	admitted, voided := adm.counts()
	if admitted != 1 || voided != 0 {
		t.Fatalf("admitted %d, voided %d; want one admission kept", admitted, voided)
	}
	a := adm.admitted[0]
	var fileBytes int64
	for _, f := range knowledgeFiles() {
		fileBytes += int64(len(f.Content))
	}
	if a.User == uuid.Nil || a.OwnerKind != "user" || a.OwnerID != a.User || a.Pack.String() != id || a.Bytes != fileBytes || a.Files != len(knowledgeFiles()) {
		t.Fatalf("admission = %+v, want the tree's %d bytes in %d files", a, fileBytes, len(knowledgeFiles()))
	}
	if n := knowledgeObjects(t, env, id); n != 1 {
		t.Fatalf("the admitted upload stored %d objects", n)
	}
	// The ticket of what was stored is recorded with it.
	if n := admittedStores(t, env, adm.tickets[0]); n != 1 {
		t.Fatalf("the stored upload's ticket is recorded %d times, want once", n)
	}

	// The same tree again, while it is scanned and after: nothing is
	// asked, nothing is stored again.
	if st, _ := put(good); st != http.StatusAccepted {
		t.Fatalf("the same tree while scanning: %d", st)
	}
	drainKnowledgeScans(t, env)
	if st, _ := put(good); st != http.StatusAccepted {
		t.Fatalf("the same tree after its scan: %d", st)
	}
	if admitted, _ := adm.counts(); admitted != 1 {
		t.Fatalf("the tree the pack holds was admitted again: %d admissions", admitted)
	}

	// A new tree is asked about again.
	other, _, _ := sealedPack(t, sizedPack(64, 'n'), key)
	if st, _ := put(other); st != http.StatusAccepted {
		t.Fatalf("a new tree: %d", st)
	}
	if admitted, _ := adm.counts(); admitted != 2 {
		t.Fatalf("a new tree: %d admissions, want 2", admitted)
	}

	// A tree whose scan failed is scanned again when it is uploaded again,
	// without being asked about: the failure was the registry's.
	var object string
	if err := env.st.Pool().QueryRow(context.Background(), `SELECT object_key FROM knowledge_packs WHERE id = $1`, id).Scan(&object); err != nil {
		t.Fatal(err)
	}
	if err := env.srvObj.Blobs().Delete(context.Background(), object); err != nil {
		t.Fatal(err)
	}
	jobs := &handlerQueue{h: map[string]queue.Handler{}}
	env.srvObj.Knowledge().RegisterHandlers(jobs)
	args, _ := json.Marshal(knowledge.ScanArgs{Pack: uuid.MustParse(id), Object: object})
	_ = jobs.h[knowledge.JobScan](context.Background(), queue.Job{Kind: knowledge.JobScan, Args: args, Attempt: 3})
	var failed knowledgePackBody
	env.doJSON(o.pat, http.MethodGet, "/api/v1/knowledge/packs/"+id, nil, &failed, http.StatusOK)
	if failed.State != knowledge.StateFailed {
		t.Fatalf("the pack whose tree could not be read is %q, want failed", failed.State)
	}
	st, _, body := env.raw(o.pat, http.MethodPut, "/api/v1/knowledge/packs/"+id+"/tree", other)
	var again knowledgePackBody
	if err := json.Unmarshal(body, &again); err != nil || st != http.StatusAccepted || again.State != knowledge.StateScanning {
		t.Fatalf("the failed tree uploaded again: %d %s, want accepted and scanning", st, body)
	}
	if admitted, _ := adm.counts(); admitted != 2 {
		t.Fatalf("a failed tree uploaded again was admitted again: %d admissions", admitted)
	}
	drainKnowledgeScans(t, env)
	env.doJSON(o.pat, http.MethodGet, "/api/v1/knowledge/packs/"+id, nil, &again, http.StatusOK)
	if again.State != knowledge.StateReady {
		t.Fatalf("the failed tree uploaded again ends %q, want ready", again.State)
	}
}

// admittedStores is how often the ticket is recorded as the ticket of a
// stored upload.
func admittedStores(t *testing.T, env *testEnv, ticket string) int {
	t.Helper()
	var n int
	if err := env.st.Pool().QueryRow(context.Background(), `SELECT count(*) FROM admitted_stores WHERE ticket = $1 AND kind = 'knowledge'`, ticket).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestAnUploadTheAllocationRefusesIsVoided: an upload admitted and then
// refused by the core under the pack's lock (the account's allocation, filled
// by another upload between the admission and the lock) is voided, so
// nothing is charged for it.
func TestAnUploadTheAllocationRefusesIsVoided(t *testing.T) {
	blobs := t.TempDir()
	env := newTestEnvCfg(t, func(c *config.Config) {
		c.Limits.KnowledgeBytesPerAccount = 400
		c.Storage.LocalDir = blobs
	})
	adm := &stubKnowledgeAdmitter{}
	env.srvObj.SetKnowledgeAdmitter(adm)
	o := newKnowledgeOwner(env, "kn-avoid")
	a, aKey := newPack(t, env, o, "first")
	sealedA, _, _ := sealedPack(t, sizedPack(200, 'a'), aKey)
	if st, _, b := env.raw(o.pat, http.MethodPut, "/api/v1/knowledge/packs/"+a+"/tree", sealedA); st != http.StatusAccepted {
		t.Fatalf("200 of 400: %d %s", st, b)
	}
	b, bKey := newPack(t, env, o, "second")
	sealedB, _, _ := sealedPack(t, sizedPack(150, 'b'), bKey)
	// 150 beside 200 fits when it is admitted; the first pack grows by 100
	// before the second takes the lock, so the reservation refuses it.
	adm.onAdmit = func() {
		if _, err := env.st.Pool().Exec(context.Background(), `UPDATE knowledge_packs SET bytes = bytes + 100 WHERE id = $1`, a); err != nil {
			t.Error(err)
		}
	}
	heldBefore := blobFiles(t, blobs)
	st, _, body := env.raw(o.pat, http.MethodPut, "/api/v1/knowledge/packs/"+b+"/tree", sealedB)
	if st != http.StatusRequestEntityTooLarge || problemTypeOf(body) != "knowledge-allocation" {
		t.Fatalf("a race lost to the allocation: %d %s", st, body)
	}
	if n := blobFiles(t, blobs); n != heldBefore {
		t.Fatalf("the refused upload left %d sealed blobs, want the %d held before", n, heldBefore)
	}
	admitted, voided := adm.counts()
	if admitted != 2 || voided != 1 || adm.voided[0] != adm.tickets[1] {
		t.Fatalf("admitted %d, voided %v of %v; want the refused upload's ticket voided", admitted, adm.voided, adm.tickets)
	}
	if n := knowledgeObjects(t, env, b); n != 0 {
		t.Fatalf("the refused upload stored %d objects", n)
	}
	// A client that gives up while its upload is being admitted does not
	// leave the ticket charged: the void is made whether or not the request
	// is still there.
	gone, giveUp := context.WithCancel(context.Background())
	defer giveUp()
	adm.mu.Lock()
	adm.hangup, adm.entered, adm.voidErr = true, make(chan struct{}), make(chan error, 1)
	entered, voidErr := adm.entered, adm.voidErr
	adm.mu.Unlock()
	cKey, cID := bKey, b
	small, _, _ := sealedPack(t, sizedPack(64, 'z'), cKey)
	req, err := http.NewRequestWithContext(gone, http.MethodPut, env.srv.URL+"/api/v1/knowledge/packs/"+cID+"/tree", bytes.NewReader(small))
	if err != nil {
		t.Fatal(err)
	}
	env.authenticate(req, o.pat)
	sent := make(chan struct{})
	go func() {
		defer close(sent)
		if res, err := env.srv.Client().Do(req); err == nil {
			_ = res.Body.Close()
		}
	}()
	<-entered
	giveUp()
	<-sent
	if err := <-voidErr; err != nil {
		t.Fatalf("the ticket of an upload given up was voided on a context that was already cancelled: %v", err)
	}
	// Only what was stored is recorded as stored.
	if first, second := admittedStores(t, env, adm.tickets[0]), admittedStores(t, env, adm.tickets[1]); first != 1 || second != 0 {
		t.Fatalf("recorded as stored: the first upload's ticket %d times, the refused one's %d; want 1 and 0", first, second)
	}
}

// TestAnUploadPastTheAllocationIsRefusedBeforeItIsAdmitted: an upload the
// allocation refuses is answered 413 knowledge-allocation before the
// admission is asked, so a payer who could not pay either is told what
// would still refuse it once they could, and nothing is charged.
func TestAnUploadPastTheAllocationIsRefusedBeforeItIsAdmitted(t *testing.T) {
	env := newTestEnvCfg(t, func(c *config.Config) { c.Limits.KnowledgeBytesPerAccount = 400 })
	adm := &stubKnowledgeAdmitter{}
	env.srvObj.SetKnowledgeAdmitter(adm)
	o := newKnowledgeOwner(env, "kn-precheck")
	a, aKey := newPack(t, env, o, "first")
	sealedA, _, _ := sealedPack(t, sizedPack(200, 'a'), aKey)
	if st, _, b := env.raw(o.pat, http.MethodPut, "/api/v1/knowledge/packs/"+a+"/tree", sealedA); st != http.StatusAccepted {
		t.Fatalf("200 of 400: %d %s", st, b)
	}
	adm.mode = "refuse" // a payer with no credits
	b, bKey := newPack(t, env, o, "second")
	sealedB, _, _ := sealedPack(t, sizedPack(250, 'b'), bKey)
	st, _, body := env.raw(o.pat, http.MethodPut, "/api/v1/knowledge/packs/"+b+"/tree", sealedB)
	if st != http.StatusRequestEntityTooLarge || problemTypeOf(body) != "knowledge-allocation" {
		t.Fatalf("past the allocation and unpaid: %d %s, want 413 knowledge-allocation", st, body)
	}
	adm.mu.Lock()
	asked := adm.asked
	adm.mu.Unlock()
	if asked != 1 {
		t.Fatalf("the admission was asked %d times, want once (the first upload only)", asked)
	}
	// A tree that fits is still asked about, and refused for credits.
	small, _, _ := sealedPack(t, sizedPack(64, 'c'), bKey)
	if st, _, body := env.raw(o.pat, http.MethodPut, "/api/v1/knowledge/packs/"+b+"/tree", small); st != http.StatusPaymentRequired {
		t.Fatalf("a tree that fits, unpaid: %d %s, want 402", st, body)
	}
}
