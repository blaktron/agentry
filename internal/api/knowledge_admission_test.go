package api_test

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
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
}

func (a *stubKnowledgeAdmitter) AdmitKnowledge(_ context.Context, adm api.KnowledgeAdmission) (registry.Ticket, *registry.Refusal, error) {
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

func (a *stubKnowledgeAdmitter) VoidKnowledge(_ context.Context, t registry.Ticket) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.voided = append(a.voided, t.ID)
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
	if a.User == uuid.Nil || a.OwnerKind != "user" || a.OwnerID != a.User || a.Pack.String() != id || a.Bytes <= 0 || a.Files != len(knowledgeFiles()) {
		t.Fatalf("admission = %+v", a)
	}
	if n := knowledgeObjects(t, env, id); n != 1 {
		t.Fatalf("the admitted upload stored %d objects", n)
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
}

// TestAnUploadTheAllocationRefusesIsVoided: an upload admitted and then
// refused by the core under the pack's lock (the account's allocation, filled
// by another upload between the admission and the lock) is voided, so
// nothing is charged for it.
func TestAnUploadTheAllocationRefusesIsVoided(t *testing.T) {
	env := newTestEnvCfg(t, func(c *config.Config) { c.Limits.KnowledgeBytesPerAccount = 400 })
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
	st, _, body := env.raw(o.pat, http.MethodPut, "/api/v1/knowledge/packs/"+b+"/tree", sealedB)
	if st != http.StatusRequestEntityTooLarge || problemTypeOf(body) != "knowledge-allocation" {
		t.Fatalf("a race lost to the allocation: %d %s", st, body)
	}
	admitted, voided := adm.counts()
	if admitted != 2 || voided != 1 || adm.voided[0] != adm.tickets[1] {
		t.Fatalf("admitted %d, voided %v of %v; want the refused upload's ticket voided", admitted, adm.voided, adm.tickets)
	}
	if n := knowledgeObjects(t, env, b); n != 0 {
		t.Fatalf("the refused upload stored %d objects", n)
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
