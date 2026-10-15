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
// admitted and voided.
type stubKnowledgeAdmitter struct {
	mu       sync.Mutex
	mode     string
	admitted []api.KnowledgeAdmission
	tickets  []string
	voided   []string
}

func (a *stubKnowledgeAdmitter) AdmitKnowledge(_ context.Context, adm api.KnowledgeAdmission) (registry.Ticket, *registry.Refusal, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
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
// refused by the core under the pack's lock (the account's allocation) is
// voided, so nothing is charged for it.
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
	sealedB, _, _ := sealedPack(t, sizedPack(250, 'b'), bKey)
	if st, _, body := env.raw(o.pat, http.MethodPut, "/api/v1/knowledge/packs/"+b+"/tree", sealedB); st == http.StatusAccepted {
		t.Fatalf("past the allocation: %d %s", st, body)
	}
	admitted, voided := adm.counts()
	if admitted != 2 || voided != 1 || adm.voided[0] != adm.tickets[1] {
		t.Fatalf("admitted %d, voided %v of %v; want the refused upload's ticket voided", admitted, adm.voided, adm.tickets)
	}
}
