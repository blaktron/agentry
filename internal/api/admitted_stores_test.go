package api_test

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/entitlements"
)

// admittedStore answers the kind recorded for an admission ticket in
// admitted_stores, or "" when the ticket has no row.
func admittedStore(t *testing.T, env *testEnv, ticket string) string {
	t.Helper()
	var kind string
	err := env.st.Pool().QueryRow(context.Background(), `SELECT coalesce((SELECT kind FROM admitted_stores WHERE ticket = $1), '')`, ticket).Scan(&kind)
	if err != nil {
		t.Fatal(err)
	}
	return kind
}

// TestAStoredAdmissionIsRecordedWithWhatItPaidFor: the ticket of an
// upload or a voice review the core stored has a row in admitted_stores,
// written with the store; a ticket the core then refused has none, so an
// extension can tell a charge with nothing stored behind it without
// relying on the void.
func TestAStoredAdmissionIsRecordedWithWhatItPaidFor(t *testing.T) {
	t.Run("knowledge", func(t *testing.T) {
		env := newTestEnvCfg(t, func(c *config.Config) { c.Limits.KnowledgeBytesPerAccount = 400 })
		adm := &stubKnowledgeAdmitter{}
		env.srvObj.SetKnowledgeAdmitter(adm)
		o := newKnowledgeOwner(env, "kn-recorded")
		a, aKey := newPack(t, env, o, "first")
		sealedA, _, _ := sealedPack(t, sizedPack(200, 'a'), aKey)
		if st, _, b := env.raw(o.pat, http.MethodPut, "/api/v1/knowledge/packs/"+a+"/tree", sealedA); st != http.StatusAccepted {
			t.Fatalf("200 of 400: %d %s", st, b)
		}
		// A second upload that fits when admitted and loses the race to the
		// cap under the lock: refused, voided, and not recorded.
		b, bKey := newPack(t, env, o, "second")
		sealedB, _, _ := sealedPack(t, sizedPack(150, 'b'), bKey)
		adm.onAdmit = func() {
			if _, err := env.st.Pool().Exec(context.Background(), `UPDATE knowledge_packs SET bytes = bytes + 100 WHERE id = $1`, a); err != nil {
				t.Error(err)
			}
		}
		if st, _, body := env.raw(o.pat, http.MethodPut, "/api/v1/knowledge/packs/"+b+"/tree", sealedB); st != http.StatusRequestEntityTooLarge {
			t.Fatalf("a race lost to the allocation: %d %s", st, body)
		}
		if len(adm.tickets) != 2 {
			t.Fatalf("tickets %v, want two admissions", adm.tickets)
		}
		if k := admittedStore(t, env, adm.tickets[0]); k != "knowledge" {
			t.Errorf("the stored upload's ticket: %q, want knowledge", k)
		}
		if k := admittedStore(t, env, adm.tickets[1]); k != "" {
			t.Errorf("the refused upload's ticket was recorded as %q", k)
		}
	})

	t.Run("voice", func(t *testing.T) {
		env, j := newVoiceEnv(t)
		adm := &stubVoiceAdmitter{}
		env.srvObj.SetVoiceAdmitter(adm)
		o := newVoiceOwner(env, "voice-recorded")
		putVoice(t, env, o, voiceText(1))
		drainVoiceReviews(t, env)
		putVoice(t, env, o, voiceText(2))
		drainVoiceReviews(t, env)
		j.questionSet("sha256:voice-set-moved")
		env.doJSON(o.pat, http.MethodPost, "/api/v1/voice/restore", nil, nil, http.StatusAccepted)
		if len(adm.tickets) != 3 {
			t.Fatalf("tickets %v, want two puts and a reviewed restore", adm.tickets)
		}
		for i, ticket := range adm.tickets {
			if k := admittedStore(t, env, ticket); k != "voice" {
				t.Errorf("ticket %d: %q, want voice", i, k)
			}
		}
	})
}

// panickingResolver answers as its Resolver does, except that its at-th
// Features call from arming panics: a fault inside the upload's
// transaction, after the admission.
type panickingResolver struct {
	entitlements.Resolver
	armed atomic.Bool
	calls atomic.Int32
	at    int32
}

func (r *panickingResolver) Features(ctx context.Context, s entitlements.Subject) (entitlements.Features, error) {
	if r.armed.Load() && r.calls.Add(1) == r.at {
		panic("entitlements: a fault after the admission")
	}
	return r.Resolver.Features(ctx, s)
}

// TestAPanicAfterAKnowledgeAdmissionIsReleasedAsNotStored: a store that
// panics after the admission (here, inside the transaction, at the lock
// on the allocation) is released as not stored, so its ticket is voided,
// and nothing is recorded for it.
func TestAPanicAfterAKnowledgeAdmissionIsReleasedAsNotStored(t *testing.T) {
	env := newTestEnvCfg(t, func(c *config.Config) { c.Limits.KnowledgeBytesPerAccount = 4000 })
	adm := &stubKnowledgeAdmitter{}
	env.srvObj.SetKnowledgeAdmitter(adm)
	// The pre-check resolves the pool once before the admission, and the
	// lock resolves it again inside the transaction: the second call panics.
	r := &panickingResolver{Resolver: entitlements.NewConfigResolver(config.Limits{KnowledgeBytesPerAccount: 4000}), at: 2}
	env.srvObj.SetEntitlements(r)
	o := newKnowledgeOwner(env, "kn-panic")
	id, key := newPack(t, env, o, "panics")
	sealed, _, _ := sealedPack(t, sizedPack(200, 'p'), key)
	r.armed.Store(true)
	if st, _, body := env.raw(o.pat, http.MethodPut, "/api/v1/knowledge/packs/"+id+"/tree", sealed); st != http.StatusInternalServerError {
		t.Fatalf("an upload whose store panicked: %d %s, want 500", st, body)
	}
	admitted, voided := adm.counts()
	if admitted != 1 || voided != 1 || adm.voided[0] != adm.tickets[0] {
		t.Fatalf("admitted %d, voided %v of %v; want the panicked upload's ticket voided", admitted, adm.voided, adm.tickets)
	}
	if k := admittedStore(t, env, adm.tickets[0]); k != "" {
		t.Errorf("the panicked upload's ticket was recorded as %q", k)
	}
	if n := knowledgeObjects(t, env, id); n != 0 {
		t.Errorf("the panicked upload stored %d objects", n)
	}
}
