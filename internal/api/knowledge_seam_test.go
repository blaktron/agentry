package api_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"
	"testing"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/knowledge"
	"github.com/blaktron/agentry/pkg/packseal"
)

// The key-wrapper seam (agentry#593, plan knowledge.md §4.4): an extension's
// KeyWrapper replaces the deployment key and nothing else — the store, the
// routes, the scan and the erasure are the core's — and with no extension
// the core wraps under its own knowledge sealing key.

// probeWrapper keeps data keys in memory by a random handle, for its owner
// alone, and records what it destroyed.
type probeWrapper struct {
	mu        sync.Mutex
	keys      map[string][]byte
	owners    map[string]knowledge.Owner
	destroyed []knowledge.Owner
}

func newProbeWrapper() *probeWrapper {
	return &probeWrapper{keys: map[string][]byte{}, owners: map[string]knowledge.Owner{}}
}

func (p *probeWrapper) Wrap(_ context.Context, o knowledge.Owner, dataKey []byte) (knowledge.WrappedKey, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	h := make([]byte, 16)
	_, _ = rand.Read(h)
	id := hex.EncodeToString(h)
	p.keys[id] = bytes.Clone(dataKey)
	p.owners[id] = o
	return knowledge.WrappedKey{Kind: "probe", Recipient: "probe:" + o.String(), Blob: []byte(id)}, nil
}

func (p *probeWrapper) Unwrap(_ context.Context, o knowledge.Owner, w knowledge.WrappedKey) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if w.Kind != "probe" || p.owners[string(w.Blob)] != o {
		return nil, knowledge.ErrNotOwner
	}
	return bytes.Clone(p.keys[string(w.Blob)]), nil
}

func (p *probeWrapper) Destroy(_ context.Context, o knowledge.Owner) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for id, owner := range p.owners {
		if owner == o {
			delete(p.owners, id)
			delete(p.keys, id)
		}
	}
	p.destroyed = append(p.destroyed, o)
	return nil
}

func TestKnowledgeKeyWrapperSeam(t *testing.T) {
	probe := newProbeWrapper()
	env := newTestEnvWith(t, func(s *api.Server) { s.SetKeyWrapper(probe) })
	o := newKnowledgeOwner(env, "kn-seam")

	p, dataKey, _, tree := putPack(t, env, o, "seamed", knowledgeFiles())
	if p.WrappedKey.Kind != "probe" {
		t.Fatalf("the pack's key is wrapped by %q, not the extension's wrapper", p.WrappedKey.Kind)
	}
	drainKnowledgeScans(t, env)
	var got knowledgePackBody
	env.doJSON(o.pat, http.MethodGet, "/api/v1/knowledge/packs/"+p.ID, nil, &got, http.StatusOK)
	if got.State != knowledge.StateReady {
		t.Fatalf("the scan under the extension's wrapper left the pack %q", got.State)
	}
	if st, _, body := env.raw(o.pat, http.MethodGet, "/api/v1/knowledge/packs/"+p.ID+"/export", nil); st != http.StatusOK || !bytes.Equal(body, tree) {
		t.Fatalf("export under the extension's wrapper: %d", st)
	}
	var dk struct {
		Key []byte `json:"key"`
	}
	env.doJSON(o.pat, http.MethodPost, "/api/v1/knowledge/keys/unwrap", p.WrappedKey, &dk, http.StatusOK)
	if !bytes.Equal(dk.Key, dataKey) {
		t.Fatal("unwrap through the extension's wrapper")
	}

	// The data clear is the core's, and destroys through the wrapper.
	env.doJSON(o.sess, http.MethodPost, "/api/v1/user/clear-data", nil, nil, http.StatusNoContent)
	probe.mu.Lock()
	destroyed := append([]knowledge.Owner(nil), probe.destroyed...)
	probe.mu.Unlock()
	if len(destroyed) != 1 || destroyed[0].Kind != knowledge.OwnerUser {
		t.Fatalf("the data clear destroyed %v through the extension's wrapper", destroyed)
	}
}

// TestCoreKnowledgeWrapsUnderItsOwnKey: with no extension the core's
// wrapper is the deployment key's, and the store needs nothing else.
func TestCoreKnowledgeWrapsUnderItsOwnKey(t *testing.T) {
	env := newTestEnv(t)
	o := newKnowledgeOwner(env, "kn-core")
	dataKey, _ := packseal.NewKey()
	var wk knowledgeKey
	env.doJSON(o.pat, http.MethodPost, "/api/v1/knowledge/keys/wrap", map[string]any{"key": dataKey}, &wk, http.StatusOK)
	if wk.Kind != knowledge.DeploymentKind || len(wk.Recipient) < len("deployment:") || wk.Recipient[:len("deployment:")] != "deployment:" || bytes.Contains(wk.Key, dataKey) {
		t.Fatalf("the core's wrapped key = %+v", wk)
	}
}
