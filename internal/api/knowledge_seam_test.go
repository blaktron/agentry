package api_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/knowledge"
	"github.com/blaktron/agentry/pkg/packseal"
)

// The key-wrapper seam: an extension's
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

	// A wrapper that answers a key of the wrong size has not opened it: the
	// owner is told it does not open, and no pack is made under it.
	probe.mu.Lock()
	probe.keys[string(p.WrappedKey.Key)] = dataKey[:16]
	probe.mu.Unlock()
	if st, _, body := env.raw(o.pat, http.MethodPost, "/api/v1/knowledge/keys/unwrap", mustJSON(t, p.WrappedKey)); st != http.StatusNotFound || problemTypeOf(body) != "knowledge-key-not-found" {
		t.Fatalf("unwrap of a key the wrapper answered short: %d %s, want 404 knowledge-key-not-found", st, body)
	}
	if st, _, body := env.raw(o.pat, http.MethodPost, "/api/v1/knowledge/packs", mustJSON(t, map[string]any{"name": "short-key", "wrappedKey": p.WrappedKey})); st != http.StatusNotFound {
		t.Fatalf("a pack made under a key the wrapper answered short: %d %s, want 404", st, body)
	}
	probe.mu.Lock()
	probe.keys[string(p.WrappedKey.Key)] = dataKey
	probe.mu.Unlock()

	// The data clear is the core's, and destroys through the wrapper.
	env.doJSON(o.sess, http.MethodPost, "/api/v1/user/clear-data", nil, nil, http.StatusNoContent)
	probe.mu.Lock()
	destroyed := append([]knowledge.Owner(nil), probe.destroyed...)
	probe.mu.Unlock()
	if len(destroyed) != 1 || destroyed[0].Kind != knowledge.OwnerUser {
		t.Fatalf("the data clear destroyed %v through the extension's wrapper", destroyed)
	}
}

// fixedSalts gives every owner the same salt, so that nothing but the
// wrapper's own binding of a wrapped key to its owner tells owners apart.
type fixedSalts struct{}

func (fixedSalts) Salt(context.Context, knowledge.Owner, bool) ([]byte, error) {
	return bytes.Repeat([]byte{7}, knowledge.SaltSize), nil
}

func (fixedSalts) DeleteSalt(context.Context, knowledge.Owner) error { return nil }

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

	// A wrapped key is bound to its owner beyond the owner's salt: even
	// where two owners share a salt, one's wrapped key does not open for the
	// other.
	w, err := knowledge.NewDeploymentWrapper(bytes.Repeat([]byte{9}, 32), fixedSalts{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	first, second := knowledge.User(uuid.New()), knowledge.User(uuid.New())
	wrapped, err := w.Wrap(ctx, first, dataKey)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := w.Unwrap(ctx, first, wrapped); err != nil || !bytes.Equal(got, dataKey) {
		t.Fatalf("the owner's wrapped key did not open: %v", err)
	}
	if _, err := w.Unwrap(ctx, second, wrapped); !errors.Is(err, knowledge.ErrNotOwner) {
		t.Fatalf("a wrapped key opened for an owner it was not wrapped for: %v", err)
	}
}

// TestKnowledgeStoreIsOffWithoutAKeyWrapper: a deployment with no knowledge
// sealing key and no extension that wraps keys keeps no packs: every route that needs the store says so, and stores nothing.
func TestKnowledgeStoreIsOffWithoutAKeyWrapper(t *testing.T) {
	env := newTestEnv(t)
	o := newKnowledgeOwner(env, "kn-off")
	env.srvObj.Knowledge().SetWrapper(nil)
	if env.srvObj.Knowledge().Configured() {
		t.Fatal("the store is on with no key wrapper")
	}
	dataKey, _ := packseal.NewKey()
	pack := "/api/v1/knowledge/packs/00000000-0000-4000-8000-000000000001"
	for _, r := range []struct {
		name, method, path string
		body               []byte
	}{
		{"wrap a key", http.MethodPost, "/api/v1/knowledge/keys/wrap", mustJSON(t, map[string]any{"key": dataKey})},
		{"unwrap a key", http.MethodPost, "/api/v1/knowledge/keys/unwrap", mustJSON(t, knowledgeKey{Kind: knowledge.DeploymentKind, Recipient: "deployment:0000000000000000", Key: dataKey})},
		{"create a pack", http.MethodPost, "/api/v1/knowledge/packs", mustJSON(t, map[string]any{"name": "off", "wrappedKey": knowledgeKey{Kind: knowledge.DeploymentKind, Key: dataKey}})},
		{"list packs", http.MethodGet, "/api/v1/knowledge/packs", nil},
		{"read the usage", http.MethodGet, "/api/v1/knowledge/usage", nil},
		{"read a pack", http.MethodGet, pack, nil},
		{"upload a tree", http.MethodPut, pack + "/tree", []byte("a sealed tree")},
	} {
		st, _, body := env.raw(o.pat, r.method, r.path, r.body)
		if st != http.StatusServiceUnavailable || problemTypeOf(body) != "knowledge-unconfigured" {
			t.Errorf("%s: %d %s, want 503 knowledge-unconfigured", r.name, st, body)
		}
	}
}
