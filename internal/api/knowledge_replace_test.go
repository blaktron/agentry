package api_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/knowledge"
	"github.com/blaktron/agentry/internal/scan"
	"github.com/blaktron/agentry/pkg/packseal"
)

// What an extension may do with the store (pkg/extension's Knowledge
// seam): make a pack under a key the registry makes, read its
// tree, and put a tree back — sealed under the pack's own key, through the
// upload's own path — only while the pack still holds the tree it read.

// TestKnowledgeReplaceThroughTheSeam: a pack made by the registry, a tree
// put back, the pack scanning with the registry's counts and its scan
// queued, the tree read back decrypted and sealed under the pack's key as
// an owner's download opens it; an unchanged tree stores nothing; a stale
// replace, another owner and a scanning pack are refused.
func TestKnowledgeReplaceThroughTheSeam(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	svc := env.srvObj.Knowledge()
	o := newKnowledgeOwner(env, "kn-seam")
	owner := ownerOf(t, env, o)

	p, err := svc.CreateSealed(ctx, owner, "built")
	if err != nil {
		t.Fatal(err)
	}
	if p.State != knowledge.StateEmpty || p.Digest != "" {
		t.Fatalf("a new pack is %+v, want empty with no digest", p)
	}
	if _, err := svc.CreateSealed(ctx, owner, "built"); !errors.Is(err, knowledge.ErrNameTaken) {
		t.Fatalf("a second pack of the name: %v", err)
	}
	if _, _, err := svc.TreeOf(ctx, owner, p.ID); !errors.Is(err, knowledge.ErrNotFound) {
		t.Fatalf("the tree of an empty pack: %v", err)
	}

	files := knowledgeFiles()
	if _, _, err := svc.Replace(ctx, owner, p.ID, "sha256:0000", files); !errors.Is(err, knowledge.ErrChanged) {
		t.Fatalf("a replace from a tree the empty pack never held: %v", err)
	}
	got, changed, err := svc.Replace(ctx, owner, p.ID, "", files)
	if err != nil || !changed {
		t.Fatalf("replace: %+v %v %v", got, changed, err)
	}
	var want bytes.Buffer
	if err := knowledge.WriteTree(&want, files); err != nil {
		t.Fatal(err)
	}
	if got.State != knowledge.StateScanning || got.Files != len(files) || got.Pages != 1 || got.Bytes == 0 || got.Digest == "" {
		t.Fatalf("after the replace the pack is %+v", got)
	}
	var queued int
	if err := env.st.Pool().QueryRow(ctx, `SELECT count(*) FROM river_job WHERE kind = $1 AND args->>'pack' = $2`, knowledge.JobScan, p.ID.String()).Scan(&queued); err != nil {
		t.Fatal(err)
	}
	if queued != 1 {
		t.Fatalf("scans queued = %d, want 1", queued)
	}

	// While it is scanned it is not read; after, its tree is the files, and
	// the sealed tree an owner downloads opens under the key they unwrap.
	if _, _, err := svc.TreeOf(ctx, owner, p.ID); !errors.Is(err, knowledge.ErrScanning) {
		t.Fatalf("the tree of a scanning pack: %v", err)
	}
	drainKnowledgeScans(t, env)
	info, tree, err := svc.TreeOf(ctx, owner, p.ID)
	if err != nil || info.State != knowledge.StateReady || !bytes.Equal(tree, want.Bytes()) {
		t.Fatalf("the tree read back: %+v %v (equal %v)", info, err, bytes.Equal(tree, want.Bytes()))
	}
	var body knowledgePackBody
	env.doJSON(o.pat, http.MethodGet, "/api/v1/knowledge/packs/"+p.ID.String(), nil, &body, http.StatusOK)
	var dk struct {
		Key []byte `json:"key"`
	}
	env.doJSON(o.pat, http.MethodPost, "/api/v1/knowledge/keys/unwrap", body.WrappedKey, &dk, http.StatusOK)
	dataKey := dk.Key
	st, _, sealed := env.raw(o.pat, http.MethodGet, "/api/v1/knowledge/packs/"+p.ID.String()+"/tree", nil)
	if st != http.StatusOK {
		t.Fatalf("download: %d", st)
	}
	h, plain, err := packseal.Open(bytes.NewReader(sealed), dataKey)
	if err != nil {
		t.Fatalf("the resealed tree does not open under the pack's key: %v", err)
	}
	if want := "kp_" + hexOf(p.ID); h.Pack != want || h.Digest != got.Digest {
		t.Fatalf("header = %+v, want pack %s digest %s", h, want, got.Digest)
	}
	if _, err := knowledge.ReadTree(plain, got.Digest); err != nil {
		t.Fatal(err)
	}

	// The same tree again stores nothing and queues nothing, even from the
	// digest before it landed: a replace retried after it succeeded.
	if again, changed, err := svc.Replace(ctx, owner, p.ID, got.Digest, files); err != nil || changed || again.Digest != got.Digest {
		t.Fatalf("an unchanged tree: %+v %v %v", again, changed, err)
	}
	if again, changed, err := svc.Replace(ctx, owner, p.ID, "", files); err != nil || changed || again.Digest != got.Digest {
		t.Fatalf("a retried replace: %+v %v %v", again, changed, err)
	}
	if err := env.st.Pool().QueryRow(ctx, `SELECT count(*) FROM river_job WHERE kind = $1 AND args->>'pack' = $2`, knowledge.JobScan, p.ID.String()).Scan(&queued); err != nil || queued != 1 {
		t.Fatalf("scans queued after two unchanged replaces = %d (%v), want still 1", queued, err)
	}
	// A new tree keeps the header's pack id; one from a stale digest is
	// refused and stores nothing.
	more := append(knowledgeFiles(), scan.PackFile{Path: "wiki/topics/more.md", Content: []byte("---\ntitle: More\n---\nMore. [src: doc:notes.md]\n")})
	next, changed, err := svc.Replace(ctx, owner, p.ID, got.Digest, more)
	if err != nil || !changed || next.Pages != 2 {
		t.Fatalf("a second replace: %+v %v %v", next, changed, err)
	}
	if _, _, err := svc.Replace(ctx, owner, p.ID, got.Digest, knowledgeFiles()); !errors.Is(err, knowledge.ErrChanged) {
		t.Fatalf("a replace from the tree before: %v", err)
	}
	if cur, _ := svc.Info(ctx, owner, p.ID); cur.Digest != next.Digest {
		t.Fatalf("a refused replace moved the pack to %s", cur.Digest)
	}
	var objects int
	if err := env.st.Pool().QueryRow(ctx, `SELECT count(*) FROM knowledge_objects WHERE pack_id = $1`, p.ID).Scan(&objects); err != nil {
		t.Fatal(err)
	}
	if objects != 1 {
		t.Fatalf("objects = %d, want the one current tree", objects)
	}
	drainKnowledgeScans(t, env)
	_, sealed2 := downloadSealed(t, env, o, p.ID.String())
	if h2, err := packseal.ReadHeader(bytes.NewReader(sealed2)); err != nil || h2.Pack != h.Pack {
		t.Fatalf("the second tree's header: %+v %v, want pack %s", h2, err, h.Pack)
	}

	// Another owner reaches nothing.
	other := ownerOf(t, env, newKnowledgeOwner(env, "kn-seam-other"))
	if _, err := svc.Info(ctx, other, p.ID); !errors.Is(err, knowledge.ErrNotFound) {
		t.Fatalf("another owner's read: %v", err)
	}
	if _, _, err := svc.TreeOf(ctx, other, p.ID); !errors.Is(err, knowledge.ErrNotFound) {
		t.Fatalf("another owner's tree: %v", err)
	}
	if _, _, err := svc.Replace(ctx, other, p.ID, next.Digest, files); !errors.Is(err, knowledge.ErrNotFound) {
		t.Fatalf("another owner's replace: %v", err)
	}
	// Files that are not a pack's tree are refused, with nothing stored.
	for name, bad := range map[string][]scan.PackFile{
		"a climb":     {{Path: "wiki/../x.md", Content: []byte("x")}},
		"outside":     {{Path: "notes.md", Content: []byte("x")}},
		"a duplicate": {{Path: "wiki/a.md", Content: []byte("x")}, {Path: "wiki/a.md", Content: []byte("y")}},
	} {
		if _, _, err := svc.Replace(ctx, owner, p.ID, next.Digest, bad); !errors.Is(err, knowledge.ErrTree) {
			t.Errorf("%s: %v, want ErrTree", name, err)
		}
	}
}

// TestKnowledgeReplaceKeepsTheAllocation: a replace that would pass the
// pool's cap is the upload's allocation refusal, and stores nothing.
func TestKnowledgeReplaceKeepsTheAllocation(t *testing.T) {
	env := newTestEnvCfg(t, func(c *config.Config) { c.Limits.KnowledgeBytesPerAccount = 400 })
	ctx := context.Background()
	svc := env.srvObj.Knowledge()
	o := newKnowledgeOwner(env, "kn-seam-cap")
	owner := ownerOf(t, env, o)
	p, err := svc.CreateSealed(ctx, owner, "capped")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Replace(ctx, owner, p.ID, "", sizedPack(300, 'a')); err != nil {
		t.Fatal(err)
	}
	cur, _ := svc.Info(ctx, owner, p.ID)
	var alloc *knowledge.AllocationError
	if _, _, err := svc.Replace(ctx, owner, p.ID, cur.Digest, sizedPack(500, 'b')); !errors.As(err, &alloc) || alloc.Max != 400 {
		t.Fatalf("500 of 400: %v", err)
	}
	if after, _ := svc.Info(ctx, owner, p.ID); after.Digest != cur.Digest || after.Bytes != 300 {
		t.Fatalf("a refused replace moved the pack: %+v", after)
	}
	u, err := svc.Usage(ctx, owner)
	if err != nil || u.Used != 300 || u.Max != 400 {
		t.Fatalf("usage = %+v %v", u, err)
	}
}

func hexOf(id uuid.UUID) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 32)
	for _, b := range id {
		out = append(out, digits[b>>4], digits[b&0x0f])
	}
	return string(out)
}

// downloadSealed is an owner's download of a pack's sealed tree.
func downloadSealed(t *testing.T, env *testEnv, o knowledgeOwner, id string) (int, []byte) {
	t.Helper()
	st, _, b := env.raw(o.pat, http.MethodGet, "/api/v1/knowledge/packs/"+id+"/tree", nil)
	if st != http.StatusOK {
		t.Fatalf("download %s: %d %s", id, st, b)
	}
	return st, b
}

// TestKnowledgeReplaceRaceLandsOnce: two replaces from the same tree at
// once — the check under the pack's row lock lets exactly one in, and the
// other is ErrChanged with nothing stored.
func TestKnowledgeReplaceRaceLandsOnce(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	svc := env.srvObj.Knowledge()
	owner := ownerOf(t, env, newKnowledgeOwner(env, "kn-seam-race"))
	p, err := svc.CreateSealed(ctx, owner, "raced")
	if err != nil {
		t.Fatal(err)
	}
	for round := range 4 {
		cur, _ := svc.Info(ctx, owner, p.ID)
		errs := make(chan error, 2)
		for i := range 2 {
			go func() {
				_, _, err := svc.Replace(ctx, owner, p.ID, cur.Digest, sizedPack(100+round*10+i, byte('a'+i)))
				errs <- err
			}()
		}
		var ok, changed int
		for range 2 {
			switch err := <-errs; {
			case err == nil:
				ok++
			case errors.Is(err, knowledge.ErrChanged):
				changed++
			default:
				t.Fatalf("round %d: %v", round, err)
			}
		}
		if ok != 1 || changed != 1 {
			t.Fatalf("round %d: %d landed and %d were refused, want one each", round, ok, changed)
		}
	}
}
