package gitsrv

import (
	"context"
	"io"
	"log/slog"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/registry"
)

// TestAcceptedRefsRefusesUnsafeNames pins that a requested update whose ref
// name is not a plain ref is never counted as accepted, a delete included:
// the repository cannot hold such a ref, so its absence proves nothing.
func TestAcceptedRefsRefusesUnsafeNames(t *testing.T) {
	r := newReleaseRepo(t, nil)
	h := &Handler{repos: r.s, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	agent := registry.Agent{RepoID: r.id}
	c1 := r.commit
	plumbIn(t, r.dir, "", "update-ref", "refs/heads/real", c1)
	want := []RefUpdate{
		{Old: c1, New: zeroOID, Ref: "refs/heads/a b"},
		{Old: c1, New: zeroOID, Ref: "refs/tags/v*"},
		{Old: c1, New: zeroOID, Ref: "-d"},
		{Old: zeroOID, New: c1, Ref: "refs/heads/real"},
		{Old: c1, New: zeroOID, Ref: "refs/heads/x~1"},
	}
	got := h.acceptedRefs(context.Background(), agent, want)
	var names []string
	for _, ru := range got {
		names = append(names, ru.Ref)
	}
	if !slices.Equal(names, []string{"refs/heads/real"}) {
		t.Fatalf("accepted %q, want only the real update", names)
	}
	// With no plain name at all, nothing is accepted either.
	if got := h.acceptedRefs(context.Background(), agent, want[:3]); len(got) != 0 {
		t.Fatalf("accepted %+v from unsafe names alone", got)
	}
}

// TestRefsAtWithNoPlainNameReadsNothing pins that names which are all
// refused leave nothing to look up: the result is empty, and git is not run
// to list every ref (a repository that is not there answers no error).
func TestRefsAtWithNoPlainNameReadsNothing(t *testing.T) {
	r := newReleaseRepo(t, nil)
	ctx := context.Background()
	unsafe := []string{"-d", "refs/heads/*", "refs/heads/a b", "main"}
	got, err := r.s.RefsAt(ctx, r.id, unsafe)
	if err != nil || len(got) != 0 {
		t.Fatalf("RefsAt(%q) = %v, %v; want nothing", unsafe, got, err)
	}
	if got, err := r.s.RefsAt(ctx, uuid.New(), unsafe); err != nil || len(got) != 0 {
		t.Fatalf("RefsAt on a missing repository with no plain name = %v, %v; want nothing, and git not run", got, err)
	}
	// nil still lists every ref.
	if all, err := r.s.RefsAt(ctx, r.id, nil); err != nil || len(all) == 0 {
		t.Fatalf("RefsAt(nil) = %v, %v; want every ref", all, err)
	}
}

// TestSafeRefNameFollowsGit pins safeRefName to the names git accepts: each
// name here is checked with git check-ref-format, and safeRefName agrees.
func TestSafeRefNameFollowsGit(t *testing.T) {
	for _, ref := range []string{
		"refs/heads/main", "refs/tags/v1.0.0", "refs/heads/feature/x-1", "refs/heads/a.b", "refs/heads/@",
		"refs/heads/a b", "refs/heads/*", "refs/heads/x~1", "refs/heads/a:b", "refs/heads/a\\b",
		"refs/heads/a..b", "refs/heads/a@{1}", "refs/heads/x.lock", "refs/heads/.hidden", "refs/heads/a//b",
		"refs/heads/a/", "refs/heads/a.", "refs/heads/a\x01b", "refs/heads/a\x7fb", "refs/heads/a\rb",
		"refs/heads/x.lock/y", "main", "-d",
	} {
		gitOK := exec.Command("git", "check-ref-format", ref).Run() == nil //nolint:gosec // fixed binary, test names
		if strings.HasPrefix(ref, "-") || !strings.HasPrefix(ref, "refs/") {
			gitOK = false // only fully-qualified names are plain refs here
		}
		if got := safeRefName(ref); got != gitOK {
			t.Errorf("safeRefName(%q) = %v, git check-ref-format says %v", ref, got, gitOK)
		}
	}
}

// TestAcceptedRefsRefusesNamesGitRefuses pins that a delete of a name git
// would never hold (a component starting with a dot, "..", "@{", ".lock",
// a control character) is not counted as accepted.
func TestAcceptedRefsRefusesNamesGitRefuses(t *testing.T) {
	r := newReleaseRepo(t, nil)
	h := &Handler{repos: r.s, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	c1 := r.commit
	var want []RefUpdate
	for _, ref := range []string{"refs/heads/.x", "refs/heads/a..b", "refs/heads/a@{1}", "refs/heads/x.lock", "refs/heads/a\x01b", "refs/heads/a//b"} {
		want = append(want, RefUpdate{Old: c1, New: zeroOID, Ref: ref})
	}
	if got := h.acceptedRefs(context.Background(), registry.Agent{RepoID: r.id}, want); len(got) != 0 {
		t.Fatalf("accepted %+v, deletes of names git refuses", got)
	}
}
