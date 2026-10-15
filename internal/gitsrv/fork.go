package gitsrv

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/registry"
)

// A fork's repository: the origin's copied, then one commit.
// RepoStore is the registry's ForkRepos on a role that holds the git
// volume (the worker, `all`).

var _ registry.ForkRepos = (*RepoStore)(nil)

// CopyRepository creates dst on defaultBranch and fetches every branch and
// tag of src into it. A fetch from a local path copies the objects into
// dst's own packs, never alternates or hard links, so deleting, retiring or
// rewriting the origin later leaves the fork as it was. An origin that was
// never pushed to has no repository on disk, and dst stays empty.
func (s *RepoStore) CopyRepository(ctx context.Context, src, dst uuid.UUID, defaultBranch string) error {
	if err := s.InitBare(ctx, dst, defaultBranch); err != nil {
		return err
	}
	srcDir := s.Path(src)
	if _, err := os.Stat(srcDir); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	_, err := s.git(ctx, s.Path(dst), nil, nil,
		"fetch", "--quiet", "--no-write-fetch-head", "--no-auto-gc", srcDir,
		"+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*")
	return err
}

// RemoveRepository deletes a repository a failed copy left behind; one that
// is not there is nothing to remove.
func (s *RepoStore) RemoveRepository(repoID uuid.UUID) error { return s.Remove(repoID) }

// HasCommit reports whether commit is a commit in the repository. What it
// and ReadFileAt are given comes from a version row, and is checked as an
// object id anyway before it reaches git's argument list.
func (s *RepoStore) HasCommit(ctx context.Context, repoID uuid.UUID, commit string) (bool, error) {
	if !reCommitID.MatchString(commit) {
		return false, nil
	}
	dir := s.Path(repoID)
	if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	cmd := exec.CommandContext(ctx, s.gitBin, "-C", dir, "cat-file", "-e", commit+"^{commit}") //nolint:gosec // fixed binary; object id validated
	cmd.Env = hermeticEnv(nil)
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return false, nil
		}
		return false, fmt.Errorf("gitsrv: cat-file: %w", err)
	}
	return true, nil
}

// ReadFileAt reads the blob at path in commit. A path the commit does not
// hold is fs.ErrNotExist, which trying again does not change.
func (s *RepoStore) ReadFileAt(ctx context.Context, repoID uuid.UUID, commit, path string) ([]byte, error) {
	if !reCommitID.MatchString(commit) || path == "" || strings.HasPrefix(path, "-") || strings.Contains(path, "..") {
		return nil, fmt.Errorf("gitsrv: %s:%s is not a file to read", commit, path)
	}
	dir := s.Path(repoID)
	// cat-file -e says whether the path is there without git's wording.
	probe := exec.CommandContext(ctx, s.gitBin, "-C", dir, "cat-file", "-e", commit+":"+path) //nolint:gosec // fixed binary; validated id and path
	probe.Env = hermeticEnv(nil)
	if err := probe.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return nil, fmt.Errorf("gitsrv: %s:%s: %w", commit[:12], path, fs.ErrNotExist)
		}
		return nil, fmt.Errorf("gitsrv: cat-file: %w", err)
	}
	return s.git(ctx, dir, nil, nil, "cat-file", "blob", commit+":"+path)
}

// CommitFork writes the fork's commit and points c.Refs at it, and c.Keep
// at the commits it names. The tree is built in a private index:
// c.BaseCommit's tree read into it, or c.Dir's files hashed into it one by
// one, then c.Manifest written over c.ManifestPath. c.Dir is an uploaded
// release's archive, so git never looks at it as a work tree: no
// `git add`, which would honour a .gitattributes among its files, read a
// .gitignore, and follow a `.git` file to whatever repository on this host
// it names (recording that repository's HEAD as a gitlink). Each file is
// hashed with --no-filters by its own path, and a path with a `.git`
// component is refused outright.
func (s *RepoStore) CommitFork(ctx context.Context, repoID uuid.UUID, c registry.ForkCommit) (string, error) {
	dir := s.Path(repoID)
	if c.BaseCommit != "" && !reCommitID.MatchString(c.BaseCommit) {
		return "", fmt.Errorf("gitsrv: %q is not a commit", c.BaseCommit)
	}
	if c.Parent != "" && !reCommitID.MatchString(c.Parent) {
		return "", fmt.Errorf("gitsrv: %q is not a commit", c.Parent)
	}
	for _, ref := range c.Refs {
		if !safeRefName(ref) || strings.Contains(ref, "..") {
			return "", fmt.Errorf("gitsrv: %q is not a ref name", ref)
		}
	}
	for ref, at := range c.Keep {
		if !safeRefName(ref) || strings.Contains(ref, "..") || !reCommitID.MatchString(at) {
			return "", fmt.Errorf("gitsrv: %q → %q is not a ref to keep", ref, at)
		}
	}
	if c.ManifestPath == "" || strings.HasPrefix(c.ManifestPath, "-") || strings.Contains(c.ManifestPath, "..") {
		return "", fmt.Errorf("gitsrv: %q is not a path", c.ManifestPath)
	}
	index, err := os.CreateTemp("", "agentry-fork-index-*")
	if err != nil {
		return "", err
	}
	indexPath := index.Name()
	_ = index.Close()
	_ = os.Remove(indexPath) // git writes a fresh index; an empty file is not one
	defer func() { _ = os.Remove(indexPath) }()
	env := []string{"GIT_INDEX_FILE=" + indexPath}

	if c.BaseCommit != "" {
		if _, err := s.git(ctx, dir, env, nil, "read-tree", c.BaseCommit); err != nil {
			return "", err
		}
	} else {
		info, err := indexInfo(ctx, s, dir, c.Dir)
		if err != nil {
			return "", err
		}
		if _, err := s.git(ctx, dir, env, info, "update-index", "--add", "--index-info"); err != nil {
			return "", err
		}
	}
	blob, err := s.git(ctx, dir, env, c.Manifest, "hash-object", "-w", "--no-filters", "--stdin")
	if err != nil {
		return "", err
	}
	if _, err := s.git(ctx, dir, env, nil, "update-index", "--add", "--cacheinfo",
		"100644,"+strings.TrimSpace(string(blob))+","+c.ManifestPath); err != nil {
		return "", err
	}
	tree, err := s.git(ctx, dir, env, nil, "write-tree")
	if err != nil {
		return "", err
	}
	args := []string{"commit-tree", strings.TrimSpace(string(tree))}
	if c.Parent != "" {
		args = append(args, "-p", c.Parent)
	}
	when := c.When.UTC().Format("2006-01-02T15:04:05Z")
	idEnv := append(env,
		"GIT_AUTHOR_NAME="+c.AuthorName, "GIT_AUTHOR_EMAIL="+c.AuthorEmail, "GIT_AUTHOR_DATE="+when,
		"GIT_COMMITTER_NAME=Agentry", "GIT_COMMITTER_EMAIL=noreply@agentry", "GIT_COMMITTER_DATE="+when,
	)
	out, err := s.git(ctx, dir, idEnv, []byte(c.Message), args...)
	if err != nil {
		return "", err
	}
	commit := strings.TrimSpace(string(out))
	for ref, at := range c.Keep {
		if _, err := s.git(ctx, dir, nil, nil, "update-ref", ref, at); err != nil {
			return "", err
		}
	}
	for _, ref := range c.Refs {
		if _, err := s.git(ctx, dir, nil, nil, "update-ref", ref, commit); err != nil {
			return "", err
		}
	}
	return commit, nil
}

// indexInfo hashes every regular file under root into the repository and
// returns `update-index --index-info` lines for them: mode, blob and the
// path relative to root. The archive extractor admits regular files only,
// and anything else here is refused rather than followed, as is a path
// with a `.git` component, in any case.
func indexInfo(ctx context.Context, s *RepoStore, dir, root string) ([]byte, error) {
	var paths, rels []string
	var modes []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
			if strings.EqualFold(part, ".git") {
				return fmt.Errorf("%w: it holds %q", registry.ErrForkTree, filepath.ToSlash(rel))
			}
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%w: %q is not a regular file", registry.ErrForkTree, filepath.ToSlash(rel))
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		mode := "100644"
		if fi.Mode().Perm()&0o111 != 0 {
			mode = "100755"
		}
		paths, rels, modes = append(paths, p), append(rels, filepath.ToSlash(rel)), append(modes, mode)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, nil
	}
	out, err := s.git(ctx, dir, nil, []byte(strings.Join(paths, "\n")+"\n"), "hash-object", "-w", "--no-filters", "--stdin-paths")
	if err != nil {
		return nil, err
	}
	shas := strings.Fields(string(out))
	if len(shas) != len(paths) {
		return nil, fmt.Errorf("gitsrv: hashed %d files, got %d ids", len(paths), len(shas))
	}
	var b bytes.Buffer
	for i := range paths {
		fmt.Fprintf(&b, "%s %s\t%s\n", modes[i], shas[i], rels[i])
	}
	return b.Bytes(), nil
}

// git runs one git command in dir with env added and stdin fed, and
// returns its standard output; a failure carries its standard error.
func (s *RepoStore) git(ctx context.Context, dir string, env []string, stdin []byte, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, s.gitBin, append([]string{"-C", dir}, args...)...) //nolint:gosec // fixed binary; store paths and validated names
	cmd.Env = hermeticEnv(env)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("gitsrv: git %s: %v: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// hermeticEnv is the process environment without any GIT_ variable a
// caller's context might carry (GIT_DIR in a hook, say), with no system or
// global configuration and no system attributes, plus extra.
func hermeticEnv(extra []string) []string {
	out := make([]string, 0, len(os.Environ())+len(extra)+4)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "GIT_") {
			out = append(out, kv)
		}
	}
	out = append(out, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_ATTR_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0")
	return append(out, extra...)
}
