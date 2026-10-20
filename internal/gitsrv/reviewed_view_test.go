package gitsrv_test

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/registry"
)

// recordVersion records a version of agent at commit with the given status,
// as the pipeline would have left it.
func (e *gitEnv) recordVersion(agent registry.Agent, version, commit, status string) uuid.UUID {
	e.t.Helper()
	id := newUUID(e.t)
	if _, err := e.st.Pool().Exec(context.Background(),
		`INSERT INTO agent_versions (id, agent_id, version, commit_sha, manifest, submitted_by, source, status)
		 VALUES ($1, $2, $3, $4, '{}', $5, 'git-tag', $6)`,
		id, agent.ID, version, commit, e.owner.id, status); err != nil {
		e.t.Fatal(err)
	}
	return id
}

// releaseHead makes work's HEAD a reviewed version of agent: tagged, pushed
// with remote, and recorded as published, so a reader with no role on a
// public agent can clone it.
func (e *gitEnv) releaseHead(agent registry.Agent, work, remote, tag string) {
	e.t.Helper()
	if _, err := e.st.Pool().Exec(context.Background(), `UPDATE agents SET auto_publish_tags = false WHERE id = $1`, agent.ID); err != nil {
		e.t.Fatal(err)
	}
	mustGit(e.t, work, "tag", tag)
	mustGit(e.t, work, "push", "-q", remote, "refs/tags/"+tag)
	e.recordVersion(agent, strings.TrimPrefix(tag, "v"), strings.TrimSpace(mustGit(e.t, work, "rev-parse", "HEAD")), "published")
}

func (e *gitEnv) setVersionStatus(id uuid.UUID, status string) {
	e.t.Helper()
	if _, err := e.st.Pool().Exec(context.Background(), `UPDATE agent_versions SET status = $2 WHERE id = $1`, id, status); err != nil {
		e.t.Fatal(err)
	}
}

func (e *gitEnv) setAgentQuarantine(agent registry.Agent, state string) {
	e.t.Helper()
	if _, err := e.st.Pool().Exec(context.Background(), `UPDATE agents SET quarantine_state = $2 WHERE id = $1`, agent.ID, state); err != nil {
		e.t.Fatal(err)
	}
}

// seedTaggedAgent creates an agent whose owner pushes one commit per tag,
// each adding a file only that commit carries, then one more commit on main
// that no tag names. Tags here never auto-publish: the test records the
// versions itself. It returns the commit of each tag and of main.
func (e *gitEnv) seedTaggedAgent(name, visibility string, tags ...string) (registry.Agent, map[string]string) {
	e.t.Helper()
	agent := e.seedAgent(name, visibility)
	if _, err := e.st.Pool().Exec(context.Background(), `UPDATE agents SET auto_publish_tags = false WHERE id = $1`, agent.ID); err != nil {
		e.t.Fatal(err)
	}
	work := seedWorkdir(e.t, map[string]string{"agent.yaml": "schemaVersion: \"1\"\n", "README.md": "# " + name + "\n"})
	commits := map[string]string{}
	for _, tag := range tags {
		writeFile(e.t, work, "only-in-"+tag+".txt", "content of "+tag+"\n")
		mustGit(e.t, work, "add", ".")
		mustGit(e.t, work, "commit", "-q", "-m", tag)
		mustGit(e.t, work, "tag", "-a", "-m", tag, tag)
		commits[tag] = strings.TrimSpace(mustGit(e.t, work, "rev-parse", "HEAD"))
	}
	writeFile(e.t, work, "unreleased.txt", "work in progress\n")
	mustGit(e.t, work, "add", ".")
	mustGit(e.t, work, "commit", "-q", "-m", "unreleased")
	commits["main"] = strings.TrimSpace(mustGit(e.t, work, "rev-parse", "HEAD"))
	mustGit(e.t, work, "push", "-q", e.cloneURL(name, e.owner.patRW), "main", "--tags")
	return agent, commits
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// remoteRefs lists the refs a reader is advertised, by protocol version.
func remoteRefs(t *testing.T, url string, protocol int) ([]string, error) {
	t.Helper()
	out, err := gitRun(t, t.TempDir(), "-c", fmt.Sprintf("protocol.version=%d", protocol), "ls-remote", url)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, out)
	}
	var refs []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if _, ref, ok := strings.Cut(line, "\t"); ok {
			refs = append(refs, ref)
		}
	}
	slices.Sort(refs)
	return refs, nil
}

func infoRefsStatus(t *testing.T, url string) int {
	t.Helper()
	res, err := http.Get(url + "/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	return res.StatusCode
}

// TestOnlyReviewedVersionsAreCloneable: a reader with no role on a public
// agent, anonymous or signed in, is served the tags of its reviewed
// versions and the objects they reach, and nothing else, over either
// protocol version; the agent's own people read everything.
func TestOnlyReviewedVersionsAreCloneable(t *testing.T) {
	env := newGitEnv(t)
	stranger := env.seedPerson("gits" + env.sfx)
	agent, c := env.seedTaggedAgent("reviewed", "public", "v1.0.0", "v1.1.0", "v1.2.0", "v1.3.0", "v1.4.0", "v1.5.0")
	env.recordVersion(agent, "1.0.0", c["v1.0.0"], "published")
	awaiting := env.recordVersion(agent, "1.1.0", c["v1.1.0"], "needs_review")
	env.recordVersion(agent, "1.2.0", c["v1.2.0"], "rejected")
	quarantined := env.recordVersion(agent, "1.3.0", c["v1.3.0"], "quarantined")
	env.recordVersion(agent, "1.4.0", c["v1.4.0"], "blocked")
	env.recordVersion(agent, "1.5.0", c["v1.5.0"], "scanning")

	readers := map[string]string{
		"anonymous":          env.cloneURL(agent.Name, ""),
		"signed in, no role": env.cloneURL(agent.Name, stranger.patRO),
	}
	for who, url := range readers {
		for _, protocol := range []int{0, 2} {
			t.Run(fmt.Sprintf("%s, protocol v%d", who, protocol), func(t *testing.T) {
				refs, err := remoteRefs(t, url, protocol)
				if err != nil {
					t.Fatal(err)
				}
				want := []string{"HEAD", "refs/tags/v1.0.0", "refs/tags/v1.0.0^{}"}
				if !slices.Equal(refs, want) {
					t.Fatalf("advertised %v, want %v", refs, want)
				}

				dst := t.TempDir()
				mustGit(t, dst, "-c", fmt.Sprintf("protocol.version=%d", protocol), "clone", "-q", url, "c")
				clone := filepath.Join(dst, "c")
				if head := strings.TrimSpace(mustGit(t, clone, "rev-parse", "HEAD")); head != c["v1.0.0"] {
					t.Fatalf("clone checked out %s, want the reviewed v1.0.0 %s", head, c["v1.0.0"])
				}
				if _, err := os.Stat(filepath.Join(clone, "only-in-v1.0.0.txt")); err != nil {
					t.Fatal("the reviewed version's file is missing from the clone")
				}
				// Nothing past the reviewed version came with it, and none
				// of it can be fetched by name: not a commit, not a tree,
				// not a file's blob.
				for _, tag := range []string{"v1.1.0", "v1.2.0", "v1.3.0", "v1.4.0", "v1.5.0", "main"} {
					if out, err := gitRun(t, clone, "cat-file", "-e", c[tag]); err == nil {
						t.Fatalf("the clone holds %s's commit:\n%s", tag, out)
					}
					if out, err := gitRun(t, clone, "-c", fmt.Sprintf("protocol.version=%d", protocol), "fetch", "-q", url, c[tag]); err == nil {
						t.Fatalf("fetched %s's commit by id:\n%s", tag, out)
					}
				}
				for id, what := range map[string]string{
					blobID(t, "work in progress\n"):    "the unreleased file",
					blobID(t, "content of v1.1.0\n"):   "a version awaiting review's file",
					blobID(t, "content of v1.3.0\n"):   "a quarantined version's file",
					treeOf(t, env, agent, c["main"]):   "main's tree",
					treeOf(t, env, agent, c["v1.2.0"]): "a rejected version's tree",
				} {
					if out, err := gitRun(t, clone, "-c", fmt.Sprintf("protocol.version=%d", protocol), "fetch", "-q", url, id); err == nil {
						t.Fatalf("fetched %s by id:\n%s", what, out)
					}
				}
			})
		}
	}

	t.Run("a partial clone reads the reviewed version", func(t *testing.T) {
		dst := t.TempDir()
		mustGit(t, dst, "clone", "-q", "--filter=blob:none", env.cloneURL(agent.Name, ""), "c")
		if _, err := os.Stat(filepath.Join(dst, "c", "only-in-v1.0.0.txt")); err != nil {
			t.Fatal("the partial clone did not check out the reviewed version")
		}
	})

	t.Run("the owner reads everything", func(t *testing.T) {
		refs, err := remoteRefs(t, env.cloneURL(agent.Name, env.owner.patRO), 2)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"refs/heads/main", "refs/tags/v1.1.0", "refs/tags/v1.3.0", "refs/tags/v1.5.0"} {
			if !slices.Contains(refs, want) {
				t.Fatalf("the owner is not advertised %s: %v", want, refs)
			}
		}
	})

	t.Run("a token git does not send reads as anonymous", func(t *testing.T) {
		// Without proactive authentication git asks anonymously first, and
		// a public agent answers that with its reviewed versions.
		out, err := gitRunWithEnv(t, t.TempDir(), []string{"GIT_CONFIG_COUNT=1"}, "ls-remote", env.cloneURL(agent.Name, env.owner.patRO))
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		if strings.Contains(out, "refs/heads/main") {
			t.Fatalf("an unsent token read the whole repository:\n%s", out)
		}
	})

	t.Run("a reinstated version is cloneable again", func(t *testing.T) {
		env.setVersionStatus(quarantined, "published")
		refs, err := remoteRefs(t, env.cloneURL(agent.Name, ""), 2)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"HEAD", "refs/tags/v1.0.0", "refs/tags/v1.0.0^{}", "refs/tags/v1.3.0", "refs/tags/v1.3.0^{}"}
		if !slices.Equal(refs, want) {
			t.Fatalf("advertised %v, want %v", refs, want)
		}
		// A reviewed version carries its history: v1.1.0 and v1.2.0 are
		// ancestors of v1.3.0, but neither tag is advertised.
		dst := t.TempDir()
		mustGit(t, dst, "clone", "-q", env.cloneURL(agent.Name, ""), "c")
		if head := strings.TrimSpace(mustGit(t, filepath.Join(dst, "c"), "rev-parse", "HEAD")); head != c["v1.3.0"] {
			t.Fatalf("clone checked out %s, want the newest reviewed version %s", head, c["v1.3.0"])
		}
		env.setVersionStatus(quarantined, "quarantined")
		refs, err = remoteRefs(t, env.cloneURL(agent.Name, ""), 2)
		if err != nil {
			t.Fatal(err)
		}
		if slices.Contains(refs, "refs/tags/v1.3.0") {
			t.Fatalf("a version quarantined again is still advertised: %v", refs)
		}
	})

	// A yanked version is still a reviewed one, which the registry serves by
	// exact pin, so its tag is served too. A version admitted without a scan
	// passed no review whatever its status says.
	t.Run("a yanked version is served and an unscanned one is not", func(t *testing.T) {
		defer func() {
			env.setVersionStatus(awaiting, "needs_review")
			if _, err := env.st.Pool().Exec(context.Background(), `UPDATE agent_versions SET scan_status = 'pipeline' WHERE id = $1`, awaiting); err != nil {
				t.Error(err)
			}
		}()
		env.setVersionStatus(awaiting, "yanked")
		refs, err := remoteRefs(t, env.cloneURL(agent.Name, ""), 2)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"HEAD", "refs/tags/v1.0.0", "refs/tags/v1.0.0^{}", "refs/tags/v1.1.0", "refs/tags/v1.1.0^{}"}
		if !slices.Equal(refs, want) {
			t.Fatalf("with v1.1.0 yanked, advertised %v, want %v", refs, want)
		}

		env.setVersionStatus(awaiting, "published")
		if _, err := env.st.Pool().Exec(context.Background(), `UPDATE agent_versions SET scan_status = 'skipped' WHERE id = $1`, awaiting); err != nil {
			t.Fatal(err)
		}
		for _, status := range []string{"published", "yanked"} {
			env.setVersionStatus(awaiting, status)
			refs, err = remoteRefs(t, env.cloneURL(agent.Name, ""), 2)
			if err != nil {
				t.Fatal(err)
			}
			if want := []string{"HEAD", "refs/tags/v1.0.0", "refs/tags/v1.0.0^{}"}; !slices.Equal(refs, want) {
				t.Fatalf("with v1.1.0 %s but admitted without a scan, advertised %v, want %v", status, refs, want)
			}
		}
	})

	for _, state := range []string{"quarantined", "blocked"} {
		t.Run("an agent the platform has "+state+" is not found", func(t *testing.T) {
			env.setAgentQuarantine(agent, state)
			defer env.setAgentQuarantine(agent, "none")
			if got := infoRefsStatus(t, env.cloneURL(agent.Name, "")); got != http.StatusUnauthorized {
				t.Fatalf("anonymous: %d, want 401 (an unknown path's answer)", got)
			}
			if got := infoRefsStatus(t, env.cloneURL(agent.Name, stranger.patRO)); got != http.StatusNotFound {
				t.Fatalf("signed in, no role: %d, want 404", got)
			}
			if _, err := remoteRefs(t, env.cloneURL(agent.Name, env.owner.patRO), 2); err != nil {
				t.Fatalf("the owner: %v", err)
			}
		})
	}
}

// blobID is the id git gives a file with this content.
func blobID(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, dir, "f", content)
	return strings.TrimSpace(mustGit(t, dir, "hash-object", "f"))
}

// treeOf reads a commit's root tree from the agent's own repository.
func treeOf(t *testing.T, env *gitEnv, agent registry.Agent, commit string) string {
	t.Helper()
	return strings.TrimSpace(mustGit(t, env.repos.Path(agent.RepoID), "rev-parse", commit+"^{tree}"))
}

// TestAPublicAgentWithNothingReviewedIsNotFound: with no reviewed version
// a public agent is, to a reader with no role, a path that is not there.
func TestAPublicAgentWithNothingReviewedIsNotFound(t *testing.T) {
	env := newGitEnv(t)
	stranger := env.seedPerson("gitn" + env.sfx)
	agent, c := env.seedTaggedAgent("unreviewed", "public", "v0.1.0", "v0.2.0")
	env.recordVersion(agent, "0.1.0", c["v0.1.0"], "rejected")
	env.recordVersion(agent, "0.2.0", c["v0.2.0"], "needs_review")
	// A published version whose tag is gone leaves nothing to serve either.
	env.recordVersion(agent, "0.3.0", c["main"], "published")

	if got := infoRefsStatus(t, env.cloneURL(agent.Name, "")); got != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d, want 401 (an unknown path's answer)", got)
	}
	if got := infoRefsStatus(t, env.cloneURL(agent.Name, stranger.patRO)); got != http.StatusNotFound {
		t.Fatalf("signed in, no role: %d, want 404", got)
	}
	out, err := gitRun(t, t.TempDir(), "clone", env.cloneURL(agent.Name, stranger.patRO), "c")
	if err == nil || !strings.Contains(out, "not found") {
		t.Fatalf("a clone with no role: %v\n%s", err, out)
	}
	dst := t.TempDir()
	mustGit(t, dst, "clone", "-q", env.cloneURL(agent.Name, env.owner.patRO), "c")
	if _, err := os.Stat(filepath.Join(dst, "c", "unreleased.txt")); err != nil {
		t.Fatal("the owner's clone is not the whole repository")
	}
}

// TestAPrivateOrgAgentOverGit: an organization's active members read its
// private agents in full; a pending member and a security reviewer get a
// missing path's answer.
func TestAPrivateOrgAgentOverGit(t *testing.T) {
	env := newGitEnv(t)
	orgH := "gitorg" + env.sfx
	orgID := env.seedOrg(orgH, false)
	env.seedOrgAgent(orgH, orgID, "inside", "private")
	work := seedWorkdir(t, map[string]string{"agent.yaml": "schemaVersion: \"1\"\n", "README.md": "# inside\n"})
	mustGit(t, work, "push", "-q", env.cloneURLNS(orgH, "inside", env.owner.patRW), "main")

	join := func(handle, role, state string) person {
		p := env.seedPerson(handle + env.sfx)
		if _, err := env.st.Pool().Exec(context.Background(),
			`INSERT INTO memberships (org_id, user_id, role, state) VALUES ($1, $2, $3, $4)`,
			orgID, p.id, role, state); err != nil {
			t.Fatal(err)
		}
		return p
	}
	member := join("gitm", "member", "active")
	pending := join("gitp", "member", "pending")
	reviewer := join("gitr", "security_reviewer", "active")

	dst := t.TempDir()
	mustGit(t, dst, "clone", "-q", env.cloneURLNS(orgH, "inside", member.patRO), "c")
	if refs, err := remoteRefs(t, env.cloneURLNS(orgH, "inside", member.patRO), 2); err != nil || !slices.Contains(refs, "refs/heads/main") {
		t.Fatalf("an active member is not advertised main: %v %v", refs, err)
	}
	for who, p := range map[string]person{"a pending member": pending, "a security reviewer": reviewer} {
		if got := infoRefsStatus(t, env.cloneURLNS(orgH, "inside", p.patRO)); got != http.StatusNotFound {
			t.Fatalf("%s: %d, want 404", who, got)
		}
	}
}

// TestSSHServesOnlyReviewedVersionsToAReaderWithNoRole: the SSH transport
// serves the same reviewed-only repository.
func TestSSHServesOnlyReviewedVersionsToAReaderWithNoRole(t *testing.T) {
	env := newGitEnv(t)
	port := sshPort(env.startSSH(t))
	stranger := env.seedPerson("gitk" + env.sfx)
	client := newSSHClient(t)
	env.seedSSHKey(stranger.id, client)
	sshEnv := []string{"GIT_SSH_COMMAND=" + client.gitSSHCommand()}

	agent, c := env.seedTaggedAgent("viassh", "public", "v1.0.0", "v2.0.0")
	env.recordVersion(agent, "1.0.0", c["v1.0.0"], "published")
	env.recordVersion(agent, "2.0.0", c["v2.0.0"], "needs_review")
	url := fmt.Sprintf("ssh://git@127.0.0.1:%d/%s/%s.git", port, env.owner.handle, agent.Name)

	out, err := gitRunWithEnv(t, t.TempDir(), sshEnv, "ls-remote", url)
	if err != nil {
		t.Fatalf("ls-remote over SSH: %v\n%s", err, out)
	}
	if strings.Contains(out, "refs/heads/main") || strings.Contains(out, "v2.0.0") || !strings.Contains(out, "refs/tags/v1.0.0") {
		t.Fatalf("over SSH a reader with no role was advertised:\n%s", out)
	}
	dst := t.TempDir()
	if out, err := gitRunWithEnv(t, dst, sshEnv, "clone", "-q", url, "c"); err != nil {
		t.Fatalf("clone over SSH: %v\n%s", err, out)
	}
	if out, err := gitRunWithEnv(t, filepath.Join(dst, "c"), sshEnv, "fetch", "-q", url, c["v2.0.0"]); err == nil {
		t.Fatalf("fetched an unreviewed commit by id over SSH:\n%s", out)
	}
}
