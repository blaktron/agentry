package gitsrv

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/registry"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// createAgentNoRepo creates an agent whose repository has never been made on
// disk, as every agent is until its first git request.
func (e *bkEnv) createAgentNoRepo(name, visibility string) registry.Agent {
	e.t.Helper()
	p := &auth.Principal{UserID: e.owner, Handle: "bko" + e.sfx, Via: "session", EmailVerified: true}
	agent, err := e.reg.CreateAgent(context.Background(), p, registry.CreateAgentInput{
		Namespace: "bko" + e.sfx, Name: name, Modes: []string{"autonomous"}, Visibility: visibility,
	}, audit.Event{Actor: e.owner, ActorKind: audit.ActorUser})
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := os.Stat(e.repos.Path(agent.RepoID)); !os.IsNotExist(err) {
		e.t.Fatalf("repository exists before any git request: %v", err)
	}
	return agent
}

// A request that is refused must not make the repository it names: the
// lazy initialisation belongs after the decision to serve.
func TestRefusedGitRequestCreatesNoRepository(t *testing.T) {
	e := newBookkeepingEnv(t)
	ctx := context.Background()
	stranger := e.seedUser("bks" + e.sfx)
	strangerP := &auth.Principal{UserID: stranger, Handle: "bks" + e.sfx, Via: "session", EmailVerified: true}
	ownerP := &auth.Principal{UserID: e.owner, Handle: "bko" + e.sfx, Via: "session", EmailVerified: true, Unactivated: true}

	cases := []struct {
		name, visibility string
		principal        *auth.Principal
		act              auth.Action
		status           int
	}{
		{"anonymous read of a private agent", "private", &auth.Principal{Anonymous: true}, auth.ActAgentRepoRead, http.StatusUnauthorized},
		{"anonymous push to a public agent", "public", &auth.Principal{Anonymous: true}, auth.ActAgentRepoWrite, http.StatusUnauthorized},
		{"stranger read of a private agent", "private", strangerP, auth.ActAgentRepoRead, http.StatusNotFound},
		{"stranger push to a public agent", "public", strangerP, auth.ActAgentRepoWrite, http.StatusForbidden},
		{"stranger read of a public agent with nothing reviewed", "public", strangerP, auth.ActAgentRepoRead, http.StatusNotFound},
		{"unactivated owner's push", "private", ownerP, auth.ActAgentRepoWrite, http.StatusForbidden},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			agent := e.createAgentNoRepo(fmt.Sprintf("refused-%d", i), c.visibility)
			_, _, _, denial := e.h.authorizeGit(ctx, "bko"+e.sfx, agent.Name, c.principal, c.act)
			if denial == nil || denial.status != c.status {
				t.Fatalf("denial = %+v, want status %d", denial, c.status)
			}
			if _, err := os.Stat(e.repos.Path(agent.RepoID)); !os.IsNotExist(err) {
				t.Fatalf("a refused request made the repository on disk (stat err %v)", err)
			}
			if left, _ := filepath.Glob(filepath.Join(filepath.Dir(e.repos.Path(agent.RepoID)), "*"+agent.RepoID.String()+"*")); len(left) != 0 {
				t.Fatalf("a refused request left %v on disk", left)
			}
		})
	}
}

// A fork still being copied is refused even to its owner, and its
// repository stays the copy's to make.
func TestCopyingForkGitRequestCreatesNoRepository(t *testing.T) {
	e := newBookkeepingEnv(t)
	ctx := context.Background()
	origin := e.createAgentNoRepo("origin", "public")
	version := uuid.New()
	if _, err := e.st.Pool().Exec(ctx,
		`INSERT INTO agent_versions (id, agent_id, version, manifest, submitted_by, source, status)
		 VALUES ($1, $2, '1.0.0', '{}', $3, 'git-tag', 'published')`,
		version, origin.ID, e.owner); err != nil {
		t.Fatal(err)
	}
	q := e.st.Queries()
	repoID, agentID := uuid.New(), uuid.New()
	if _, err := q.CreateRepo(ctx, repoID); err != nil {
		t.Fatal(err)
	}
	agent, err := q.CreateForkAgent(ctx, storegen.CreateForkAgentParams{
		ID: agentID, NamespaceID: e.owner, Name: "copying", RepoID: repoID, Modes: []string{"autonomous"},
		ForkedFromAgentID: &origin.ID, ForkedFromVersionID: &version, ForkedBy: &e.owner,
	})
	if err != nil {
		t.Fatal(err)
	}
	ownerP := &auth.Principal{UserID: e.owner, Handle: "bko" + e.sfx, Via: "session", EmailVerified: true}
	_, _, _, denial := e.h.authorizeGit(ctx, "bko"+e.sfx, agent.Name, ownerP, auth.ActAgentRepoWrite)
	if denial == nil || denial.status != http.StatusConflict {
		t.Fatalf("denial = %+v, want status %d", denial, http.StatusConflict)
	}
	if _, err := os.Stat(e.repos.Path(agent.RepoID)); !os.IsNotExist(err) {
		t.Fatalf("a request for a fork being copied made its repository (stat err %v)", err)
	}
}

// Concurrent first requests for one repository all succeed, and each one
// that succeeds is served a complete repository, policy hook included.
func TestConcurrentFirstGitRequestsInitialiseOnce(t *testing.T) {
	e := newBookkeepingEnv(t)
	ctx := context.Background()
	ownerP := &auth.Principal{UserID: e.owner, Handle: "bko" + e.sfx, Via: "session", EmailVerified: true}
	const agentCount, callerCount = 6, 8
	for a := range agentCount {
		agent := e.createAgentNoRepo(fmt.Sprintf("race-%d", a), "private")
		var wg sync.WaitGroup
		start := make(chan struct{})
		errs := make(chan string, callerCount)
		for range callerCount {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, _, _, denial := e.h.authorizeGit(ctx, "bko"+e.sfx, agent.Name, ownerP, auth.ActAgentRepoWrite)
				if denial != nil {
					errs <- denial.message
					return
				}
				if _, err := os.Stat(filepath.Join(e.repos.Path(agent.RepoID), "hooks", "pre-receive")); err != nil {
					errs <- "served before the repository was complete: " + err.Error()
				}
			}()
		}
		close(start)
		wg.Wait()
		close(errs)
		for msg := range errs {
			t.Errorf("%s: a concurrent first request failed: %s", agent.Name, msg)
		}
		if left, _ := filepath.Glob(filepath.Join(filepath.Dir(e.repos.Path(agent.RepoID)), "."+agent.RepoID.String()+"*")); len(left) != 0 {
			t.Errorf("%s: initialisation left %v behind", agent.Name, left)
		}
	}
}
