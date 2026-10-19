package gitsrv

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/registry"
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
		{"anonymous read of a private agent", "private", &auth.Principal{Anonymous: true}, auth.ActAgentRepoRead, 401},
		{"anonymous push to a public agent", "public", &auth.Principal{Anonymous: true}, auth.ActAgentRepoWrite, 401},
		{"stranger read of a private agent", "private", strangerP, auth.ActAgentRepoRead, 404},
		{"stranger push to a public agent", "public", strangerP, auth.ActAgentRepoWrite, 403},
		{"stranger read of a public agent with nothing reviewed", "public", strangerP, auth.ActAgentRepoRead, 404},
		{"unactivated owner's push", "private", ownerP, auth.ActAgentRepoWrite, 403},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			agent := e.createAgentNoRepo("refused"+string(rune('a'+i)), c.visibility)
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

// Concurrent first requests for one repository all succeed, and each one
// that succeeds is served a complete repository, policy hook included.
func TestConcurrentFirstGitRequestsInitialiseOnce(t *testing.T) {
	e := newBookkeepingEnv(t)
	ctx := context.Background()
	ownerP := &auth.Principal{UserID: e.owner, Handle: "bko" + e.sfx, Via: "session", EmailVerified: true}
	const agents, callers = 6, 8
	for a := range agents {
		agent := e.createAgentNoRepo("race"+string(rune('a'+a)), "private")
		var wg sync.WaitGroup
		start := make(chan struct{})
		errs := make(chan string, callers)
		for range callers {
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
