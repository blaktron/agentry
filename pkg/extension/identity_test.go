package extension

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/entitlements"
	"github.com/blaktron/agentry/internal/knowledge"
	"github.com/blaktron/agentry/internal/registry"
	"github.com/blaktron/agentry/internal/voice"
	"github.com/blaktron/agentry/internal/webhook"
)

// directoryLike is the shape a directory extension takes: the directory
// port, the callbacks its sign-in flow calls, and the sign-in hook, all
// with this package's aliases alone, as a module outside the core writes
// them.
type directoryLike struct {
	noop
	name   string
	dir    Directory
	deps   Deps
	signIn []SignIn
}

func (d *directoryLike) Name() string         { return d.name }
func (d *directoryLike) Directory() Directory { return d.dir }
func (d *directoryLike) Bind(deps Deps)       { d.deps = deps }
func (d *directoryLike) SignedIn(_ context.Context, in SignIn) {
	d.signIn = append(d.signIn, in)
}
func (d *directoryLike) Callbacks() Callbacks {
	return Callbacks{
		Secret: "directory-callback-secret-0123456789",
		Class:  CallbackRateNone,
		Why:    "the directory's flow calls once per sign-in, on the private network",
		Routes: func(mux *http.ServeMux) {
			mux.HandleFunc("POST /trusted-device", func(w http.ResponseWriter, r *http.Request) {
				if p := PrincipalFromContext(r.Context()); p != nil && !p.Anonymous {
					http.Error(w, "a principal was resolved", http.StatusInternalServerError)
					return
				}
				_, _ = io.WriteString(w, `{"trusted":false}`)
			})
		},
	}
}

// aDirectory answers nothing: what a directory says is the API's tests'.
type aDirectory struct{}

func (aDirectory) EraseAccount(context.Context, DirectoryLink) (bool, DirectoryLookup, error) {
	return false, DirectoryLookupByAddress, nil
}
func (aDirectory) Devices(context.Context, DirectoryLink) ([]DirectoryDevice, error) { return nil, nil }
func (aDirectory) DeleteDevice(context.Context, DirectoryLink, string, string) (bool, error) {
	return false, nil
}
func (aDirectory) SignInFacts(context.Context, DirectoryLink) (DirectorySignInFacts, error) {
	return DirectorySignInFacts{}, nil
}
func (aDirectory) AccountGone(context.Context, DirectoryLink) (bool, error) { return false, nil }
func (aDirectory) GroupMembers(context.Context, string) (string, []DirectoryAccount, error) {
	return "", nil, nil
}
func (aDirectory) AccountsByEmail(context.Context, string) ([]DirectoryAccount, error) {
	return nil, nil
}
func (aDirectory) SetMember(context.Context, string, int, bool) error { return nil }

var (
	_ ManagesDirectory   = (*directoryLike)(nil)
	_ ReceivesCallbacks  = (*directoryLike)(nil)
	_ HearsSignIn        = (*directoryLike)(nil)
	_ Directory          = aDirectory{}
	_ Staff              = serverStaff{}
	_ RememberedBrowsers = serverRememberedBrowsers{}
)

func identityServer(t *testing.T) *api.Server {
	t.Helper()
	cfg := config.Default()
	cfg.DevMode = true
	return api.New(cfg, nil, slog.New(slog.DiscardHandler))
}

// TestApplyExtensionsWiresTheIdentitySeam: an extension's directory
// replaces the server's, its callbacks are mounted and declared under
// /internal/x/<name>/ behind the core's gate, and its sign-in hook is
// registered.
func TestApplyExtensionsWiresTheIdentitySeam(t *testing.T) {
	srv := identityServer(t)
	if srv.HasDirectory() {
		t.Fatal("a server with no directory configured has one")
	}
	ext := &directoryLike{name: "directory", dir: aDirectory{}}
	applyExtensions(srv, []Extension{ext})
	if !srv.HasDirectory() {
		t.Fatal("the extension's directory was not set")
	}
	if ext.deps.Staff != nil || ext.deps.RememberedBrowsers != nil || ext.deps.Members != nil {
		t.Error("without a database the staff read, the remembered browsers and the membership door must be nil, as DB is")
	}
	// The sealer is the server's with or without a database: what it seals
	// opens, and a value changed since does not.
	if ext.deps.Sealer == nil {
		t.Fatal("no sealer")
	}
	sealed, err := ext.deps.Sealer.Seal([]byte("person@example.test"))
	if err != nil {
		t.Fatal(err)
	}
	if open, err := ext.deps.Sealer.Open(sealed); err != nil || string(open) != "person@example.test" {
		t.Fatalf("open: %q %v", open, err)
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := ext.deps.Sealer.Open(sealed); err == nil {
		t.Fatal("a tampered value opened")
	}

	hs := httptest.NewServer(api.NewHandler(srv))
	defer hs.Close()
	if decl, ok := srv.MountAuthzDecl("/internal/x/directory/"); !ok || decl.Gate != api.GateExtensionSecret || decl.Class != CallbackRateNone {
		t.Fatalf("the callback mount is declared %+v (%v)", decl, ok)
	}
	post := func(header map[string]string) (int, string) {
		req, _ := http.NewRequest(http.MethodPost, hs.URL+"/internal/x/directory/trusted-device", strings.NewReader(`{}`))
		for k, v := range header {
			req.Header.Set(k, v)
		}
		res, err := hs.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}
	if code, body := post(map[string]string{"Authorization": "Bearer directory-callback-secret-0123456789"}); code != http.StatusOK || body != `{"trusted":false}` {
		t.Fatalf("the directory's call: %d %s", code, body)
	}
	if code, _ := post(nil); code != http.StatusUnauthorized {
		t.Errorf("a call without the secret: %d, want 401", code)
	}
}

// TestOneDirectoryPerDeployment: two extensions that both manage the
// directory are refused at start-up, and one whose Directory is nil leaves
// the server's in place.
func TestOneDirectoryPerDeployment(t *testing.T) {
	srv := identityServer(t)
	applyExtensions(srv, []Extension{&directoryLike{name: "quiet"}})
	if srv.HasDirectory() {
		t.Error("an extension with no directory set one")
	}
	// One that sets none does not count as the deployment's directory: the
	// next one that does is accepted.
	after := identityServer(t)
	applyExtensions(after, []Extension{&directoryLike{name: "quiet"}, &directoryLike{name: "real", dir: aDirectory{}}})
	if !after.HasDirectory() {
		t.Error("a directory after an extension that set none was not set")
	}
	defer func() {
		r := recover()
		if r == nil {
			t.Error("two directories were accepted")
			return
		}
		if msg, _ := r.(string); !strings.Contains(msg, "two and one both manage the directory") {
			t.Errorf("the refusal says %v, want it to name both extensions", r)
		}
	}()
	applyExtensions(identityServer(t), []Extension{
		&directoryLike{name: "one", dir: aDirectory{}},
		&directoryLike{name: "two", dir: aDirectory{}},
	})
}

// signInHookOf hands the extension's hook a sign-in whose remembered
// browser is audited as the extension's: the detail it asks for is kept,
// the keys that say who minted it are the core's, whatever the extension
// asked for, and the extension's own map is not written to.
func TestSignInHookAuditsTheRememberedBrowserUnderTheExtensionsName(t *testing.T) {
	var heard []SignIn
	hook := signInHookOf(signInRecorder{&heard}, "idp-bridge")
	var minted map[string]any
	user := uuid.New()
	hook(context.Background(), SignIn{
		UserID:   user,
		Provider: "google",
		RememberBrowser: func(detail map[string]any) (string, time.Duration, error) {
			minted = detail
			return "token", time.Hour, nil
		},
	})
	if len(heard) != 1 || heard[0].UserID != user || heard[0].Provider != "google" {
		t.Fatalf("the extension heard %+v, want the sign-in of %s through google", heard, user)
	}
	asked := map[string]any{"device": "laptop", "via": "forged", "extension": "someone-else"}
	token, ttl, err := heard[0].RememberBrowser(asked)
	if err != nil || token != "token" || ttl != time.Hour {
		t.Fatalf("remember: %q %v %v", token, ttl, err)
	}
	if minted["device"] != "laptop" || minted["via"] != "extension" || minted["extension"] != "idp-bridge" || len(minted) != 3 {
		t.Fatalf("the audited detail is %v, want device kept and via/extension the core's", minted)
	}
	if asked["via"] != "forged" || asked["extension"] != "someone-else" || len(asked) != 3 {
		t.Fatalf("the extension's own map was written to: %v", asked)
	}
	// With no detail at all the stamp is still there.
	if _, _, err := heard[0].RememberBrowser(nil); err != nil {
		t.Fatal(err)
	}
	if minted["via"] != "extension" || minted["extension"] != "idp-bridge" || len(minted) != 2 {
		t.Fatalf("the audited detail for none asked is %v", minted)
	}
}

// signInRecorder is a sign-in hook that keeps what it heard.
type signInRecorder struct{ heard *[]SignIn }

func (r signInRecorder) SignedIn(_ context.Context, in SignIn) { *r.heard = append(*r.heard, in) }

// TestTheIdentityEventsAreTheCoresNames: the event kinds an extension
// matches on are the ones the core fires.
func TestTheIdentityEventsAreTheCoresNames(t *testing.T) {
	if EventAccountErased != "account.erased" || EventStaffChanged != "staff.changed" {
		t.Fatalf("events %q %q", EventAccountErased, EventStaffChanged)
	}
	if ErrNoSecondFactor == nil {
		t.Fatal("no refusal for a mint without a second factor")
	}
}

// The names and refusals the seam exports are the core's own, each one the
// very value it stands for: an extension compares what the core hands it
// with these, so one that stood for its neighbour would be read as another
// answer. The api queue's name is the one the chart and the docs give.
func TestTheSeamsNamesAreTheCoresNames(t *testing.T) {
	if QueueAPI != "api" {
		t.Errorf("QueueAPI = %q, want api", QueueAPI)
	}
	for _, c := range []struct {
		name      string
		got, want any
	}{
		{"ErrNoSecondFactor", ErrNoSecondFactor, api.ErrNoSecondFactor},
		{"ErrOrgNotProvisionable", ErrOrgNotProvisionable, api.ErrOrgNotProvisionable},
		{"ErrAddressUnproven", ErrAddressUnproven, api.ErrAddressUnproven},
		{"ErrStaffOrgDomain", ErrStaffOrgDomain, registry.ErrStaffOrgDomain},
		{"ErrKeyNotOwner", ErrKeyNotOwner, knowledge.ErrNotOwner},
		{"ErrKnowledgeUnconfigured", ErrKnowledgeUnconfigured, knowledge.ErrUnconfigured},
		{"ErrKnowledgeNotFound", ErrKnowledgeNotFound, knowledge.ErrNotFound},
		{"ErrKnowledgeScanning", ErrKnowledgeScanning, knowledge.ErrScanning},
		{"ErrKnowledgeChanged", ErrKnowledgeChanged, knowledge.ErrChanged},
		{"ErrKnowledgeName", ErrKnowledgeName, knowledge.ErrName},
		{"ErrKnowledgeNameTaken", ErrKnowledgeNameTaken, knowledge.ErrNameTaken},
		{"ErrKnowledgeTree", ErrKnowledgeTree, knowledge.ErrTree},
		{"ErrKnowledgeTooLarge", ErrKnowledgeTooLarge, knowledge.ErrTooLarge},
		{"ErrVoiceUnconfigured", ErrVoiceUnconfigured, voice.ErrUnconfigured},
		{"ErrVoiceNotFound", ErrVoiceNotFound, voice.ErrNotFound},
		{"ErrVoiceTooLarge", ErrVoiceTooLarge, voice.ErrTooLarge},
		{"NamespaceUser", NamespaceUser, entitlements.NamespaceUser},
		{"NamespaceOrg", NamespaceOrg, entitlements.NamespaceOrg},
		{"KeyOwnerUser", KeyOwnerUser, knowledge.OwnerUser},
		{"KeyOwnerOrg", KeyOwnerOrg, knowledge.OwnerOrg},
		{"KnowledgeEmpty", KnowledgeEmpty, knowledge.StateEmpty},
		{"KnowledgeScanning", KnowledgeScanning, knowledge.StateScanning},
		{"KnowledgeReady", KnowledgeReady, knowledge.StateReady},
		{"KnowledgeFailed", KnowledgeFailed, knowledge.StateFailed},
		{"VoiceSourceBuild", VoiceSourceBuild, voice.SourceBuild},
		{"VoiceSourceAIEdit", VoiceSourceAIEdit, voice.SourceAIEdit},
		{"ScopeRunRead", ScopeRunRead, auth.ScopeRunRead},
		{"ScopeRunWrite", ScopeRunWrite, auth.ScopeRunWrite},
		{"ScopeKnowledgeRead", ScopeKnowledgeRead, auth.ScopeKnowledgeRead},
		{"ScopeKnowledgeWrite", ScopeKnowledgeWrite, auth.ScopeKnowledgeWrite},
		{"ScopeSecretWrite", ScopeSecretWrite, auth.ScopeSecretWrite},
		{"ModelInputOpScan", ModelInputOpScan, api.ModelInputOpScan},
		{"ModelInputOpSearch", ModelInputOpSearch, api.ModelInputOpSearch},
		{"ModelInputOpCheck", ModelInputOpCheck, api.ModelInputOpCheck},
		{"AccountErased", AccountErased, api.AccountErased},
		{"AccountDataCleared", AccountDataCleared, api.AccountDataCleared},
		{"ActorUser", ActorUser, audit.ActorUser},
		{"ActorPAT", ActorPAT, audit.ActorPAT},
		{"ActorSystem", ActorSystem, audit.ActorSystem},
		{"CallbackRateNone", CallbackRateNone, api.RateNone},
		{"CallbackRateAnon", CallbackRateAnon, api.RateAnon},
		{"DirectoryLookupByID", DirectoryLookupByID, api.DirectoryLookupByID},
		{"DirectoryLookupByUID", DirectoryLookupByUID, api.DirectoryLookupByUID},
		{"DirectoryLookupByAddress", DirectoryLookupByAddress, api.DirectoryLookupByAddress},
		{"DirectoryLookupAddressShared", DirectoryLookupAddressShared, api.DirectoryLookupAddressShared},
		{"DirectoryLookupIDMismatch", DirectoryLookupIDMismatch, api.DirectoryLookupIDMismatch},
		{"DirectoryLookupSuperuser", DirectoryLookupSuperuser, api.DirectoryLookupSuperuser},
		{"DirectoryErasureDeleted", DirectoryErasureDeleted, api.DirectoryErasureDeleted},
		{"DirectoryErasureNotFound", DirectoryErasureNotFound, api.DirectoryErasureNotFound},
		{"DirectoryErasureUnresolved", DirectoryErasureUnresolved, api.DirectoryErasureUnresolved},
		{"DirectoryErasureNotConfigured", DirectoryErasureNotConfigured, api.DirectoryErasureNotConfigured},
		{"DirectoryErasureFailed", DirectoryErasureFailed, api.DirectoryErasureFailed},
		{"DirectoryErasurePending", DirectoryErasurePending, api.DirectoryErasurePending},
		{"EventAgentDependencyAlert", EventAgentDependencyAlert, webhook.EventAgentDependencyAlert},
	} {
		if c.got != c.want {
			t.Errorf("%s = %v, want the core's %v", c.name, c.got, c.want)
		}
	}
}
