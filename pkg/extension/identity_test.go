package extension

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
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
	defer func() {
		if recover() == nil {
			t.Error("two directories were accepted")
		}
	}()
	applyExtensions(identityServer(t), []Extension{
		&directoryLike{name: "one", dir: aDirectory{}},
		&directoryLike{name: "two", dir: aDirectory{}},
	})
}

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
