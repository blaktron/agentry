package ui

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"strings"
	"time"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/ui.css
var stylesheet []byte

// page is what every template receives.
type page struct {
	Title   string
	Brand   Brand
	Mode    string
	Site    bool
	User    *userInfo
	Flash   string
	Error   string
	CSRF    string
	Path    string
	Nav     []navItem
	Data    any
	LogoURL string
	CSSURL  string
}

type navItem struct {
	Href, Label string
	Current     bool
}

type userInfo struct {
	ID            string    `json:"id"`
	Handle        string    `json:"handle"`
	Email         string    `json:"email"`
	DisplayName   string    `json:"displayName"`
	EmailVerified bool      `json:"emailVerified"`
	TotpEnabled   bool      `json:"totpEnabled"`
	Orgs          []userOrg `json:"orgs"`
}

type userOrg struct {
	Handle string `json:"handle"`
	Role   string `json:"role"`
}

var funcs = template.FuncMap{
	"utc": func(v any) string {
		switch t := v.(type) {
		case time.Time:
			return t.UTC().Format("2006-01-02 15:04 UTC")
		case *time.Time:
			if t == nil {
				return ""
			}
			return t.UTC().Format("2006-01-02 15:04 UTC")
		case string:
			if p, err := time.Parse(time.RFC3339, t); err == nil {
				return p.UTC().Format("2006-01-02 15:04 UTC")
			}
			return t
		}
		return fmt.Sprint(v)
	},
	"join": strings.Join,
}

// templates parses the layout once and each page against a clone of it.
type templates map[string]*template.Template

func loadTemplates() (templates, error) {
	layout, err := template.New("layout").Funcs(funcs).ParseFS(templateFS, "templates/layout.html")
	if err != nil {
		return nil, err
	}
	out := templates{}
	entries, err := fs.ReadDir(templateFS, "templates")
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		name := e.Name()
		if name == "layout.html" || !strings.HasSuffix(name, ".html") {
			continue
		}
		t, err := layout.Clone()
		if err != nil {
			return nil, err
		}
		if _, err := t.ParseFS(templateFS, "templates/"+name); err != nil {
			return nil, fmt.Errorf("ui: template %s: %w", name, err)
		}
		out[strings.TrimSuffix(name, ".html")] = t
	}
	return out, nil
}

func (h *handler) render(w http.ResponseWriter, r *http.Request, status int, name string, p page) {
	t, ok := h.tmpl[name]
	if !ok {
		h.log.Error("ui: no template", "name", name)
		http.Error(w, "page missing", http.StatusInternalServerError)
		return
	}
	p.Brand = h.opt.Brand
	p.Mode = h.opt.Mode
	p.Site = h.opt.SiteURL != ""
	p.Path = r.URL.Path
	p.CSRF = cookieValue(r, csrfCookie)
	if p.Flash == "" {
		p.Flash = r.URL.Query().Get("ok")
	}
	if p.Error == "" {
		p.Error = r.URL.Query().Get("error")
	}
	p.LogoURL = h.opt.Brand.LogoURL
	p.CSSURL = h.opt.Brand.CSSURL
	if p.User != nil && h.opt.Mode == "full" {
		for _, n := range []navItem{{Href: "/ui/account", Label: "Account"}, {Href: "/ui/account/tokens", Label: "Tokens"}, {Href: "/ui/account/ssh-keys", Label: "SSH keys"}, {Href: "/ui/account/sessions", Label: "Sessions"}, {Href: "/ui/review", Label: "Review"}, {Href: "/ui/staff", Label: "Staff"}} {
			n.Current = strings.HasPrefix(r.URL.Path, n.Href) && (n.Href != "/ui/account" || r.URL.Path == "/ui/account" || r.URL.Path == "/ui/account/directory")
			p.Nav = append(p.Nav, n)
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// no-transform: a CDN in front (Cloudflare on the hosted site) must not
	// rewrite the page — its email obfuscation replaces addresses with a
	// script this CSP blocks, leaving "[email protected]" on the account page.
	w.Header().Set("Cache-Control", "no-store, no-transform")
	w.Header().Set("Content-Security-Policy", h.csp)
	w.WriteHeader(status)
	if err := t.ExecuteTemplate(w, "layout", p); err != nil {
		h.log.Error("ui: render", "name", name, "err", err)
	}
}
