// Package managedsettings is the format of a managed settings document:
// the values an organization's admins set for its members' Agentry
// clients. The registry signs one document per organization and version
// as a DSSE envelope with its release-signing key, and serves it to each
// active member. A client opens it only with a key it already trusts for
// that registry, and only for the organization it is a member of.
//
// A setting is either locked, which the member cannot change, or a
// default, which applies until the member chooses otherwise. Every setting
// is a row of the catalogue below, and a row's values only ever narrow
// what a member could choose for themselves: a document can forbid
// something, and it can never switch on something the member has not.
package managedsettings

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/blaktron/agentry/pkg/attest"
)

// PayloadType is the DSSE payload type of a managed settings document.
// The signature covers it, so an envelope of another type (a release's
// attestation) never opens as a document, and a verifier that checks the
// payload type refuses a document as an attestation.
const PayloadType = "application/vnd.agentry.managed-settings+json"

// Schema names this version of the document's shape. A client refuses a
// document whose schema it does not know.
const Schema = "managed-settings/1"

// Document is one member's managed settings.
type Document struct {
	// Schema is always the Schema constant.
	Schema string `json:"schema"`
	// Registry is the base URL of the registry that signed the document.
	// A client accepts it only from that registry.
	Registry string `json:"registry"`
	// Org is the handle of the organization whose settings these are. A
	// client accepts the document only while the signed-in account is an
	// active member of that organization; a person belongs to one.
	Org string `json:"org"`
	// Version increases with every change the organization's admins make.
	// A client refuses a version lower than the last it accepted from the
	// same organization, so an older copy cannot be replayed to it.
	Version int64 `json:"version"`
	// IssuedAt is when the registry signed this version.
	IssuedAt time.Time `json:"issuedAt"`
	// Settings maps a catalogue id to its value.
	Settings map[string]Setting `json:"settings"`
}

// Setting is one managed value.
type Setting struct {
	// Value is the row's value, a JSON string for an enumerated row.
	Value json.RawMessage `json:"value"`
	// Locked says the member cannot change it. A setting that is not
	// locked is an organization default.
	Locked bool `json:"locked"`
}

// String reads an enumerated setting's value, or "" when it is not a
// JSON string.
func (s Setting) String() string {
	var v string
	if json.Unmarshal(s.Value, &v) != nil {
		return ""
	}
	return v
}

// Kind is how a row's value is written and how it narrows.
type Kind string

const (
	// KindChoice is one of the row's Values, which run from the most open
	// to the most restrictive. No row has a value that switches anything
	// on.
	KindChoice Kind = "choice"
	// KindSet is a JSON array of the row's Values with no repeats and at
	// least one member: the members still allowed. A lock never adds a
	// member the row does not list.
	KindSet Kind = "set"
	// KindCap is a positive JSON number (an integer where the row says
	// so). A lock is the highest value a member may use; a default is the
	// value used when the member set none. A cap never lifts a member's
	// own lower limit.
	KindCap Kind = "cap"
	// KindSources is {"scope": "any"} or {"scope":
	// "organization-and-built-ins", "namespaces": [...]}: where a member
	// may install from.
	KindSources Kind = "sources"
	// KindMinimumVersion is a version "X.Y.Z": a client older than it
	// refuses runs and names the update.
	KindMinimumVersion Kind = "minimumVersion"
)

// Row is one entry of the catalogue.
type Row struct {
	// ID is the setting's name in a document.
	ID string
	// Kind says how the value is written and how it narrows.
	Kind Kind
	// Values are a choice's values, from the most open to the most
	// restrictive, or a set's members.
	Values []string
	// Integer says a cap is a whole number.
	Integer bool
	// Max is the largest cap a registry accepts.
	Max float64
	// LockOnly says the row is only ever locked: a default would have
	// nothing to apply (a set, a source list, a version floor).
	LockOnly bool
	// Summary says in one sentence what the row decides, for consoles and
	// for the client's own listing.
	Summary string
}

// The catalogue's ids.
const (
	// UnsafeMode decides whether a member may turn on Unsafe Mode, which
	// lets a local run use commands this machine has not catalogued. It
	// is "allowed" (the member decides, behind the client's own consent)
	// or "forbidden" (the client refuses to turn it on, and the runner
	// refuses an unsafe run). No value turns it on.
	UnsafeMode = "run.unsafeMode"

	InstallSources           = "install.sources"
	InstallAcceptRisk        = "install.acceptRisk"
	RunWhere                 = "run.where"
	RunTimeout               = "run.timeout"
	RunMaxTurns              = "run.maxTurns"
	RunMaxCost               = "run.maxCost"
	EgressWildcard           = "egress.wildcard"
	BrowserPublicWeb         = "browser.publicWeb"
	MCPAllowVulnerable       = "mcpServers.allowVulnerable"
	DesktopApplications      = "desktop.applications"
	DesktopScreen            = "desktop.screen"
	DesktopCustomServers     = "desktop.customServers"
	Messengers               = "messengers"
	PersistentReleases       = "persistentReleases"
	AgentsCodingAgent        = "agents.codingAgent"
	AgentsAssistant          = "agents.assistant"
	Schedules                = "schedules"
	DeliverablesDestinations = "deliverables.destinations"
	MalwareCheck             = "malwareCheck"
	UpdatesMinimumVersion    = "updates.minimumVersion"
	BugReports               = "bugReports"
)

// Values of the allowed-or-forbidden choices, UnsafeMode's among them.
const (
	UnsafeModeAllowed   = "allowed"
	UnsafeModeForbidden = "forbidden"

	Allowed   = "allowed"
	Forbidden = "forbidden"
)

// Values of MalwareCheck.
const (
	MalwareCheckOptional = "optional"
	MalwareCheckRequired = "required"
)

// Members of RunWhere.
const (
	WhereLocal      = "local"
	WhereHosted     = "hosted"
	WhereRunhost    = "runhost"
	WhereTargetHost = "target-host"
)

// Members of DeliverablesDestinations.
const (
	DestinationFolder  = "folder"
	DestinationWebhook = "webhook"
	DestinationS3      = "s3"
)

// Scopes of InstallSources.
const (
	SourcesAny                  = "any"
	SourcesOrganizationBuiltIns = "organization-and-built-ins"
)

// allowedOrForbidden is a row that forbids something a member may do.
func allowedOrForbidden(id, summary string) Row {
	return Row{ID: id, Kind: KindChoice, Values: []string{Allowed, Forbidden}, Summary: summary}
}

var catalogue = []Row{
	allowedOrForbidden(UnsafeMode, "Whether members may turn on Unsafe Mode for local runs."),
	{ID: InstallSources, Kind: KindSources, LockOnly: true,
		Summary: "Where members may install QuickAgents from: anywhere, or the organization, the built-ins and the namespaces listed."},
	allowedOrForbidden(InstallAcceptRisk, "Whether members may accept a release's risk at install (an unsigned or unscanned release)."),
	{ID: RunWhere, Kind: KindSet, Values: []string{WhereLocal, WhereHosted, WhereRunhost, WhereTargetHost}, LockOnly: true,
		Summary: "Where members' runs may go: this computer, In Agentry, a runhost, a target host."},
	{ID: RunTimeout, Kind: KindCap, Integer: true, Max: 7 * 24 * 3600,
		Summary: "The longest a run may take, in seconds."},
	{ID: RunMaxTurns, Kind: KindCap, Integer: true, Max: 100000,
		Summary: "The most turns a run may take."},
	{ID: RunMaxCost, Kind: KindCap, Max: 100000,
		Summary: "The most a run may cost, in US dollars, as its harness reports it."},
	allowedOrForbidden(EgressWildcard, "Whether members' policies may allow wildcard egress hosts."),
	allowedOrForbidden(BrowserPublicWeb, "Whether a run's browser may reach the public web."),
	allowedOrForbidden(MCPAllowVulnerable, "Whether members may run a declared MCP server the registry's gate rates high or critical."),
	allowedOrForbidden(DesktopApplications, "Whether runs may use applications on the member's computer through Agentry Desktop."),
	allowedOrForbidden(DesktopScreen, "Whether runs may see and use the member's screen (computer use)."),
	allowedOrForbidden(DesktopCustomServers, "Whether runs may use applications the member set up themselves rather than Agentry's catalogue."),
	allowedOrForbidden(Messengers, "Whether persistent agents may reach messengers."),
	allowedOrForbidden(PersistentReleases, "Whether members may run persistent QuickAgents from the registry."),
	allowedOrForbidden(AgentsCodingAgent, "Whether members may use the Coding agent."),
	allowedOrForbidden(AgentsAssistant, "Whether members may use the Assistant."),
	allowedOrForbidden(Schedules, "Whether members may schedule runs."),
	{ID: DeliverablesDestinations, Kind: KindSet, Values: []string{DestinationFolder, DestinationWebhook, DestinationS3}, LockOnly: true,
		Summary: "Where a run may send its result and files: a folder, a webhook, an S3 bucket."},
	{ID: MalwareCheck, Kind: KindChoice, Values: []string{MalwareCheckOptional, MalwareCheckRequired},
		Summary: "Whether a run's malware check of what it downloads is required."},
	{ID: UpdatesMinimumVersion, Kind: KindMinimumVersion, LockOnly: true,
		Summary: "The oldest Agentry client that may run; an older one names the update."},
	allowedOrForbidden(BugReports, "Whether members may send bug reports from their clients."),
}

// Catalogue is every row a document may carry, sorted by id.
func Catalogue() []Row {
	out := slices.Clone(catalogue)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Lookup is the row with the id, or false.
func Lookup(id string) (Row, bool) {
	for _, r := range catalogue {
		if r.ID == id {
			return r, true
		}
	}
	return Row{}, false
}

// Sources is the value of an InstallSources row.
type Sources struct {
	Scope      string   `json:"scope"`
	Namespaces []string `json:"namespaces,omitempty"`
}

// namespacePattern is a registry handle.
var namespacePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,38}$`)

// versionPattern is a release version a client compares itself with.
var versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$`)

// Check says whether s is a value this row takes: its shape, and for a row
// that is only ever locked, its lock.
func (r Row) Check(s Setting) error {
	if r.LockOnly && !s.Locked {
		return fmt.Errorf("managed settings: %s is only ever locked", r.ID)
	}
	switch r.Kind {
	case KindChoice:
		if !slices.Contains(r.Values, s.String()) {
			return fmt.Errorf("managed settings: %s must be one of %s", r.ID, strings.Join(r.Values, ", "))
		}
	case KindSet:
		var members []string
		if err := strictJSON(s.Value, &members); err != nil || len(members) == 0 {
			return fmt.Errorf("managed settings: %s must be a list of at least one of %s", r.ID, strings.Join(r.Values, ", "))
		}
		seen := map[string]bool{}
		for _, m := range members {
			if !slices.Contains(r.Values, m) || seen[m] {
				return fmt.Errorf("managed settings: %s must list each of %s at most once, and nothing else", r.ID, strings.Join(r.Values, ", "))
			}
			seen[m] = true
		}
	case KindCap:
		var n float64
		if err := strictJSON(s.Value, &n); err != nil || n <= 0 || n > r.Max || (r.Integer && n != math.Trunc(n)) {
			what := "a number"
			if r.Integer {
				what = "a whole number"
			}
			return fmt.Errorf("managed settings: %s must be %s above 0 and at most %g", r.ID, what, r.Max)
		}
	case KindSources:
		var v Sources
		if err := strictJSON(s.Value, &v); err != nil {
			return fmt.Errorf("managed settings: %s must be {\"scope\": …, \"namespaces\": […]}", r.ID)
		}
		switch v.Scope {
		case SourcesAny:
			if len(v.Namespaces) > 0 {
				return fmt.Errorf("managed settings: %s lists namespaces only with scope %s", r.ID, SourcesOrganizationBuiltIns)
			}
		case SourcesOrganizationBuiltIns:
			if len(v.Namespaces) > 100 {
				return fmt.Errorf("managed settings: %s lists at most 100 namespaces", r.ID)
			}
			for _, ns := range v.Namespaces {
				if !namespacePattern.MatchString(ns) {
					return fmt.Errorf("managed settings: %s: %q is not a namespace", r.ID, ns)
				}
			}
		default:
			return fmt.Errorf("managed settings: %s scope must be %s or %s", r.ID, SourcesAny, SourcesOrganizationBuiltIns)
		}
	case KindMinimumVersion:
		var v string
		if err := strictJSON(s.Value, &v); err != nil || !versionPattern.MatchString(v) {
			return fmt.Errorf("managed settings: %s must be a version X.Y.Z", r.ID)
		}
	default:
		return fmt.Errorf("managed settings: %s has no kind", r.ID)
	}
	return nil
}

// strictJSON decodes one JSON value into v, refusing fields v lacks and
// anything after the value.
func strictJSON(raw json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

// ValidateSettings checks every setting against the catalogue: a known id,
// and a value the row takes. It is what a registry checks before it stores
// or signs settings: a registry signs only rows it knows.
func ValidateSettings(settings map[string]Setting) error {
	return validateSettings(settings, false)
}

// validateSettings checks known rows' values. With allowUnknown, an id the
// catalogue does not know passes: a client reading a document from a newer
// registry keeps such rows and decides what they mean (Unknown).
func validateSettings(settings map[string]Setting, allowUnknown bool) error {
	for _, id := range sortedIDs(settings) {
		row, ok := Lookup(id)
		if !ok {
			if allowUnknown {
				continue
			}
			return fmt.Errorf("managed settings: unknown setting %q", id)
		}
		if err := row.Check(settings[id]); err != nil {
			return err
		}
	}
	return nil
}

func sortedIDs(settings map[string]Setting) []string {
	ids := make([]string, 0, len(settings))
	for id := range settings {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// UnknownSetting is a setting whose id this version's catalogue does not
// know: a row a newer registry added.
type UnknownSetting struct {
	ID     string
	Locked bool
}

// Unknown lists the document's settings whose ids the catalogue does not
// know, sorted by id. A client cannot apply them: a locked one means the
// organization holds the member to something this client cannot enforce,
// so the client should refuse to run until it is updated; a default one
// can be passed over.
func (d Document) Unknown() []UnknownSetting {
	var out []UnknownSetting
	for _, id := range sortedIDs(d.Settings) {
		if _, ok := Lookup(id); !ok {
			out = append(out, UnknownSetting{ID: id, Locked: d.Settings[id].Locked})
		}
	}
	return out
}

// Validate checks a whole document as a registry signs it: its schema, its
// binding fields, and settings that are all rows of the catalogue.
func (d Document) Validate() error {
	return d.validate(false)
}

func (d Document) validate(allowUnknown bool) error {
	switch {
	case d.Schema != Schema:
		return fmt.Errorf("managed settings: schema %q, want %q", d.Schema, Schema)
	case d.Registry == "":
		return errors.New("managed settings: no registry")
	case d.Org == "":
		return errors.New("managed settings: no organization")
	case d.Version < 1:
		return errors.New("managed settings: version must be at least 1")
	case d.IssuedAt.IsZero():
		return errors.New("managed settings: no issue time")
	}
	return validateSettings(d.Settings, allowUnknown)
}

// Envelope is a signed document as the registry serves it.
type Envelope = attest.DSSEEnvelope

// Seal encodes a valid document as the payload a signer signs. The
// returned bytes are what the envelope carries.
func Seal(d Document) ([]byte, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	if d.Settings == nil {
		d.Settings = map[string]Setting{}
	}
	return json.Marshal(d)
}

// Wrap puts a payload and its signature into an envelope.
func Wrap(payload []byte, sig attest.DSSESignature) Envelope {
	return Envelope{
		PayloadType: PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []attest.DSSESignature{sig},
	}
}

// Open verifies an envelope against a public key the caller already
// trusts for the registry, then decodes and validates the document. It
// refuses another payload type, another schema, a field the format does
// not have, and a known row with a value it does not take. A row whose id
// this catalogue does not know is kept, for the caller to judge through
// Unknown: a newer registry may add rows. It does not check Registry, Org
// or Version: the caller compares them with the registry it is signed in
// to, the organization it is a member of, and the last version it
// accepted.
func Open(env Envelope, publicKeyPEM string) (Document, error) {
	payload, err := attest.VerifyPayload(env, publicKeyPEM, PayloadType)
	if err != nil {
		return Document{}, err
	}
	return decode(payload)
}

func decode(payload []byte) (Document, error) {
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	var d Document
	if err := dec.Decode(&d); err != nil {
		return Document{}, fmt.Errorf("managed settings: decode: %w", err)
	}
	if dec.More() {
		return Document{}, errors.New("managed settings: trailing data after the document")
	}
	if err := d.validate(true); err != nil {
		return Document{}, err
	}
	return d, nil
}
