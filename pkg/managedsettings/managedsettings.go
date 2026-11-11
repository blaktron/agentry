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
	"unicode"
	"unicode/utf8"

	"github.com/blaktron/agentry/pkg/attest"
	"github.com/blaktron/agentry/pkg/manifest"
)

// PayloadType is the DSSE payload type of a managed settings document.
// The signature covers it, so an envelope of another type (a release's
// attestation) never opens as a document, and a verifier that checks the
// payload type refuses a document as an attestation.
const PayloadType = "application/vnd.agentry.managed-settings+json"

// Schema names the document's shape when every member of the organization
// receives it alike. A client refuses a document whose schema it does not
// know; SchemaMembers is the other shape.
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
	// Members binds the document to the accounts it is for. A document
	// of SchemaMembers has it; one of Schema, which every member of the
	// organization receives alike, has none.
	Members *Members `json:"members,omitempty"`
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
	// KindModel is {"provider": …, "model": …}: a provider of the row's
	// Values and a model id. Locked, it is the only model members' runs
	// use; as a default, the one a member who chose none runs on.
	KindModel Kind = "model"
	// KindSource is {"source": …} with one of the row's Values: what pays
	// for a service, from the member's own key (the most open) to none at
	// all. A row that delivers keys (Delivers) carries, with
	// organization-key and only then, {"key": {"id", "rev"}}: a reference
	// to the organization's key, never its value. A row with Providers
	// names the service's provider with organization-key.
	KindSource Kind = "source"
	// KindQuickAgents is a list of Assignment: the QuickAgents an
	// organization gives its members, each required or offered, pinned to a
	// version or following the latest, with an optional preset of run
	// settings. It is only ever locked: the list is the organization's.
	KindQuickAgents Kind = "quickAgents"
	// KindText is a JSON string of at most the row's MaxLength characters,
	// with no control characters but newlines: a preference such as an
	// agent's name, which grants nothing.
	KindText Kind = "text"
	// KindToggle is a JSON boolean: a preference such as whether an agent
	// starts with Agentry, which grants nothing.
	KindToggle Kind = "toggle"
	// KindServers is a list of Server: remote MCP servers put on an agent's
	// roster. The member still consents to them at the agent's next start,
	// and the runner's own server rules still apply to them.
	KindServers Kind = "servers"
	// KindPacks is a list of the organization's shared knowledge packs by
	// name, put on an agent's roster; the member still consents to them.
	KindPacks Kind = "packs"
	// KindToolModels maps a coding tool of the row's Values to the model id
	// it uses.
	KindToolModels Kind = "toolModels"
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
	// AllowEmpty says a set may have no member: nothing of it allowed.
	AllowEmpty bool
	// Delivers says a source row's organization-key carries a key
	// reference, which a client exchanges for the key itself; a row that
	// does not deliver never carries one.
	Delivers bool
	// Providers are the providers a source row's organization-key may
	// name; empty when the row names none.
	Providers []string
	// MaxLength is the most characters a text row takes.
	MaxLength int
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

	ModelProviders       = "model.providers"
	ModelDefault         = "model.default"
	ModelSource          = "model.source"
	ModelSignIns         = "model.signIns"
	ModelCustomEndpoints = "model.customEndpoints"
	ReviewSource         = "review.source"
	WebSearchSource      = "webSearch.source"
	CodingToolsAllowed   = "codingTools.allowed"

	QuickAgents = "quickagents"

	AgentsAssistantName        = "agents.assistant.name"
	AgentsAssistantPersonality = "agents.assistant.personality"
	AgentsAssistantRunOnStart  = "agents.assistant.runOnStart"
	AgentsAssistantServers     = "agents.assistant.servers"
	AgentsAssistantKnowledge   = "agents.assistant.knowledge"
	AgentsCodingAgentServers   = "agents.codingAgent.servers"
	AgentsCodingAgentKnowledge = "agents.codingAgent.knowledge"
	CodingToolsModels          = "codingTools.models"
	AgentsUnreviewed           = "agents.unreviewed"
)

// The bounds of an agent configuration's rows.
const (
	MaxAgentNameLength   = 64
	MaxPersonalityLength = 4000
	MaxAgentServers      = 20
	MaxAgentPacks        = 20
)

// Server is one remote MCP server of a KindServers row: a name it is shown
// by, its https address, and how it is signed in to: "oauth" (the member's
// connection, or the organization's identity provider for a server the
// organization manages) or "none". The organization delivers no secret
// for it.
type Server struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	Auth string `json:"auth"`
}

// An assignment's modes and its version that follows the newest release.
const (
	// AssignRequired is installed on every member's signed-in client, and
	// cannot be uninstalled while the organization requires it.
	AssignRequired = "required"
	// AssignOffered is listed for the member, who installs it on demand.
	AssignOffered = "offered"
	// VersionLatest follows the newest version the member could install.
	VersionLatest = "latest"
)

// The bounds of a quickagents value.
const (
	MaxAssignments  = 100
	MaxPresetInputs = 32
	MaxInputBytes   = 4096
)

// Assignment is one QuickAgent an organization gives its members.
type Assignment struct {
	// Ref is the release, "namespace/name".
	Ref string `json:"ref"`
	// Version is "X.Y.Z" to pin it, or VersionLatest.
	Version string `json:"version"`
	// Mode is AssignRequired or AssignOffered.
	Mode string `json:"mode"`
	// Preset is the run settings a member would otherwise choose.
	Preset *Preset `json:"preset,omitempty"`
	// PresetLocked makes the preset a lock rather than a default.
	PresetLocked bool `json:"presetLocked,omitempty"`
}

// Preset is the run settings of an assignment's runs: each a default the
// member may change, or, with Assignment.PresetLocked, fixed. A field left
// out is the member's to choose.
type Preset struct {
	Model          *Model            `json:"model,omitempty"`
	TimeoutSeconds int               `json:"timeoutSeconds,omitempty"`
	MaxTurns       int               `json:"maxTurns,omitempty"`
	Where          string            `json:"where,omitempty"`
	Inputs         map[string]string `json:"inputs,omitempty"`
}

// Members of ModelProviders and providers of ModelDefault: the model
// providers a run may use. ProviderAgentry is the registry's own
// endpoint, paid from credits or by the organization's key; ProviderCustom
// is any endpoint of the member's own.
const (
	ProviderAnthropic   = "anthropic"
	ProviderOpenAI      = "openai"
	ProviderGoogle      = "google"
	ProviderVultr       = "vultr"
	ProviderOpenRouter  = "openrouter"
	ProviderPoe         = "poe"
	ProviderHuggingFace = "huggingface"
	ProviderCopilot     = "copilot"
	ProviderAgentry     = "agentry"
	ProviderCustom      = "custom"
)

// Members of ModelSignIns: the subscriptions and plans a run may spend.
const (
	SignInSubscription = "subscription"
	SignInClaude       = "claude-signin"
	SignInChatGPT      = "chatgpt-plan"
	SignInCopilot      = "copilot-signin"
)

// Values of ModelCustomEndpoints.
const (
	EndpointsHTTPSOnly = "https-only"
)

// Values of the source rows, from the most open to none.
const (
	SourceMember          = "member"
	SourceAgentryCredits  = "agentry-credits"
	SourceOrganizationKey = "organization-key"
	SourceOff             = "off"
)

// Providers of WebSearchSource.
const (
	SearchBrave      = "brave"
	SearchTavily     = "tavily"
	SearchExa        = "exa"
	SearchPerplexity = "perplexity"
	SearchYouCom     = "youcom"
)

// Members of CodingToolsAllowed: the coding tools whose harnesses a run
// may use.
const (
	CodingClaudeCode = "claude-code"
	CodingCodex      = "codex"
	CodingCopilot    = "copilot"
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
	{ID: ModelProviders, Kind: KindSet, LockOnly: true,
		Values:  []string{ProviderAnthropic, ProviderOpenAI, ProviderGoogle, ProviderVultr, ProviderOpenRouter, ProviderPoe, ProviderHuggingFace, ProviderCopilot, ProviderAgentry, ProviderCustom},
		Summary: "Which model providers members' runs may use."},
	{ID: ModelDefault, Kind: KindModel,
		Values:  []string{ProviderAnthropic, ProviderOpenAI, ProviderGoogle, ProviderVultr, ProviderOpenRouter, ProviderPoe, ProviderHuggingFace, ProviderCopilot, ProviderAgentry, ProviderCustom},
		Summary: "The model members' runs use: the only one when locked, the one a member who chose none runs on as a default."},
	{ID: ModelSource, Kind: KindSource, Values: []string{SourceMember, SourceAgentryCredits, SourceOrganizationKey},
		Summary: "What pays for members' models: their own keys and plans, the organization's credits, or the organization's own key, which stays with the registry."},
	{ID: ModelSignIns, Kind: KindSet, LockOnly: true, AllowEmpty: true,
		Values:  []string{SignInSubscription, SignInClaude, SignInChatGPT, SignInCopilot},
		Summary: "Which subscriptions and plans of their own members' runs may spend; none when the list is empty."},
	{ID: ModelCustomEndpoints, Kind: KindChoice, Values: []string{Allowed, EndpointsHTTPSOnly, Forbidden},
		Summary: "Whether members' runs may use a model endpoint of their own, and whether it may be plain http."},
	{ID: ReviewSource, Kind: KindSource, Values: []string{SourceMember, SourceAgentryCredits, SourceOrganizationKey, SourceOff}, Delivers: true,
		Summary: "What pays for AI Review: the member's own key, the organization's credits, the organization's key, or no AI Review."},
	{ID: WebSearchSource, Kind: KindSource, Values: []string{SourceMember, SourceAgentryCredits, SourceOrganizationKey, SourceOff}, Delivers: true,
		Providers: []string{SearchBrave, SearchTavily, SearchExa, SearchPerplexity, SearchYouCom},
		Summary:   "What pays for web search: the member's own key, the organization's credits, the organization's key for a provider, or no web search."},
	{ID: CodingToolsAllowed, Kind: KindSet, LockOnly: true, Values: []string{CodingClaudeCode, CodingCodex, CodingCopilot},
		Summary: "Which coding tools members' runs may use."},
	{ID: QuickAgents, Kind: KindQuickAgents, LockOnly: true,
		Summary: "The QuickAgents the organization gives its members: each required (installed for every member) or offered, pinned or following the latest, with an optional preset of run settings."},

	{ID: AgentsAssistantName, Kind: KindText, MaxLength: MaxAgentNameLength,
		Summary: "The name members' Assistant goes by."},
	{ID: AgentsAssistantPersonality, Kind: KindText, MaxLength: MaxPersonalityLength,
		Summary: "The personality members' Assistant takes on."},
	{ID: AgentsAssistantRunOnStart, Kind: KindToggle,
		Summary: "Whether members' Assistant starts when Agentry starts."},
	{ID: AgentsAssistantServers, Kind: KindServers,
		Summary: "Remote MCP servers on members' Assistant, which each member consents to at its next start."},
	{ID: AgentsAssistantKnowledge, Kind: KindPacks,
		Summary: "The organization's shared knowledge packs on members' Assistant, which each member consents to at its next start."},
	{ID: AgentsCodingAgentServers, Kind: KindServers,
		Summary: "Remote MCP servers on members' Coding agent, which each member consents to at its next start."},
	{ID: AgentsCodingAgentKnowledge, Kind: KindPacks,
		Summary: "The organization's shared knowledge packs on members' Coding agent, which each member consents to at its next start."},
	{ID: CodingToolsModels, Kind: KindToolModels, Values: []string{CodingClaudeCode, CodingCodex, CodingCopilot},
		Summary: "The model each coding tool uses in members' runs."},
	allowedOrForbidden(AgentsUnreviewed, "Whether members may let a persistent agent read web pages Without AI Review."),
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

// Model is the value of a KindModel row.
type Model struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
}

// Source is the value of a KindSource row.
type Source struct {
	Source   string  `json:"source"`
	Provider string  `json:"provider,omitempty"`
	Key      *KeyRef `json:"key,omitempty"`
}

// KeyRef names an organization's key and its revision. It is a reference
// a client exchanges for the key, never the key.
type KeyRef struct {
	ID  string `json:"id"`
	Rev int64  `json:"rev"`
}

// modelPattern is a model id as providers name them.
var modelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}$`)

// keyIDPattern is an organization key's id.
var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,63}$`)

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
		if err := strictJSON(s.Value, &members); err != nil || members == nil || (len(members) == 0 && !r.AllowEmpty) {
			least := "at least one"
			if r.AllowEmpty {
				least = "any"
			}
			return fmt.Errorf("managed settings: %s must be a list of %s of %s", r.ID, least, strings.Join(r.Values, ", "))
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
	case KindModel:
		var v Model
		if err := strictJSON(s.Value, &v); err != nil || !slices.Contains(r.Values, v.Provider) || !modelPattern.MatchString(v.Model) {
			return fmt.Errorf("managed settings: %s must be {\"provider\": one of %s, \"model\": a model id}", r.ID, strings.Join(r.Values, ", "))
		}
	case KindSource:
		return r.checkSource(s)
	case KindQuickAgents:
		return r.checkQuickAgents(s)
	case KindText:
		var v string
		if err := strictJSON(s.Value, &v); err != nil || isNull(s.Value) || utf8.RuneCountInString(v) > r.MaxLength || !utf8.ValidString(v) || hasControl(v) {
			return fmt.Errorf("managed settings: %s must be text of at most %d characters, with no control characters but newlines", r.ID, r.MaxLength)
		}
	case KindToggle:
		var v bool
		if err := strictJSON(s.Value, &v); err != nil || isNull(s.Value) {
			return fmt.Errorf("managed settings: %s must be true or false", r.ID)
		}
	case KindServers:
		return r.checkServers(s)
	case KindPacks:
		var names []string
		if err := strictJSON(s.Value, &names); err != nil || names == nil || len(names) > MaxAgentPacks {
			return fmt.Errorf("managed settings: %s must be a list of at most %d knowledge pack names", r.ID, MaxAgentPacks)
		}
		seen := map[string]bool{}
		for _, n := range names {
			if !agentNamePattern.MatchString(n) || seen[n] {
				return fmt.Errorf("managed settings: %s must name each knowledge pack once, by its name", r.ID)
			}
			seen[n] = true
		}
	case KindToolModels:
		var v map[string]string
		if err := strictJSON(s.Value, &v); err != nil || len(v) == 0 {
			return fmt.Errorf("managed settings: %s must map at least one of %s to a model id", r.ID, strings.Join(r.Values, ", "))
		}
		for tool, model := range v {
			if !slices.Contains(r.Values, tool) || !modelPattern.MatchString(model) {
				return fmt.Errorf("managed settings: %s must map each of %s to a model id, and nothing else", r.ID, strings.Join(r.Values, ", "))
			}
		}
	default:
		return fmt.Errorf("managed settings: %s has no kind", r.ID)
	}
	return nil
}

// agentNamePattern is a server's name on an agent, or a knowledge pack's
// name, as a manifest names them.
var agentNamePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`)

// isNull says a value is JSON null, which decodes into a string or a
// boolean with no error.
func isNull(raw json.RawMessage) bool { return string(bytes.TrimSpace(raw)) == "null" }

// hasControl says v holds a control character other than a newline or a
// tab.
func hasControl(v string) bool {
	return strings.ContainsFunc(v, func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\t' })
}

// checkServers checks a KindServers value: at most MaxAgentServers, each
// with its own name, an address a remote MCP server may have, and oauth or
// none to sign in with.
func (r Row) checkServers(s Setting) error {
	var list []Server
	if err := strictJSON(s.Value, &list); err != nil || list == nil || len(list) > MaxAgentServers {
		return fmt.Errorf("managed settings: %s must be a list of at most %d {\"name\", \"url\", \"auth\"}", r.ID, MaxAgentServers)
	}
	seen := map[string]bool{}
	for _, sv := range list {
		if !agentNamePattern.MatchString(sv.Name) || seen[sv.Name] {
			return fmt.Errorf("managed settings: %s must name each server once, with a lower-case name", r.ID)
		}
		seen[sv.Name] = true
		if err := manifest.CheckRemoteAddress(sv.URL); err != nil {
			return fmt.Errorf("managed settings: %s: %s: %w", r.ID, sv.Name, err)
		}
		if sv.Auth != string(manifest.AuthOAuth) && sv.Auth != string(manifest.AuthNone) {
			return fmt.Errorf("managed settings: %s: %s's auth must be oauth or none", r.ID, sv.Name)
		}
	}
	return nil
}

// inputNamePattern is a preset's input name, as a manifest names its
// inputs.
var inputNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]{0,63}$`)

// checkQuickAgents checks a KindQuickAgents value: at most MaxAssignments,
// one per release, each with a release reference, a version or
// VersionLatest, a mode, and a preset whose fields are each within the
// catalogue's own bounds for the setting it presets.
func (r Row) checkQuickAgents(s Setting) error {
	var list []Assignment
	if err := strictJSON(s.Value, &list); err != nil || list == nil {
		return fmt.Errorf("managed settings: %s must be a list of {\"ref\", \"version\", \"mode\", \"preset\", \"presetLocked\"}", r.ID)
	}
	if len(list) > MaxAssignments {
		return fmt.Errorf("managed settings: %s lists at most %d QuickAgents", r.ID, MaxAssignments)
	}
	seen := map[string]bool{}
	for _, a := range list {
		ns, name, ok := strings.Cut(a.Ref, "/")
		if !ok || !manifest.ValidNamespace(ns) || !manifest.ValidName(name) {
			return fmt.Errorf("managed settings: %s: %q is not a QuickAgent namespace/name", r.ID, a.Ref)
		}
		if seen[a.Ref] {
			return fmt.Errorf("managed settings: %s lists %s more than once", r.ID, a.Ref)
		}
		seen[a.Ref] = true
		if a.Version != VersionLatest && !versionPattern.MatchString(a.Version) {
			return fmt.Errorf("managed settings: %s: %s's version must be X.Y.Z or %s", r.ID, a.Ref, VersionLatest)
		}
		if a.Mode != AssignRequired && a.Mode != AssignOffered {
			return fmt.Errorf("managed settings: %s: %s's mode must be %s or %s", r.ID, a.Ref, AssignRequired, AssignOffered)
		}
		if a.Preset == nil {
			if a.PresetLocked {
				return fmt.Errorf("managed settings: %s: %s locks a preset it does not have", r.ID, a.Ref)
			}
			continue
		}
		if err := checkPreset(r.ID, a.Ref, *a.Preset); err != nil {
			return err
		}
	}
	return nil
}

// checkPreset holds each field of a preset to the row it presets.
func checkPreset(id, ref string, p Preset) error {
	bad := func(what string) error { return fmt.Errorf("managed settings: %s: %s's preset %s", id, ref, what) }
	if p.Model != nil {
		row, _ := Lookup(ModelDefault)
		if !slices.Contains(row.Values, p.Model.Provider) || !modelPattern.MatchString(p.Model.Model) {
			return bad(fmt.Sprintf("model must be {\"provider\": one of %s, \"model\": a model id}", strings.Join(row.Values, ", ")))
		}
	}
	for _, c := range []struct {
		row string
		n   int
	}{{RunTimeout, p.TimeoutSeconds}, {RunMaxTurns, p.MaxTurns}} {
		row, _ := Lookup(c.row)
		if c.n < 0 || float64(c.n) > row.Max {
			return bad(fmt.Sprintf("%s must be above 0 and at most %g", c.row, row.Max))
		}
	}
	if p.Where != "" {
		row, _ := Lookup(RunWhere)
		if !slices.Contains(row.Values, p.Where) {
			return bad("where must be one of " + strings.Join(row.Values, ", "))
		}
	}
	if len(p.Inputs) > MaxPresetInputs {
		return bad(fmt.Sprintf("sets at most %d inputs", MaxPresetInputs))
	}
	for k, v := range p.Inputs {
		if !inputNamePattern.MatchString(k) {
			return bad(fmt.Sprintf("names an input %q that is not an input name", k))
		}
		if len(v) > MaxInputBytes {
			return bad(fmt.Sprintf("input %s is over %d bytes", k, MaxInputBytes))
		}
	}
	return nil
}

// checkSource checks a KindSource value: a source of the row's, a provider
// only where the row names providers and only with organization-key, and a
// key reference exactly when the row delivers keys and the source is
// organization-key.
func (r Row) checkSource(s Setting) error {
	var v Source
	if err := strictJSON(s.Value, &v); err != nil || !slices.Contains(r.Values, v.Source) {
		return fmt.Errorf("managed settings: %s must be {\"source\": one of %s}", r.ID, strings.Join(r.Values, ", "))
	}
	org := v.Source == SourceOrganizationKey
	switch {
	case v.Provider != "" && (!org || !slices.Contains(r.Providers, v.Provider)):
		return fmt.Errorf("managed settings: %s names a provider only with %s, one of %s", r.ID, SourceOrganizationKey, strings.Join(r.Providers, ", "))
	case org && len(r.Providers) > 0 && v.Provider == "":
		return fmt.Errorf("managed settings: %s with %s names its provider, one of %s", r.ID, SourceOrganizationKey, strings.Join(r.Providers, ", "))
	case v.Key != nil && (!org || !r.Delivers):
		return fmt.Errorf("managed settings: %s carries a key reference only with %s on a row that delivers keys", r.ID, SourceOrganizationKey)
	case org && r.Delivers && v.Key == nil:
		return fmt.Errorf("managed settings: %s with %s names the organization's key", r.ID, SourceOrganizationKey)
	case v.Key != nil && (!keyIDPattern.MatchString(v.Key.ID) || v.Key.Rev < 1):
		return fmt.Errorf("managed settings: %s's key reference must be an id and a revision of at least 1", r.ID)
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
	case d.Schema != Schema && d.Schema != SchemaMembers:
		return fmt.Errorf("managed settings: schema %q, want %q or %q", d.Schema, Schema, SchemaMembers)
	case d.Schema == Schema && d.Members != nil:
		return fmt.Errorf("managed settings: a document of %q must not name members", Schema)
	case d.Schema == SchemaMembers && d.Members == nil:
		return fmt.Errorf("managed settings: a document of %q must name its members", SchemaMembers)
	case d.Registry == "":
		return errors.New("managed settings: no registry")
	case d.Org == "":
		return errors.New("managed settings: no organization")
	case d.Version < 1:
		return errors.New("managed settings: version must be at least 1")
	case d.IssuedAt.IsZero():
		return errors.New("managed settings: no issue time")
	}
	if d.Members != nil {
		if err := d.Members.validate(); err != nil {
			return err
		}
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
// Unknown: a newer registry may add rows. It does not check Registry, Org,
// Version or Members: the caller compares them with the registry it is
// signed in to, the organization it is a member of, the last version it
// accepted, and the account it is signed in as (For).
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
