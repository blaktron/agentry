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

// Row is one entry of the catalogue.
type Row struct {
	// ID is the setting's name in a document.
	ID string
	// Values are the values the row takes, from the most open to the most
	// restrictive.
	Values []string
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
)

// Values of UnsafeMode.
const (
	UnsafeModeAllowed   = "allowed"
	UnsafeModeForbidden = "forbidden"
)

var catalogue = []Row{
	{
		ID:      UnsafeMode,
		Values:  []string{UnsafeModeAllowed, UnsafeModeForbidden},
		Summary: "Whether members may turn on Unsafe Mode for local runs.",
	},
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
		v := settings[id].String()
		if !slices.Contains(row.Values, v) {
			return fmt.Errorf("managed settings: %s must be one of %s", id, strings.Join(row.Values, ", "))
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
