// RFC 9457 problem+json helpers. Every non-2xx response the API emits
// goes through this file so the error contract can't drift per-handler.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/blaktron/agentry/internal/registry"
)

// ProblemTypeBase prefixes stable problem type URIs. The domain is a
// placeholder.
const ProblemTypeBase = "https://agentry.dev/problems/"

// FieldError describes one field-level validation failure.
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// problemBody is the wire shape; kept private so writers go through helpers.
type problemBody struct {
	Type     string       `json:"type"`
	Title    string       `json:"title"`
	Status   int          `json:"status"`
	Detail   string       `json:"detail,omitempty"`
	Instance string       `json:"instance,omitempty"`
	Errors   []FieldError `json:"errors,omitempty"`
}

func writeProblem(w http.ResponseWriter, r *http.Request, status int, slug, title, detail string, fields ...FieldError) {
	writeProblemWith(w, r, status, slug, title, detail, nil, fields...)
}

// writeProblemWith is writeProblem with RFC 9457 extension members: ext's
// keys land at the top level of the body beside the standard ones (an
// admission refusal's balance and reset date, say), so a client can render
// its own sentence without parsing detail. Standard members win a
// collision.
func writeProblemWith(w http.ResponseWriter, r *http.Request, status int, slug, title, detail string, ext map[string]any, fields ...FieldError) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	body := problemBody{
		Type:     ProblemTypeBase + slug,
		Title:    title,
		Status:   status,
		Detail:   detail,
		Instance: r.URL.Path,
		Errors:   fields,
	}
	var out any = body
	if len(ext) > 0 {
		m := make(map[string]any, len(ext)+6)
		for k, v := range ext {
			m[k] = v
		}
		raw, err := json.Marshal(body)
		if err == nil {
			var std map[string]any
			if json.Unmarshal(raw, &std) == nil {
				for k, v := range std {
					m[k] = v
				}
				out = m
			}
		}
	}
	if err := json.NewEncoder(w).Encode(out); err != nil {
		slog.WarnContext(r.Context(), "problem encode failed", "err", err)
	}
}

// sentence renders an error's text as a problem detail. Go errors are
// lowercase fragments and never end in punctuation (ST1005), while a detail
// is read verbatim as a sentence by the site's flash, the core's pages and
// the CLI — so the two registers meet here, at the API boundary, rather than
// in the packages that raise the error. It strips the domain sentinel's own
// prefix (ErrDenied wraps its reason, so the reader would otherwise see
// "registry: denied: …"), upper-cases the first rune, and ends the sentence.
// An empty message stays empty: problemNotFound and problemInternal say
// nothing on purpose.
func sentence(s string) string {
	s = strings.TrimSpace(s)
	if rest, cut := strings.CutPrefix(s, registry.ErrDenied.Error()); cut {
		s = strings.TrimSpace(strings.TrimPrefix(rest, ":"))
	}
	if s == "" {
		return ""
	}
	if r, size := utf8.DecodeRuneInString(s); unicode.ToUpper(r) != r {
		s = string(unicode.ToUpper(r)) + s[size:]
	}
	switch {
	case strings.HasSuffix(s, "."), strings.HasSuffix(s, "!"), strings.HasSuffix(s, "?"):
		return s
	}
	return s + "."
}

// Common problem writers. Add new slugs here, not inline in handlers.

func problemInternal(w http.ResponseWriter, r *http.Request) {
	writeProblem(w, r, http.StatusInternalServerError, "internal", "Internal server error", "")
}

func problemNotFound(w http.ResponseWriter, r *http.Request) {
	writeProblem(w, r, http.StatusNotFound, "not-found", "Not found", "")
}

func problemValidation(w http.ResponseWriter, r *http.Request, detail string, fields ...FieldError) {
	writeProblem(w, r, http.StatusUnprocessableEntity, "validation", "Validation error", detail, fields...)
}

func problemBadRequest(w http.ResponseWriter, r *http.Request, detail string) {
	writeProblem(w, r, http.StatusBadRequest, "bad-request", "Bad request", detail)
}

func problemUnauthorized(w http.ResponseWriter, r *http.Request, detail string) {
	writeProblem(w, r, http.StatusUnauthorized, "unauthorized", "Authentication required", detail)
}

func problemForbidden(w http.ResponseWriter, r *http.Request, detail string) {
	writeProblem(w, r, http.StatusForbidden, "forbidden", "Access denied", detail)
}

func problemConflict(w http.ResponseWriter, r *http.Request, detail string) {
	writeProblem(w, r, http.StatusConflict, "conflict", "Conflict", detail)
}

func problemTooMany(w http.ResponseWriter, r *http.Request, detail string) {
	writeProblem(w, r, http.StatusTooManyRequests, "rate-limited", "Too many requests", detail)
}

func problemGone(w http.ResponseWriter, r *http.Request, detail string) {
	writeProblem(w, r, http.StatusGone, "gone", "No longer available", detail)
}

// problemAdmissionRefused answers a registry admission refusal with the refusal's own status and slug — 402
// credits-exhausted from the billing extension, which says so explicitly —
// and its fields at top level. A refusal that names no status is a 403
// admission-refused: "payment required" is a claim an extension makes,
// never a default.
func problemAdmissionRefused(w http.ResponseWriter, r *http.Request, ref registry.Refusal) {
	status, slug, title := ref.Status, ref.Slug, ref.Title
	if status == 0 {
		status = http.StatusForbidden
	}
	if slug == "" {
		slug = "admission-refused"
	}
	if title == "" {
		title = "Submission refused"
	}
	writeProblemWith(w, r, status, slug, title, sentence(ref.Detail), ref.Fields)
}

// problemPrivateAgentCap answers the namespace's private-agent cap: a 422 with its own slug, so a client can offer
// the upgrade rather than a generic validation message.
func problemPrivateAgentCap(w http.ResponseWriter, r *http.Request) {
	writeProblem(w, r, http.StatusUnprocessableEntity, "private-agent-cap",
		"Private agent cap reached",
		"This namespace holds as many private agents as its subscription tier allows. Make one public, or upgrade the account.")
}

// The organization problems. Each has its own slug so a client can offer the right next step
// rather than parse a sentence.

// problemLastAdmin refuses the demotion or removal of an organization's
// last admin: the org must first have another one, and only a decommission
// removes the last.
func problemLastAdmin(w http.ResponseWriter, r *http.Request, org string) {
	writeProblem(w, r, http.StatusConflict, "last-admin", "The last admin stays",
		"This organization must keep at least one admin. Make another member of "+org+" an admin first.")
}

// problemEmailUnverified refuses an act that needs a verified address —
// creating an organization, which is keyed on the creator's domain.
func problemEmailUnverified(w http.ResponseWriter, r *http.Request, detail string) {
	writeProblem(w, r, http.StatusForbidden, "email-unverified", "Verify your email address", detail)
}

// problemOrgPending refuses a second organization while one the account
// created is still awaiting payment.
func problemOrgPending(w http.ResponseWriter, r *http.Request, org string) {
	writeProblem(w, r, http.StatusConflict, "org-pending", "An organization is awaiting payment",
		"This account already created "+org+", which is awaiting payment. Complete its subscription, or let it lapse, before creating another.")
}

// problemSeatAllowance refuses an invitation or an approval past the
// organization's seats. The counts ride at the top level
// so a console can say "24 of 25 used, 1 invited" without parsing a
// sentence; nothing is removed when it is answered.
func problemSeatAllowance(w http.ResponseWriter, r *http.Request, org string, seats *registry.Seats) {
	detail := "The " + org + " organization holds as many seats as its subscription allows. Free a seat, or add seats to the subscription, then try again."
	if seats == nil {
		// The counts could not be read. Saying nothing beats saying zero:
		// max 0 means "unbounded" to every client of this schema, which is
		// the opposite of what this refusal means.
		writeProblem(w, r, http.StatusForbidden, "seat-allowance", "No seat available", detail)
		return
	}
	writeProblemWith(w, r, http.StatusForbidden, "seat-allowance", "No seat available", detail,
		map[string]any{"used": seats.Used, "invited": seats.Invited, "pending": seats.Pending, "max": seats.Max})
}

// problemUploadTooLarge refuses a body over its cap, with the same slug the
// release upload uses: one meaning, one slug, wherever a client meets it.
func problemUploadTooLarge(w http.ResponseWriter, r *http.Request, detail string) {
	writeProblem(w, r, http.StatusRequestEntityTooLarge, "upload-too-large", "Upload too large", detail)
}

// problemUnsupportedImage refuses an image the registry will not serve:
// not a raster the standard library decodes, or not one this route
// admits. SVG in particular — there is no sanitiser for it here and there
// will not be one by accident.
func problemUnsupportedImage(w http.ResponseWriter, r *http.Request, detail string) {
	writeProblem(w, r, http.StatusUnsupportedMediaType, "unsupported-image", "Not a PNG or JPEG", detail)
}

// problemAgentUnscanned refuses making a QuickAgent public while it holds
// versions admitted unscanned that are published, or could be again from
// quarantine: only a version that passed the gate is ever public.
// The count travels as `unscanned` beside the words.
func problemAgentUnscanned(w http.ResponseWriter, r *http.Request, standing int64) {
	detail := "One version of this QuickAgent was admitted unscanned and stands published, quarantined or blocked. Yank it, then make the QuickAgent public: only a version that passed the gate is ever public."
	if standing != 1 {
		detail = fmt.Sprintf("%d versions of this QuickAgent were admitted unscanned and stand published, quarantined or blocked. Yank them, then make the QuickAgent public: only a version that passed the gate is ever public.", standing)
	}
	writeProblemWith(w, r, http.StatusConflict, "agent-unscanned", "Unscanned versions cannot be made public", detail, map[string]any{"unscanned": standing})
}

// problemForkStaysPrivate refuses making a fork public:
// a fork is private for good, to keep Publisher Earnings with the
// QuickAgent's own publisher.
func problemForkStaysPrivate(w http.ResponseWriter, r *http.Request) {
	writeProblem(w, r, http.StatusConflict, "fork-stays-private", "A fork stays private",
		"A fork of a QuickAgent is private for good, so it cannot be made public. Its origin's publisher keeps the public QuickAgent.")
}

// problemAgentRetired refuses a write a retired agent does not take:
// a submission, or being made public other than by Restore.
func problemAgentRetired(w http.ResponseWriter, r *http.Request) {
	writeProblem(w, r, http.StatusConflict, "agent-retired", "This QuickAgent is retired",
		"A retired QuickAgent takes no new versions and stays private. Restore it first.")
}

// problemFeatureNotIncluded refuses an act the subscription — the
// organization's, or a person's own — does not include at
// all, distinct from its allowance being reached. detail names whose.
func problemFeatureNotIncluded(w http.ResponseWriter, r *http.Request, detail string) {
	writeProblem(w, r, http.StatusForbidden, "feature-not-included", "Not included in this subscription", detail)
}

// problemAlreadyAMember refuses an invitation, an approval or a creation
// for someone who is already an active member of another organization
// (one organization per person). detail says whose membership it is.
func problemAlreadyAMember(w http.ResponseWriter, r *http.Request, detail string) {
	writeProblem(w, r, http.StatusConflict, "already-a-member", "Already in an organization", detail)
}

// alreadyAMemberDetail is the sentence for the doors an admin drives.
const alreadyAMemberDetail = "That person is already a member of another organization. A person belongs to one organization at a time; they leave the other first."

// alreadyAMemberCreatorDetail is the sentence for the door a person opens
// for themselves: creating an organization while belonging to one.
const alreadyAMemberCreatorDetail = "This account is already a member of an organization. A person belongs to one organization at a time: leave it before creating another."

// problemDomainClaimed refuses an organization at a domain another one
// holds (one organization per domain). It names the holder,
// whose handle is public, so the person can ask its administrators — the
// site's sign-up page and GET /user/domain-org say the same thing.
func problemDomainClaimed(w http.ResponseWriter, r *http.Request, domain, org, displayName string) {
	writeProblemWith(w, r, http.StatusConflict, "domain-claimed", "That domain belongs to an organization",
		domain+" is registered to "+orgLabel(org, displayName)+" on this registry. Its administrators can add you; ask them, or verify a different domain.",
		map[string]any{"domain": domain, "org": org})
}

// orgLabel names an organization for a sentence: its display name with the
// handle in brackets, or the handle alone when they are the same or the
// name is empty.
func orgLabel(handle, displayName string) string {
	if displayName != "" && displayName != handle {
		return displayName + " (" + handle + ")"
	}
	return handle
}

// problemOrgDecommissioning refuses a change to an organization in its
// decommission hold: reads and exports go on, nothing else, until
// the erasure at the hold's end.
func problemOrgDecommissioning(w http.ResponseWriter, r *http.Request, org string, until *time.Time) {
	detail := "The " + org + " organization is being decommissioned and is read-only: its members can still read its agents and export its audit log, and nothing else changes."
	ext := map[string]any{"org": org}
	if until != nil {
		detail += " It is erased on " + until.UTC().Format("2 January 2006") + "."
		ext["decommissionAt"] = until.UTC().Format(time.RFC3339)
	}
	writeProblemWith(w, r, http.StatusConflict, "org-decommissioning", "Organization being decommissioned", detail, ext)
}

// orgGateProblem answers a refusal from registry.OrgGate and reports
// whether it wrote one: a suspended (or erased) organization answers as
// absent, the way its own lookup does; a decommissioning one names the
// hold. Any other error is not this function's.
func (s *Server) orgGateProblem(w http.ResponseWriter, r *http.Request, org string, err error) bool {
	var gate *registry.OrgGateError
	if !errors.As(err, &gate) {
		return false
	}
	if gate.State == registry.OrgStateDecommissioning {
		problemOrgDecommissioning(w, r, org, gate.DecommissionAt)
		return true
	}
	problemNotFound(w, r)
	return true
}

func problemUnavailable(w http.ResponseWriter, r *http.Request, detail string) {
	writeProblem(w, r, http.StatusServiceUnavailable, "unavailable", "Service unavailable", detail)
}
