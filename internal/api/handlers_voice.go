package api

// The Writing Voice: the one
// VOICE.md a person keeps in Agentry. Every route is the caller's own: a
// voice is found by its owner, and nobody else's is reachable. A version
// put here is pending until AI Review passes it; the review runs on the
// worker (internal/voice).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/registry"
	"github.com/blaktron/agentry/internal/voice"
)

// VoiceAdmission is a version a route is about to store for review: whose,
// from where, and its size.
type VoiceAdmission struct {
	User   uuid.UUID
	Source voice.Source
	Bytes  int
}

// VoiceAdmitter is the seam through which an extension admits a review a
// route asks for, and may charge for it (pkg/extension AdmitsVoice;
// one credit an operation): an edit
// saved, a client's upload, a Restore of a version reviewed under another
// question set. A build's own output reaches the store through the
// extension's door (Voice.Propose) and is never admitted here. The core
// has none, and admits every call.
type VoiceAdmitter interface {
	// AdmitVoice returns a ticket, or a Refusal the route answers in its
	// own status and words. An error is "unknown": the route fails closed
	// with 503 and stores nothing.
	AdmitVoice(ctx context.Context, a VoiceAdmission) (registry.Ticket, *registry.Refusal, error)
	// VoidVoice cancels a ticket the core could not honour: nothing was
	// stored. It must be idempotent. A void can fail or never be called (a
	// crash between the admission and the store): the core records each
	// ticket it stored in admitted_stores, in the storing transaction, so a
	// ticket with no row there stored nothing.
	VoidVoice(ctx context.Context, t registry.Ticket) error
}

type voiceAdmission struct {
	mu       sync.RWMutex
	admitter VoiceAdmitter
}

// SetVoiceAdmitter sets the extension that admits a voice's review.
func (s *Server) SetVoiceAdmitter(a VoiceAdmitter) {
	s.voiceAdmit.mu.Lock()
	defer s.voiceAdmit.mu.Unlock()
	s.voiceAdmit.admitter = a
}

func (s *Server) voiceAdmitter() VoiceAdmitter {
	s.voiceAdmit.mu.RLock()
	defer s.voiceAdmit.mu.RUnlock()
	return s.voiceAdmit.admitter
}

// Voice is the voice store, for an extension that builds on it.
func (s *Server) Voice() *voice.Service { return s.voice }

// SetVoiceJudge replaces the judge the voice review asks (a test's stub).
func (s *Server) SetVoiceJudge(j voice.Judge) {
	if s.voice != nil {
		s.voice.SetJudge(j)
	}
}

// voiceProblem answers a store error in the store's words.
func (s *Server) voiceProblem(w http.ResponseWriter, r *http.Request, err error, what string) {
	var invalid *voice.InvalidError
	switch {
	case errors.Is(err, voice.ErrUnconfigured):
		writeProblem(w, r, http.StatusServiceUnavailable, "voice-unconfigured", "Voice store off",
			"This registry keeps no Writing Voices: it has no key to seal them with, or no AI Review judge to review them.")
	case errors.Is(err, voice.ErrNotFound):
		writeProblem(w, r, http.StatusNotFound, "voice-not-found", "No voice",
			"There is no Writing Voice, or no version of it, of that kind here.")
	case errors.Is(err, voice.ErrTooLarge):
		writeProblem(w, r, http.StatusRequestEntityTooLarge, "voice-too-large", "Voice too large",
			fmt.Sprintf("A Writing Voice is at most %d KiB.", voice.MaxBytes>>10))
	case errors.As(err, &invalid):
		writeProblem(w, r, http.StatusUnprocessableEntity, "voice-invalid", "Not a Writing Voice", sentence(invalid.Reason)+".")
	case errors.Is(err, voice.ErrNoPrevious):
		writeProblem(w, r, http.StatusConflict, "voice-no-previous", "No previous version",
			"There is no previous version of this voice to restore.")
	case errors.Is(err, voice.ErrRestoreNeedsReview):
		writeProblem(w, r, http.StatusConflict, "voice-restore-changed", "Restore changed",
			"AI Review's questions changed while the restore was asked for. Ask again.")
	default:
		s.log.ErrorContext(r.Context(), what, "err", err)
		problemInternal(w, r)
	}
}

// voiceToAPI is a voice as the API shows it.
func (s *Server) voiceToAPI(st voice.State) (Voice, error) {
	out := Voice{AlwaysAttach: st.AlwaysAttach, QuestionSet: s.voice.QuestionSet(), UpdatedAt: st.UpdatedAt}
	for _, slot := range []struct {
		v   *voice.Version
		dst **VoiceVersion
	}{{st.Live, &out.Live}, {st.Pending, &out.Pending}, {st.Previous, &out.Previous}} {
		if slot.v == nil {
			continue
		}
		v, err := voiceVersionToAPI(slot.v)
		if err != nil {
			return out, err
		}
		*slot.dst = &v
	}
	return out, nil
}

func voiceVersionToAPI(v *voice.Version) (VoiceVersion, error) {
	out := VoiceVersion{
		Id: v.ID, Slot: VoiceVersionSlot(v.Slot), Review: VoiceVersionReview(v.ReviewState), Source: VoiceVersionSource(v.Source),
		Digest: v.Digest, Bytes: v.Bytes, Text: string(v.Text), QuestionSet: v.QuestionSet,
		CreatedAt: v.CreatedAt, ReviewedAt: v.ReviewedAt,
	}
	if v.Report != nil {
		// The report is the store's own type; the API's is the same shape,
		// generated from the spec, so one is read into the other.
		raw, err := json.Marshal(v.Report)
		if err != nil {
			return out, fmt.Errorf("voice: the review report of %s: %w", v.ID, err)
		}
		var rep VoiceReviewReport
		if err := json.Unmarshal(raw, &rep); err != nil {
			return out, fmt.Errorf("voice: the review report of %s is not the API's shape: %w", v.ID, err)
		}
		out.Report = &rep
	}
	return out, nil
}

func (s *Server) writeVoice(w http.ResponseWriter, r *http.Request, status int, st voice.State) {
	out, err := s.voiceToAPI(st)
	if err != nil {
		s.voiceProblem(w, r, err, "voice report")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, out)
}

// admitVoice asks the extension, if any, to admit a review. It writes the
// refusal or the failure itself and answers false; with true, ticket is
// the admission the store records with the version, and release voids it
// when nothing was stored.
func (s *Server) admitVoice(w http.ResponseWriter, r *http.Request, a VoiceAdmission) (ticket string, release func(stored bool), ok bool) {
	adm := s.voiceAdmitter()
	if adm == nil {
		return "", func(bool) {}, true
	}
	t, refusal, err := adm.AdmitVoice(r.Context(), a)
	switch {
	case err != nil:
		s.log.ErrorContext(r.Context(), "voice: admission unavailable", "err", err)
		writeProblem(w, r, http.StatusServiceUnavailable, "admission-unavailable", "Review not admitted",
			"The registry could not check whether this account may have a voice reviewed. Nothing was stored; retry shortly.")
		return "", nil, false
	case refusal != nil:
		problemAdmissionRefused(w, r, *refusal)
		return "", nil, false
	}
	return t.ID, func(stored bool) {
		if stored || t.ID == "" {
			return
		}
		if err := adm.VoidVoice(context.WithoutCancel(r.Context()), t); err != nil {
			s.log.ErrorContext(r.Context(), "voice: void an admission", "ticket", t.ID, "err", err)
		}
	}, true
}

// GetVoice implements GET /voice.
func (s *Server) GetVoice(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActVoiceRead, uuid.Nil) {
		return
	}
	st, err := s.voice.Get(r.Context(), principalFrom(r.Context()).UserID)
	if err != nil {
		s.voiceProblem(w, r, err, "get voice")
		return
	}
	s.writeVoice(w, r, http.StatusOK, st)
}

// PutVoice implements PUT /voice: a new version, pending until reviewed.
func (s *Server) PutVoice(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActVoiceWrite, uuid.Nil) {
		return
	}
	var body PutVoiceRequest
	if !readJSON(w, r, &body) {
		return
	}
	src := voice.Source(body.Source)
	if src != voice.SourceEdit && src != voice.SourceUpload {
		problemValidation(w, r, "The registry refused the voice.", FieldError{Field: "source", Message: "Must be edit or upload."})
		return
	}
	text := []byte(body.Text)
	// Refuse what cannot be stored before anything is admitted or charged.
	if !s.voice.Configured() {
		s.voiceProblem(w, r, voice.ErrUnconfigured, "put voice")
		return
	}
	if err := voice.Check(text); err != nil {
		s.voiceProblem(w, r, err, "put voice")
		return
	}
	user := principalFrom(r.Context()).UserID
	ticket, release, ok := s.admitVoice(w, r, VoiceAdmission{User: user, Source: src, Bytes: len(text)})
	if !ok {
		return
	}
	st, err := s.voice.PutAdmitted(r.Context(), user, text, src, ticket)
	release(err == nil)
	if err != nil {
		s.voiceProblem(w, r, err, "put voice")
		return
	}
	s.writeVoice(w, r, http.StatusAccepted, st)
}

// RestoreVoice implements POST /voice/restore.
func (s *Server) RestoreVoice(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActVoiceWrite, uuid.Nil) {
		return
	}
	user := principalFrom(r.Context()).UserID
	review, err := s.voice.RestoreNeedsReview(r.Context(), user)
	if err != nil {
		s.voiceProblem(w, r, err, "restore voice")
		return
	}
	ticket, release := "", func(bool) {}
	if review {
		var ok bool
		if ticket, release, ok = s.admitVoice(w, r, VoiceAdmission{User: user, Source: voice.SourceRestore}); !ok {
			return
		}
	}
	st, err := s.voice.RestoreAdmitted(r.Context(), user, review, ticket)
	release(err == nil)
	if err != nil {
		s.voiceProblem(w, r, err, "restore voice")
		return
	}
	status := http.StatusOK
	if review {
		status = http.StatusAccepted
	}
	s.writeVoice(w, r, status, st)
}

// DiscardVoicePending implements DELETE /voice/pending.
func (s *Server) DiscardVoicePending(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActVoiceWrite, uuid.Nil) {
		return
	}
	st, err := s.voice.DiscardPending(r.Context(), principalFrom(r.Context()).UserID)
	if err != nil {
		s.voiceProblem(w, r, err, "discard pending voice")
		return
	}
	s.writeVoice(w, r, http.StatusOK, st)
}

// UpdateVoiceSettings implements PUT /voice/settings; a field not sent
// keeps its value.
func (s *Server) UpdateVoiceSettings(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActVoiceWrite, uuid.Nil) {
		return
	}
	var body VoiceSettingsRequest
	if !readJSON(w, r, &body) {
		return
	}
	user := principalFrom(r.Context()).UserID
	var (
		st  voice.State
		err error
	)
	if body.AlwaysAttach != nil {
		st, err = s.voice.SetAlwaysAttach(r.Context(), user, *body.AlwaysAttach)
	} else {
		st, err = s.voice.Get(r.Context(), user)
	}
	if err != nil {
		s.voiceProblem(w, r, err, "voice settings")
		return
	}
	s.writeVoice(w, r, http.StatusOK, st)
}

// DeleteVoice implements DELETE /voice.
func (s *Server) DeleteVoice(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ActVoiceWrite, uuid.Nil) {
		return
	}
	if err := s.voice.Delete(r.Context(), principalFrom(r.Context()).UserID); err != nil {
		s.voiceProblem(w, r, err, "delete voice")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
