// Package voice is the registry's store of Writing Voices (plan
// writing-voice.md §4, §7; agentry#809): the one VOICE.md a person keeps in
// Agentry, the instructions a run follows for how it writes and nothing
// else (DR-56). A person has at most three versions of it: the live one, a
// pending one (in review, or flagged with its findings) and the previous
// one, for Restore (D13). Each is sealed at rest under a data key of the
// voice's own, wrapped for the person by the knowledge store's key wrapper
// (D2), and a version goes live only when AI Review passed it: the pack
// scan's rule stages over the text and Jev's voice question set (D7). A
// judge that cannot answer leaves the version in review, retried; nothing
// goes live unreviewed.
//
// A voice is not a knowledge pack: no name, no tree, no listing, one a
// person, and it is the one attached text that is instruction-shaped. The
// open core carries the whole object and its review; the SecureAgentry
// build adds the hosted Voice Writer, its price and the charge for a
// review (pkg/extension AdmitsVoice, Voice).
package voice

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/blaktron/agentry/pkg/judge"
)

// MaxBytes caps a VOICE.md (D3): the most AI Review reads in its one
// request, so a voice is never cut. The CLI holds the same cap
// (agentry-cli pkg/voice).
const MaxBytes = judge.VoiceMaxBytes

// File is the voice's one file, the name AI Review's report places
// findings in.
const File = "VOICE.md"

// Source is how a version came to be.
type Source string

// The sources a version can have (§4): the Voice Writer run In Agentry
// (build: Create or Improve; ai-edit), the person's own text saved on the
// web (edit) or sent from a client (upload), and the previous version put
// back under a question set it was not reviewed by (restore).
const (
	SourceBuild   Source = "build"
	SourceAIEdit  Source = "ai-edit"
	SourceEdit    Source = "edit"
	SourceUpload  Source = "upload"
	SourceRestore Source = "restore"
)

// Valid says whether s is a source a version may have.
func (s Source) Valid() bool {
	switch s {
	case SourceBuild, SourceAIEdit, SourceEdit, SourceUpload, SourceRestore:
		return true
	}
	return false
}

// Slot is where a version sits.
type Slot string

// The three slots (D13).
const (
	SlotLive     Slot = "live"
	SlotPending  Slot = "pending"
	SlotPrevious Slot = "previous"
)

// ReviewState is where a version is in its review: a pending version is
// reviewing or flagged; a live or previous one passed.
type ReviewState string

// The review states.
const (
	ReviewReviewing ReviewState = "reviewing"
	ReviewFlagged   ReviewState = "flagged"
	ReviewPassed    ReviewState = "passed"
)

var (
	// ErrNotFound is a person with no voice, or no version in the slot
	// asked for.
	ErrNotFound = errors.New("voice: no such voice")
	// ErrUnconfigured is a deployment that keeps no voices: no key
	// wrapper (the knowledge store is off) or no judge to review them.
	ErrUnconfigured = errors.New("voice: the voice store is off")
	// ErrTooLarge is a voice past MaxBytes.
	ErrTooLarge = fmt.Errorf("voice: a Writing Voice is at most %d KiB", MaxBytes>>10)
	// ErrNoPrevious is a Restore with no previous version.
	ErrNoPrevious = errors.New("voice: there is no previous version to restore")
)

// InvalidError is text that is not a voice, and why.
type InvalidError struct{ Reason string }

func (e *InvalidError) Error() string { return "voice: " + e.Reason }

// Check holds text to the format the CLI holds it to: UTF-8 Markdown with
// something in it, no NUL, at most MaxBytes.
func Check(text []byte) error {
	switch {
	case len(text) > MaxBytes:
		return ErrTooLarge
	case len(bytes.TrimSpace(text)) == 0:
		return &InvalidError{Reason: "a Writing Voice is empty"}
	case !utf8.Valid(text):
		return &InvalidError{Reason: "a Writing Voice is not UTF-8 text"}
	case bytes.IndexByte(text, 0) >= 0:
		return &InvalidError{Reason: "a Writing Voice holds a NUL byte, which text does not"}
	}
	return nil
}

// Digest is text's digest, "sha256:<hex>", as the CLI computes it.
func Digest(text []byte) string {
	sum := sha256.Sum256(text)
	return "sha256:" + hex.EncodeToString(sum[:])
}
