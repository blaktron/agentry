package api

// Idempotency-Key support for mutating POSTs (§9.1).
//
// The problem it solves is narrow and real: a client that retries a POST it
// never saw the response to must not create a second org, webhook, or ruleset
// release. The mechanism is a claim-then-record row keyed by
// (user, endpoint, key):
//
//   - first request under a key inserts the claim and runs the handler, then
//     records the status+body;
//   - a retry with the SAME request body replays the recorded response, or —
//     if the first attempt is still in flight — answers 409 rather than
//     racing it;
//   - a retry with a DIFFERENT body is a 409: the key is a promise about one
//     request, and silently returning some other request's answer would be
//     worse than an error.
//
// Keys are per user because the table is keyed on the caller: one tenant's
// key can never collide with, or read, another's.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"

	storegen "github.com/PLACEHOLDER_ORG/agentry/internal/store/gen"
)

const (
	idempotencyHeader = "Idempotency-Key"
	idempotencyMaxLen = 255
	// idempotencyTTL bounds how long a response is replayable. Long enough to
	// cover any realistic client retry schedule, short enough that the table
	// stays small.
	idempotencyTTL = 24 * time.Hour
)

// idempotency carries the state one guarded request needs to finish.
type idempotency struct {
	active   bool
	key      string
	endpoint string
	userID   uuid.UUID
	srv      *Server
	// body is the request body, buffered so the handler can still read it.
	done bool
}

// beginIdempotent inspects the Idempotency-Key header. It returns:
//
//	handled = true  → the response has already been written (replay or 409);
//	                  the caller must return immediately.
//	ik            → the guard to finish with ik.complete / ik.abandon.
//
// Requests without the header are unguarded and pass straight through, so the
// header stays opt-in exactly as §9.1 describes.
func (s *Server) beginIdempotent(w http.ResponseWriter, r *http.Request, endpoint string) (ik *idempotency, handled bool) {
	key := r.Header.Get(idempotencyHeader)
	if key == "" || s.st == nil {
		return &idempotency{}, false
	}
	if len(key) > idempotencyMaxLen {
		problemValidation(w, r, "Idempotency-Key must be at most 255 characters")
		return nil, true
	}
	p := principalFrom(r.Context())
	if p.Anonymous {
		// Nothing to key on; the route's own authz will refuse anyway.
		return &idempotency{}, false
	}

	hash, err := hashRequestBody(w, r)
	if err != nil {
		problemBadRequest(w, r, "could not read request body")
		return nil, true
	}

	row, err := s.q().ClaimIdempotencyKey(r.Context(), storegen.ClaimIdempotencyKeyParams{
		Key: key, UserID: p.UserID, Endpoint: endpoint, RequestHash: hash,
		ExpiresAt: time.Now().Add(idempotencyTTL),
	})
	if err != nil {
		s.log.Error("idempotency claim", "err", err, "endpoint", endpoint)
		problemInternal(w, r)
		return nil, true
	}
	if row.Claimed {
		return &idempotency{active: true, key: key, endpoint: endpoint, userID: p.UserID, srv: s}, false
	}

	// The key existed already.
	if row.RequestHash != hash {
		problemConflict(w, r, "this Idempotency-Key was already used with a different request body")
		return nil, true
	}
	if row.ResponseStatus == nil {
		problemConflict(w, r, "a request with this Idempotency-Key is still in flight")
		return nil, true
	}
	w.Header().Set("Idempotency-Replayed", "true")
	if len(row.ResponseBody) == 0 {
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(int(*row.ResponseStatus))
		return nil, true
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(int(*row.ResponseStatus))
	_, _ = w.Write(row.ResponseBody)
	return nil, true
}

// complete records the response so a retry replays it verbatim. body may be
// nil for status-only responses.
func (ik *idempotency) complete(r *http.Request, status int, body any) {
	if ik == nil || !ik.active || ik.done {
		return
	}
	ik.done = true
	var raw []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err == nil {
			raw = b
		}
	}
	st := int32(status)
	if err := ik.srv.q().CompleteIdempotencyKey(r.Context(), storegen.CompleteIdempotencyKeyParams{
		UserID: ik.userID, Endpoint: ik.endpoint, Key: ik.key,
		ResponseStatus: &st, ResponseBody: raw,
	}); err != nil {
		// A lost record only costs a client its replay; it never affects the
		// mutation, which already committed.
		ik.srv.log.Warn("idempotency record", "err", err, "endpoint", ik.endpoint)
	}
}

// abandon drops an unfinished claim so a failed attempt does not lock the key
// out for a day. Deferred by guarded handlers; complete() disarms it.
func (ik *idempotency) abandon(r *http.Request) {
	if ik == nil || !ik.active || ik.done {
		return
	}
	ik.done = true
	// The request's own context may already be cancelled by the time a
	// handler unwinds, so this cleanup detaches from it.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer cancel()
	if err := ik.srv.q().ReleaseIdempotencyKey(ctx, storegen.ReleaseIdempotencyKeyParams{
		UserID: ik.userID, Endpoint: ik.endpoint, Key: ik.key,
	}); err != nil {
		ik.srv.log.Warn("idempotency release", "err", err, "endpoint", ik.endpoint)
	}
}

// hashRequestBody buffers and hashes the body, leaving r.Body re-readable.
func hashRequestBody(w http.ResponseWriter, r *http.Request) (string, error) {
	if r.Body == nil {
		return hex.EncodeToString(sha256.New().Sum(nil)), nil
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		return "", err
	}
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(raw))
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
