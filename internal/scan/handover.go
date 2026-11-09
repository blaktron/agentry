package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/store"
	storegen "github.com/blaktron/agentry/internal/store/gen"
	"github.com/blaktron/agentry/pkg/keyhandover"
)

// RotationOptions say how a start on a new signing key treats the key it
// replaces.
type RotationOptions struct {
	// Registry is the registry's base URL, which a handover names.
	Registry string
	// Previous signs with the outgoing key, when the operator kept it for
	// this start. It hands the registry over to the new key.
	Previous Signer
	// WithoutHandover lets a new key replace the active one with no
	// handover: the outgoing key is lost or compromised, and every client
	// must re-pin deliberately.
	WithoutHandover bool
	// DevInstance is a registry in dev mode, which mints and swaps keys
	// freely: a new key with no handover is logged there, not refused.
	DevInstance bool
	// Now is the handover's time; time.Now when nil.
	Now func() time.Time
}

// ErrRotationWithoutHandover refuses a start on a new signing key that the
// active key has not handed over to.
var ErrRotationWithoutHandover = errors.New("scan: the signing key changed with no handover")

// RotateSigningKey records the signer's key as RegisterSigningKey does and,
// when it replaces the key the registry signed with until now, has the
// outgoing key hand over to it first. A start on the active key, the first
// start, and a key already handed over to do nothing more. A new key with
// no handover is refused unless opt.WithoutHandover or opt.DevInstance says
// why there is none, so a planned rotation cannot silently cost every
// client its trust in the new key. The refusal leaves the record as it was.
func RotateSigningKey(ctx context.Context, st *store.Store, signer Signer, opt RotationOptions, log *slog.Logger) (SigningKeyRegistration, error) {
	if st == nil {
		return SigningKeyRegistration{}, fmt.Errorf("scan: rotate signing key: no database")
	}
	if signer == nil {
		return SigningKeyRegistration{}, fmt.Errorf("scan: rotate signing key: no signer")
	}
	if log == nil {
		log = slog.Default()
	}
	q := st.Queries()
	active, err := q.GetActiveSigningKey(ctx)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return RegisterSigningKey(ctx, st, signer)
	case err != nil:
		return SigningKeyRegistration{}, fmt.Errorf("scan: read the active signing key: %w", err)
	case active.KeyID == signer.KeyID():
		return RegisterSigningKey(ctx, st, signer)
	}
	done, err := q.HasSigningKeyHandover(ctx, storegen.HasSigningKeyHandoverParams{FromKeyID: active.KeyID, ToKeyID: signer.KeyID()})
	if err != nil {
		return SigningKeyRegistration{}, fmt.Errorf("scan: read the signing key handovers: %w", err)
	}
	if done {
		return RegisterSigningKey(ctx, st, signer)
	}

	var env []byte
	switch {
	case opt.Previous != nil && opt.Previous.KeyID() == active.KeyID:
		env, err = signHandover(opt, active, signer)
		if err != nil {
			return SigningKeyRegistration{}, err
		}
	case opt.Previous != nil:
		return SigningKeyRegistration{}, fmt.Errorf("%w: the previous key configured is %s, but the key the registry signs with until now is %s", ErrRotationWithoutHandover, opt.Previous.KeyID(), active.KeyID)
	case opt.WithoutHandover, opt.DevInstance:
		log.Warn("scan: the signing key changed with no handover; every client that pinned the outgoing key must re-pin",
			"from", active.KeyID, "to", signer.KeyID())
	default:
		return SigningKeyRegistration{}, fmt.Errorf("%w: the registry signed with %s until now and this start signs with %s. "+
			"Keep the outgoing key for this start (signing.previousKeyFile or signing.previousKmsKeyARN) so it hands over to the new one, "+
			"or, when the outgoing key is lost or compromised, set signing.rotateWithoutHandover and tell clients to re-pin",
			ErrRotationWithoutHandover, active.KeyID, signer.KeyID())
	}

	reg, err := RegisterSigningKey(ctx, st, signer)
	if err != nil {
		return reg, err
	}
	if env != nil {
		n, err := q.InsertSigningKeyHandover(ctx, storegen.InsertSigningKeyHandoverParams{
			FromKeyID: active.KeyID, ToKeyID: signer.KeyID(), DsseEnvelope: env,
		})
		if err != nil {
			return reg, fmt.Errorf("scan: record the signing key handover: %w", err)
		}
		if n > 0 {
			log.Info("scan: signing key handed over", "from", active.KeyID, "to", signer.KeyID())
		}
	}
	return reg, nil
}

// signHandover has the outgoing key sign the statement naming the incoming
// one, and checks the signature against the outgoing key as the registry
// recorded it, so a previous key that is not the recorded one cannot vouch
// for anything.
func signHandover(opt RotationOptions, active storegen.SigningKey, signer Signer) ([]byte, error) {
	now := time.Now
	if opt.Now != nil {
		now = opt.Now
	}
	payload, err := keyhandover.Seal(keyhandover.Handover{
		Schema:   keyhandover.Schema,
		Registry: opt.Registry,
		From:     active.KeyID,
		To:       keyhandover.Key{KeyID: signer.KeyID(), Algorithm: keyhandover.Algorithm, PublicKeyPEM: signer.PublicKeyPEM()},
		At:       now().UTC().Truncate(time.Second),
	})
	if err != nil {
		return nil, fmt.Errorf("scan: signing key handover: %w", err)
	}
	sig, err := opt.Previous.SignPayload(keyhandover.PayloadType, payload)
	if err != nil {
		return nil, fmt.Errorf("scan: the outgoing key could not sign the handover: %w", err)
	}
	env := keyhandover.Wrap(payload, sig)
	if _, err := keyhandover.Open(env, active.PublicKeyPem); err != nil {
		return nil, fmt.Errorf("scan: the handover does not verify with the outgoing key on record: %w", err)
	}
	return json.Marshal(env)
}
