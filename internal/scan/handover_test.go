package scan_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/blaktron/agentry/internal/scan"
	storegen "github.com/blaktron/agentry/internal/store/gen"
	"github.com/blaktron/agentry/pkg/keyhandover"
)

const handoverRegistry = "https://registry.example"

// A planned rotation is handed over by the outgoing key: the handover is
// recorded once, verifies with the outgoing key as recorded, and a client
// that pinned the outgoing key adopts the new one from the chain. A new key
// with no handover is refused and leaves the record as it was, unless the
// operator says the outgoing key is lost; a previous key that is not the
// active one hands over nothing.
func TestRotateSigningKeyHandsOverOrRefuses(t *testing.T) {
	e := newPipeEnv(t)
	ctx := context.Background()
	a, _ := scan.NewFileSigner("", true)
	b, _ := scan.NewFileSigner("", true)
	c, _ := scan.NewFileSigner("", true)
	stranger, _ := scan.NewFileSigner("", true)
	at := func() time.Time { return time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC) }
	opts := func(prev scan.Signer) scan.RotationOptions {
		return scan.RotationOptions{Registry: handoverRegistry, Previous: prev, Now: at}
	}
	active := func() string {
		t.Helper()
		k, err := e.st.Queries().GetActiveSigningKey(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return k.KeyID
	}
	chain := func() keyhandover.Chain {
		t.Helper()
		rows, err := e.st.Queries().ListSigningKeyHandovers(ctx)
		if err != nil {
			t.Fatal(err)
		}
		out := keyhandover.Chain{Registry: handoverRegistry}
		for _, r := range rows {
			var env keyhandover.Envelope
			if err := json.Unmarshal(r.DsseEnvelope, &env); err != nil {
				t.Fatal(err)
			}
			out.Handovers = append(out.Handovers, env)
		}
		return out
	}

	// The first start has nothing to hand over from.
	if _, err := scan.RotateSigningKey(ctx, e.st, a, opts(nil), nil); err != nil {
		t.Fatalf("first start: %v", err)
	}
	if _, err := scan.RotateSigningKey(ctx, e.st, a, opts(nil), nil); err != nil {
		t.Fatalf("a restart on the same key: %v", err)
	}

	// A new key with no handover is refused, and so is one whose previous
	// key is not the active one; neither changes the record.
	if _, err := scan.RotateSigningKey(ctx, e.st, b, opts(nil), nil); !errors.Is(err, scan.ErrRotationWithoutHandover) {
		t.Fatalf("a rotation with no previous key: %v", err)
	}
	if _, err := scan.RotateSigningKey(ctx, e.st, b, opts(stranger), nil); !errors.Is(err, scan.ErrRotationWithoutHandover) {
		t.Fatalf("a rotation whose previous key was never active: %v", err)
	}
	if active() != a.KeyID() || len(chain().Handovers) != 0 {
		t.Fatalf("a refused rotation changed the record: active %s, %d handovers", active(), len(chain().Handovers))
	}

	// The outgoing key hands over; a restart on the new key adds nothing.
	reg, err := scan.RotateSigningKey(ctx, e.st, b, opts(a), nil)
	if err != nil || !reg.New || active() != b.KeyID() {
		t.Fatalf("a handed-over rotation: %+v %v, active %s", reg, err, active())
	}
	if _, err := scan.RotateSigningKey(ctx, e.st, b, opts(a), nil); err != nil {
		t.Fatalf("a restart after the handover: %v", err)
	}
	if _, err := scan.RotateSigningKey(ctx, e.st, b, opts(nil), nil); err != nil {
		t.Fatalf("a restart on the new key without the previous one: %v", err)
	}
	ch := chain()
	if len(ch.Handovers) != 1 {
		t.Fatalf("%d handovers recorded, want 1", len(ch.Handovers))
	}
	h, err := keyhandover.Open(ch.Handovers[0], a.PublicKeyPEM())
	if err != nil || h.From != a.KeyID() || h.To.KeyID != b.KeyID() || h.Registry != handoverRegistry || !h.At.Equal(at()) {
		t.Fatalf("the recorded handover: %+v %v", h, err)
	}

	// A lost outgoing key: the operator says so, and the rotation goes
	// ahead with no handover, so a client that pinned b cannot adopt c.
	if _, err := scan.RotateSigningKey(ctx, e.st, c, scan.RotationOptions{Registry: handoverRegistry, WithoutHandover: true}, nil); err != nil {
		t.Fatalf("a rotation without a handover, by the operator's word: %v", err)
	}
	got, err := keyhandover.Follow(handoverRegistry, []keyhandover.Key{{KeyID: a.KeyID(), PublicKeyPEM: a.PublicKeyPEM()}}, chain(), nil)
	if err != nil || len(got) != 1 || got[0].To.KeyID != b.KeyID() {
		t.Fatalf("a client that pinned a adopts %+v %v, want b alone", got, err)
	}
	if n, _ := e.st.Queries().HasSigningKeyHandover(ctx, storegen.HasSigningKeyHandoverParams{FromKeyID: b.KeyID(), ToKeyID: c.KeyID()}); n {
		t.Fatal("a rotation without a handover recorded one")
	}

	// A dev instance swaps keys freely: no handover, and no refusal.
	d, _ := scan.NewFileSigner("", true)
	if _, err := scan.RotateSigningKey(ctx, e.st, d, scan.RotationOptions{Registry: handoverRegistry, DevInstance: true}, nil); err != nil {
		t.Fatalf("a dev instance's new key: %v", err)
	}
}
