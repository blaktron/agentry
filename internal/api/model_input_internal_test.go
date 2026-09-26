package api

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/blaktron/agentry/pkg/judge"
)

type askedOnce struct{ n int }

func (a *askedOnce) Model() string { return judge.DefaultModel }

func (a *askedOnce) Ask(context.Context, map[string]string, []judge.Question) (map[string]float64, judge.Usage, error) {
	a.n++
	return map[string]float64{}, judge.Usage{Requests: 1}, nil
}

// The pacer: a request that cannot start before its call's deadline is a
// timeout (its chunk not scanned, never passed); a cancelled call is
// cancelled, not a timeout; neither reaches the judge.
func TestPacedAskerFailsAsATimeoutOrACancellation(t *testing.T) {
	inner := &askedOnce{}
	lim := rate.NewLimiter(rate.Every(time.Hour), 1)
	p := &pacedAsker{asker: inner, lim: lim}
	if _, _, err := p.Ask(context.Background(), nil, nil); err != nil || inner.n != 1 {
		t.Fatalf("the first request is within the burst: %v, %d", err, inner.n)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, _, err := p.Ask(ctx, nil, nil); !errors.Is(err, context.DeadlineExceeded) || inner.n != 1 {
		t.Fatalf("a request that cannot start in time: %v, %d", err, inner.n)
	}
	gone, stop := context.WithCancel(context.Background())
	stop()
	if _, _, err := p.Ask(gone, nil, nil); !errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || inner.n != 1 {
		t.Fatalf("a cancelled call: %v, %d", err, inner.n)
	}
}
