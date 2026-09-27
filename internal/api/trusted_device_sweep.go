package api

import (
	"context"

	"github.com/blaktron/agentry/internal/queue"
)

// JobTrustedDeviceSweep removes remembered browsers past their expiry
// (agentry#464). The worker role enqueues it hourly and once at start
// (pkg/extension/agentryd.go), like the decommission sweep.
const JobTrustedDeviceSweep = "trusted_device.sweep"

// registerTrustedDeviceSweep wires the sweep onto a queue worker.
func (s *Server) registerTrustedDeviceSweep(q queue.Client) {
	if q == nil {
		return
	}
	q.Register(JobTrustedDeviceSweep, func(ctx context.Context, _ queue.Job) error {
		_, err := s.RunTrustedDeviceSweep(ctx)
		return err
	})
}

// RunTrustedDeviceSweep deletes every remembered-browser record past its own
// expiry and reports how many it deleted. Expired records are already inert,
// since every lookup filters on expiry; the sweep is what removes the
// address and the user agent they still hold, so a table of browsers does
// not grow for ever. Exported for the tests and for an operator's hand-run.
// A run with nothing to delete is the common case and does nothing.
func (s *Server) RunTrustedDeviceSweep(ctx context.Context) (int64, error) {
	if s.st == nil {
		return 0, nil
	}
	n, err := s.q().DeleteExpiredTrustedDevices(ctx)
	if err != nil {
		return 0, err
	}
	if n > 0 {
		s.log.InfoContext(ctx, "remembered browsers: expired records deleted", "count", n)
	}
	return n, nil
}
