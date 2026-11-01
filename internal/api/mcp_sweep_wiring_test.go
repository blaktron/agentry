package api_test

import (
	"testing"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
)

// The production wiring must reach the sweep, not only S7: a sweep that
// reports "no vulnerability database configured" while S7 has one is a
// wiring fault.
func TestMCPSweepWiringReachesThePipeline(t *testing.T) {
	var srv *api.Server
	env := newTestEnvCfg(t, func(c *config.Config) { c.Scan.OSVURL = "https://osv.example.test" }, func(s *api.Server) { srv = s })
	_ = env
	if srv == nil || !srv.MCPSweepReady() {
		t.Fatal("the sweep has no vulnerability database although AGENTRY_SCAN_OSV_URL names one")
	}
	env2 := newTestEnvCfg(t, func(c *config.Config) { c.Scan.OSVURL = "none" }, func(s *api.Server) { srv = s })
	_ = env2
	if srv.MCPSweepReady() {
		t.Fatal("\"none\" must leave the sweep without a database")
	}

	// Every spelling of "no database", in any case, leaves it without one;
	// an unset address means the public database, not none.
	ready := func(osvURL string) bool {
		t.Helper()
		newTestEnvCfg(t, func(c *config.Config) { c.Scan.OSVURL = osvURL }, func(s *api.Server) { srv = s })
		return srv.MCPSweepReady()
	}
	for _, off := range []string{"off", "false", "disabled", "NONE", " Off "} {
		if ready(off) {
			t.Errorf("%q must leave the sweep without a database", off)
		}
	}
	if !ready("") {
		t.Error("an unset address must leave the sweep with the public database")
	}
}
