package api_test

import (
	"testing"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
)

// The production wiring must reach the sweep, not only S7: on dev the first
// sweep found "no vulnerability database configured" while S7 had one.
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
}
