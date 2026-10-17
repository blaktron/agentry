package api

import (
	"testing"

	"github.com/blaktron/agentry/internal/config"
)

func TestPublicPublish2FAEnabled(t *testing.T) {
	cases := []struct {
		name            string
		dev, requireMFA bool
		want            bool
	}{
		{"production, no IdP evidence asked for", false, false, false},
		{"production, MFA evidence required", false, true, true},
		{"dev mode", true, false, false},
		{"dev mode, MFA evidence required", true, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.DevMode = tc.dev
			cfg.Auth.RequireIdPMFA = tc.requireMFA
			if got := publicPublish2FAEnabled(cfg); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}
