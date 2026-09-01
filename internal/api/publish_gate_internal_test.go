package api

import (
	"testing"

	"github.com/blaktron/agentry/internal/config"
)

func TestPublicPublish2FAEnabled(t *testing.T) {
	cases := []struct {
		name         string
		dev, extOnly bool
		want         bool
	}{
		{"dev mode, native credentials", true, false, false},
		{"production, native credentials", false, false, true},
		{"production, external directory", false, true, false},
		{"dev mode, external directory", true, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.DevMode = tc.dev
			cfg.Auth.ExternalOnly = tc.extOnly
			if got := publicPublish2FAEnabled(cfg); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}
