package api

import "github.com/blaktron/agentry/internal/config"

// publicPublish2FAEnabled decides whether the registry enforces the rule
// "a second factor before publishing to a public namespace".
//
// The server keeps no second factor of its own: people sign in through the
// deployment's OpenID provider, which is where a second factor is enforced,
// on the sign-in flow itself. With auth.requireIdpMFA the gate is on,
// satisfied by evidence: users.idp_mfa_at, stamped when a sign-in's ID token
// carried an `amr` naming a second factor. Without it the gate is off, since
// the registry holds no evidence it could ask for. Off in dev mode too.
func publicPublish2FAEnabled(cfg config.Config) bool {
	if cfg.DevMode {
		return false
	}
	return cfg.Auth.RequireIdPMFA
}
