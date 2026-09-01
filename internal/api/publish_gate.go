package api

import "github.com/blaktron/agentry/internal/config"

// publicPublish2FAEnabled decides whether the registry enforces the §12.1/§19
// rule "two-factor authentication before publishing to a public namespace"
// with its own TOTP flag.
//
// Off in dev mode (DEV-016: a dev instance has no enrollment flow behind the
// gate). Off as well when credentials live in an external directory
// (auth.externalOnly, DEV-057): the native TOTP endpoints answer 410 Gone, so
// no account can ever set users.totp_enabled, and the gate would hold every
// publisher to human review with an instruction — "enable two-factor
// authentication" — that the product cannot honour. Under externalOnly the
// requirement belongs to the directory service: enforce MFA there, on the
// authentication flow or the registry application, where it also covers
// sign-in itself. The registry does not currently read an `amr`/`acr` claim
// to verify that policy; docs/self-hosting.md says so.
func publicPublish2FAEnabled(cfg config.Config) bool {
	return !cfg.DevMode && !cfg.Auth.ExternalOnly
}
