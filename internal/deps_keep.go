// Package agentrydeps pins dependencies that upcoming milestones import,
// so parallel workgroups never mutate go.mod concurrently. Each blank
// import moves to its real consumer as that code lands, then this file
// shrinks and finally disappears.
package agentrydeps

import (
	_ "github.com/Masterminds/semver/v3"
	_ "github.com/klauspost/compress/zstd"
	_ "github.com/pquerna/otp/totp"
	_ "github.com/zalando/go-keyring"
	_ "golang.org/x/crypto/argon2"
	_ "golang.org/x/text/unicode/norm"
	_ "golang.org/x/time/rate"
)
