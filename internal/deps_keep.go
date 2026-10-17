// Package agentrydeps pins dependencies that code about to land imports,
// so go.mod does not change concurrently. Each blank import moves to its
// real consumer as that code lands, then this file shrinks and finally
// disappears.
package agentrydeps

import (
	_ "github.com/Masterminds/semver/v3"
	_ "github.com/klauspost/compress/zstd"
	_ "github.com/zalando/go-keyring"
	_ "golang.org/x/text/unicode/norm"
	_ "golang.org/x/time/rate"
)
