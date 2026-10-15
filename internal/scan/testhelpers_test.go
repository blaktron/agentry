package scan

import (
	"archive/tar"
	"bytes"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// tarZst builds a tar.zst from name→content (raw entries, for hostile cases).
// The extractor and its own fixtures live in pkg/archive; this copy serves
// the scan-side tests that assemble small archives.
func tarZst(t *testing.T, entries []tar.Header, bodies [][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, _ := zstd.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for i, h := range entries {
		hh := h
		if hh.Typeflag == tar.TypeReg && hh.Size == 0 {
			hh.Size = int64(len(bodies[i]))
		}
		_ = tw.WriteHeader(&hh)
		if hh.Typeflag == tar.TypeReg {
			_, _ = tw.Write(bodies[i])
		}
	}
	_ = tw.Close()
	_ = zw.Close()
	return buf.Bytes()
}
