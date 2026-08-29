package main

// A minimal deterministic tar writer for the install fixtures.

import (
	"archive/tar"
	"io"
	"sort"
	"testing"
	"time"
)

type fixtureTar struct {
	tw      *tar.Writer
	pending map[string]string
}

func newTarWriter(w io.Writer) *fixtureTar {
	return &fixtureTar{tw: tar.NewWriter(w), pending: map[string]string{}}
}

func (f *fixtureTar) add(_ *testing.T, name, content string) {
	f.pending[name] = content
}

// close writes the buffered entries in sorted order, so a fixture archive
// built from a Go map still has stable bytes and therefore a stable digest.
func (f *fixtureTar) close(t *testing.T) {
	t.Helper()
	names := make([]string, 0, len(f.pending))
	for n := range f.pending {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		content := f.pending[n]
		if err := f.tw.WriteHeader(&tar.Header{
			Name: n, Mode: 0o644, Size: int64(len(content)),
			Typeflag: tar.TypeReg, ModTime: time.Unix(0, 0).UTC(), Format: tar.FormatUSTAR,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.tw.Close(); err != nil {
		t.Fatal(err)
	}
}
