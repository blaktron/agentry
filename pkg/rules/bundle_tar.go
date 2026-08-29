package rules

// Bundle serialization. `agentry validate --rules-update` fetches the
// registry's rule bundle over HTTP; this is the wire form.
//
// The transport is a plain, uncompressed tar of the bundle *directory*:
// bundle.yaml plus the family YAML files, flat, no leading path component.
// Nothing is compressed because the payload is a few tens of kilobytes of
// YAML and a compressed archive is one more decoder standing between a
// client and its trust decision.
//
// The important property is round-tripping: extracting Tar() into a
// directory and calling LoadBundle on it yields a bundle with the SAME
// Digest(). The digest a server advertises is therefore the digest a client
// can recompute from the bytes it received, which is what makes digest
// pinning meaningful. TestBundleTarRoundTrip holds that property.

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"time"
)

// Serialization limits. A rule bundle is a handful of small YAML files; these
// bound what a client is willing to unpack from a registry response.
const (
	maxBundleEntries   = 256
	maxBundleEntrySize = 4 << 20
)

// Tar serializes the bundle as an uncompressed tar archive. Output is
// deterministic: entries appear in digest order with fixed mode, zero
// ownership, and a fixed timestamp, so two calls produce identical bytes and
// the archive itself can be digested.
func (b *Bundle) Tar() ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	// A fixed epoch keeps the bytes reproducible; any real timestamp would
	// make two serializations of the same bundle differ.
	epoch := time.Unix(0, 0).UTC()
	for _, name := range b.order {
		content := b.source[name]
		hdr := &tar.Header{
			Name:     name,
			Mode:     0o644,
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
			ModTime:  epoch,
			Format:   tar.FormatUSTAR,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, fmt.Errorf("rules: tar header %s: %w", name, err)
		}
		if _, err := tw.Write(content); err != nil {
			return nil, fmt.Errorf("rules: tar write %s: %w", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("rules: tar close: %w", err)
	}
	return buf.Bytes(), nil
}

// UntarBundle reads a Tar() archive and hands each entry to write.
//
// It accepts only flat, regular YAML entries: no directories, no symlinks,
// no path separators, no "..". A rule bundle has no directory structure to
// preserve, so an archive that contains structure did not come from Tar() —
// it is refused rather than interpreted, which is what keeps an untrusted
// response from writing outside the directory the caller chose.
//
// Returns the entry names in archive order.
func UntarBundle(data []byte, write func(name string, content []byte) error) ([]string, error) {
	tr := tar.NewReader(bytes.NewReader(data))
	var names []string
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("rules: read bundle archive: %w", err)
		}
		if len(names) >= maxBundleEntries {
			return nil, fmt.Errorf("rules: bundle archive has more than %d entries", maxBundleEntries)
		}
		if hdr.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("rules: bundle archive entry %q is not a regular file", hdr.Name)
		}
		name := hdr.Name
		if name == "" || name == "." || name == ".." ||
			strings.ContainsAny(name, `/\`) || name != path.Base(name) {
			return nil, fmt.Errorf("rules: bundle archive entry %q is not a flat file name", hdr.Name)
		}
		if ext := strings.ToLower(path.Ext(name)); ext != ".yaml" && ext != ".yml" {
			return nil, fmt.Errorf("rules: bundle archive entry %q is not a YAML file", hdr.Name)
		}
		if hdr.Size > maxBundleEntrySize {
			return nil, fmt.Errorf("rules: bundle archive entry %q exceeds %d bytes", hdr.Name, maxBundleEntrySize)
		}
		content := make([]byte, hdr.Size)
		if _, err := io.ReadFull(tr, content); err != nil {
			return nil, fmt.Errorf("rules: read %q from bundle archive: %w", hdr.Name, err)
		}
		if err := write(name, content); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	if len(names) == 0 {
		return nil, errors.New("rules: bundle archive is empty")
	}
	return names, nil
}
