package knowledge

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/blaktron/agentry/internal/scan"
	"github.com/blaktron/agentry/pkg/manifest"
)

// MaxBytes caps a pack: every file of its tree, in MiB as the CLI counts
// it (agentry-cli pkg/knowledge.MaxBytes).
const MaxBytes = manifest.MaxKnowledgePackBytes

// MaxFiles caps the files of one pack's tree.
const MaxFiles = manifest.MaxKnowledgePackFiles

// MaxTreeBytes bounds a tree's tar: its files, and for each at most a PAX
// header, a ustar header and a block of padding, and the end blocks.
const MaxTreeBytes = MaxBytes + MaxFiles*2048 + 1024

// The two directories a pack's tree holds (agentry-cli pkg/knowledge).
const (
	WikiDir    = "wiki"
	SourcesDir = "sources"
)

var (
	// ErrTooLarge is a tree past MaxBytes or MaxFiles.
	ErrTooLarge = fmt.Errorf("knowledge: a pack is at most %d MB and %d files", MaxBytes>>20, MaxFiles)
	// ErrDigest is a tree whose bytes are not the digest it names.
	ErrDigest = errors.New("knowledge: the tree does not match its digest")
	// ErrTree is a tree that is not a pack's canonical tar.
	ErrTree = errors.New("knowledge: not a knowledge pack's tree")
)

// Tree is a pack's tree as the registry read it.
type Tree struct {
	Files []scan.PackFile
	// Bytes is the files' size, Pages the wiki's pages (the index and the
	// log aside), as the CLI counts them.
	Bytes int64
	Pages int
	// Digest is the SHA-256 of the tar, "sha256:<hex>".
	Digest string
}

// ReadTree reads a pack's tree from the canonical tar its digest is taken
// over (agentry-cli pkg/knowledge.TreeDigest: regular files under wiki/
// and sources/, in byte order of their paths) and checks that its bytes
// are digest. It refuses anything else a tar can carry — a link, a
// device, a directory entry, a path that climbs or is not the pack's, a
// name twice — and a tree past the pack's caps.
func ReadTree(r io.Reader, digest string) (*Tree, error) {
	h := sha256.New()
	lr := &io.LimitedReader{R: r, N: MaxTreeBytes + 1}
	tr := tar.NewReader(io.TeeReader(lr, h))
	t := &Tree{}
	last := ""
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if lr.N <= 0 {
				return nil, ErrTooLarge
			}
			return nil, ErrTree
		}
		if hdr.Typeflag != tar.TypeReg || !treePath(hdr.Name) || hdr.Name <= last {
			return nil, ErrTree
		}
		last = hdr.Name
		if len(t.Files) == MaxFiles || hdr.Size < 0 || t.Bytes+hdr.Size > MaxBytes {
			return nil, ErrTooLarge
		}
		body, err := io.ReadAll(io.LimitReader(tr, hdr.Size))
		if err != nil || int64(len(body)) != hdr.Size {
			return nil, ErrTree
		}
		t.Bytes += hdr.Size
		t.Files = append(t.Files, scan.PackFile{Path: hdr.Name, Content: body})
		if isPage(hdr.Name) {
			t.Pages++
		}
	}
	// The end blocks are part of what the digest covers, and nothing may
	// follow them.
	if _, err := io.Copy(io.Discard, io.TeeReader(lr, h)); err != nil {
		return nil, ErrTree
	}
	if lr.N <= 0 {
		return nil, ErrTooLarge
	}
	t.Digest = "sha256:" + hex.EncodeToString(h.Sum(nil))
	if t.Digest != digest {
		return nil, ErrDigest
	}
	// The bytes are the digest; they must also be the canonical tar of the
	// files they hold, or two trees of the same files could carry two
	// digests (a GNU long name, a mode, a time), and the registry's record
	// would not be the CLI's.
	canon := sha256.New()
	if err := WriteTree(canon, t.Files); err != nil {
		return nil, ErrTree
	}
	if "sha256:"+hex.EncodeToString(canon.Sum(nil)) != digest {
		return nil, ErrTree
	}
	return t, nil
}

// WriteTree writes files as a pack's canonical tar, in byte order of their
// paths: the form agentry-cli's TreeDigest hashes, field by field (mode
// 0644, uid and gid 0, mtime 0, a PAX header only when a name needs one,
// two zero blocks and no record padding after the last file).
func WriteTree(w io.Writer, files []scan.PackFile) error {
	sorted := append([]scan.PackFile(nil), files...)
	sort.Slice(sorted, func(i, k int) bool { return sorted[i].Path < sorted[k].Path })
	tw := tar.NewWriter(w)
	for _, f := range sorted {
		if err := tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg,
			Name:     f.Path,
			Mode:     0o644,
			Size:     int64(len(f.Content)),
			ModTime:  time.Unix(0, 0),
			Format:   tar.FormatPAX,
		}); err != nil {
			return err
		}
		if _, err := tw.Write(f.Content); err != nil {
			return err
		}
	}
	return tw.Close()
}

// treePath says whether name is a clean slash path of a file under wiki/
// or sources/.
func treePath(name string) bool {
	if !strings.HasPrefix(name, WikiDir+"/") && !strings.HasPrefix(name, SourcesDir+"/") {
		return false
	}
	if path.Clean(name) != name || strings.Contains(name, `\`) {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	for _, c := range name {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}

// isPage is agentry-cli's rule: a markdown file under wiki/ other than an
// index or the log.
func isPage(rel string) bool {
	if !strings.HasPrefix(rel, WikiDir+"/") || !strings.HasSuffix(rel, ".md") {
		return false
	}
	return path.Base(rel) != "index.md" && rel != WikiDir+"/log.md"
}
