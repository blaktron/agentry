package registry

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// BlobStore stores release archives content-addressed by digest. Keys look
// like "releases/ab/sha256:abcd....tar.zst"; the implementation maps them
// to its backend. Objects are write-once: Put to an existing key
// verifies nothing and returns nil (same content by construction).
type BlobStore interface {
	Put(ctx context.Context, key string, r io.Reader) error
	Get(ctx context.Context, key string) (io.ReadCloser, error)
	Exists(ctx context.Context, key string) (bool, error)
	// Delete removes an object; a key that is not there is not an error,
	// so a sweep that runs twice is a sweep that ran.
	Delete(ctx context.Context, key string) error
}

// ArchiveKey computes the content-addressed storage key for a digest
// ("sha256:<hex>" → "releases/<hex[0:2]>/<hex>.tar.zst").
func ArchiveKey(digest string) string {
	hex := strings.TrimPrefix(digest, "sha256:")
	if len(hex) < 2 {
		return "releases/xx/" + hex + ".tar.zst"
	}
	return "releases/" + hex[:2] + "/" + hex + ".tar.zst"
}

// LocalFS is the self-host/dev BlobStore (no hard cloud dependency); the S3
// implementation is S3Store.
type LocalFS struct {
	Root string
}

// NewLocalFS creates the root directory if needed.
func NewLocalFS(root string) (*LocalFS, error) {
	if err := os.MkdirAll(root, 0o750); err != nil {
		return nil, fmt.Errorf("blobstore: %w", err)
	}
	return &LocalFS{Root: root}, nil
}

func (l *LocalFS) path(key string) (string, error) {
	clean := filepath.Clean(filepath.FromSlash(key))
	if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
		return "", fmt.Errorf("blobstore: invalid key %q", key)
	}
	return filepath.Join(l.Root, clean), nil
}

// Put implements BlobStore with atomic rename semantics.
func (l *LocalFS) Put(ctx context.Context, key string, r io.Reader) error {
	path, err := l.path(key)
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return nil // content-addressed: already stored
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".upload-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := io.Copy(tmp, r); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("blobstore: write: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Get implements BlobStore.
func (l *LocalFS) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	path, err := l.path(key)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path) //nolint:gosec // key sanitized in path()
	if err != nil {
		return nil, fmt.Errorf("blobstore: %w", err)
	}
	return f, nil
}

// Delete implements BlobStore.
func (l *LocalFS) Delete(ctx context.Context, key string) error {
	path, err := l.path(key)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("blobstore: delete %s: %w", key, err)
	}
	return nil
}

// Exists implements BlobStore.
func (l *LocalFS) Exists(ctx context.Context, key string) (bool, error) {
	path, err := l.path(key)
	if err != nil {
		return false, err
	}
	_, statErr := os.Stat(path)
	if statErr == nil {
		return true, nil
	}
	if os.IsNotExist(statErr) {
		return false, nil
	}
	return false, statErr
}
