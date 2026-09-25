package packseal

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"testing"
)

func key(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, KeySize)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func seal(t *testing.T, k []byte, h Header, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := Seal(&buf, k, h, bytes.NewReader(plain)); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func open(k []byte, sealed []byte) (Header, []byte, error) {
	h, r, err := Open(bytes.NewReader(sealed), k)
	if err != nil {
		return h, nil, err
	}
	b, err := io.ReadAll(r)
	return h, b, err
}

func TestSealOpenRoundTrip(t *testing.T) {
	k := key(t)
	for _, size := range []int{0, 1, ChunkSize - 1, ChunkSize, ChunkSize + 1, 3*ChunkSize + 17} {
		plain := bytes.Repeat([]byte{'k'}, size)
		sealed := seal(t, k, Header{Pack: "kp_abc", Digest: "sha256:00"}, plain)
		h, got, err := open(k, sealed)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if !bytes.Equal(got, plain) || h.Pack != "kp_abc" || h.Digest != "sha256:00" || h.AEAD != "AES-256-GCM" {
			t.Fatalf("size %d: header %+v, %d bytes back", size, h, len(got))
		}
		if int64(len(sealed)) > MaxSealedSize(int64(size)) {
			t.Fatalf("size %d: sealed %d bytes, past MaxSealedSize %d", size, len(sealed), MaxSealedSize(int64(size)))
		}
	}
}

func TestReadHeaderNeedsNoKey(t *testing.T) {
	sealed := seal(t, key(t), Header{Pack: "kp_x", Digest: "sha256:ab"}, []byte("tree"))
	h, err := ReadHeader(bytes.NewReader(sealed))
	if err != nil || h.Pack != "kp_x" || h.Digest != "sha256:ab" || h.Version != 1 {
		t.Fatalf("%+v %v", h, err)
	}
	if _, err := ReadHeader(strings.NewReader("not a sealed pack")); !errors.Is(err, ErrFormat) {
		t.Fatalf("err = %v", err)
	}
}

func TestOpenRefuses(t *testing.T) {
	k := key(t)
	plain := bytes.Repeat([]byte("page "), 3*ChunkSize/5) // three frames
	sealed := seal(t, k, Header{Pack: "kp_a", Digest: "sha256:aa"}, plain)
	hlen := len(Magic) + 4 + int(uint32(sealed[len(Magic)])<<24|uint32(sealed[len(Magic)+1])<<16|uint32(sealed[len(Magic)+2])<<8|uint32(sealed[len(Magic)+3]))
	firstFrame := hlen
	frameLen := 4 + int(uint32(sealed[firstFrame])<<24|uint32(sealed[firstFrame+1])<<16|uint32(sealed[firstFrame+2])<<8|uint32(sealed[firstFrame+3]))

	tests := []struct {
		name   string
		sealed func() []byte
		key    []byte
		is     error
	}{
		{name: "another key", sealed: func() []byte { return sealed }, key: key(t), is: ErrOpen},
		{name: "a flipped byte in a frame", sealed: func() []byte {
			b := bytes.Clone(sealed)
			b[firstFrame+10] ^= 1
			return b
		}, key: k, is: ErrOpen},
		{name: "a header changed after sealing", sealed: func() []byte {
			return bytes.Replace(bytes.Clone(sealed), []byte(`"kp_a"`), []byte(`"kp_b"`), 1)
		}, key: k, is: ErrOpen},
		{name: "the last frame cut off", sealed: func() []byte {
			return sealed[:len(sealed)-(frameLen/2)]
		}, key: k, is: ErrOpen},
		{name: "a whole frame dropped", sealed: func() []byte {
			b := bytes.Clone(sealed[:firstFrame])
			return append(b, sealed[firstFrame+frameLen:]...)
		}, key: k, is: ErrOpen},
		{name: "cut at a frame boundary", sealed: func() []byte {
			return sealed[:firstFrame+frameLen]
		}, key: k, is: ErrOpen},
		{name: "not a sealed pack", sealed: func() []byte { return []byte("PK\x03\x04 a zip") }, key: k, is: ErrFormat},
		{name: "a short key", sealed: func() []byte { return sealed }, key: k[:16], is: ErrKey},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := open(tc.key, tc.sealed()); !errors.Is(err, tc.is) {
				t.Fatalf("err = %v, want %v", err, tc.is)
			}
		})
	}
}

func TestSealRefusesABadKeyAndHeader(t *testing.T) {
	if err := Seal(io.Discard, make([]byte, 16), Header{Pack: "kp_a"}, strings.NewReader("x")); !errors.Is(err, ErrKey) {
		t.Fatalf("err = %v", err)
	}
	if err := Seal(io.Discard, key(t), Header{Pack: strings.Repeat("x", MaxHeader)}, strings.NewReader("x")); err == nil {
		t.Fatal("an oversized header was sealed")
	}
}

func TestTwoSealsOfOneTreeDiffer(t *testing.T) {
	k := key(t)
	a := seal(t, k, Header{Pack: "kp_a"}, []byte("same"))
	b := seal(t, k, Header{Pack: "kp_a"}, []byte("same"))
	if bytes.Equal(a, b) {
		t.Fatal("two seals of one tree under one key are identical: the nonce is not fresh")
	}
}
