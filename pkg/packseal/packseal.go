// Package packseal is the sealed form of a knowledge pack: the pack's
// tree, as one tar, encrypted under a random data key of its own, so that
// neither a laptop's store nor Agentry's holds a pack's pages in the
// clear. The data key is never stored beside it in the clear: it is
// wrapped, by the registry the person is signed in to or, signed out, by a
// key on the machine. It is the core's, open, so the CLI, the desktop and
// the registry all read and write the same bytes.
//
// The layout, all integers big-endian:
//
//	magic    "AGYPACK1\n"
//	uint32   header length, then the header (JSON, below)
//	frames:  uint32 length, then that many bytes of ciphertext
//
// Each frame is at most ChunkSize bytes of plaintext sealed with
// AES-256-GCM under the data key. Its nonce is the header's random prefix
// and the frame's index; its additional data is the header's SHA-256, the
// frame's index and whether it is the last, so a frame cannot be altered,
// moved, dropped or repeated, the header cannot be changed, and a stream
// cut short at a frame boundary does not open (the last frame says it is
// the last). It follows the framing of the hosted run's sealed output
// (the enterprise build's runout package), with a data key in place of HPKE.
package packseal

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Magic opens every sealed pack.
const Magic = "AGYPACK1\n"

// ChunkSize is the most plaintext one frame carries.
const ChunkSize = 64 << 10

// KeySize is a data key's length: AES-256.
const KeySize = 32

// MaxHeader bounds the header a reader accepts.
const MaxHeader = 2048

// frameOverhead is a frame's length prefix and its AEAD tag.
const frameOverhead = 4 + 16

// nonceSize is GCM's nonce; the header carries its first 8 bytes and the
// frame index fills the last 4.
const nonceSize = 12

// Header is what may be read of a sealed pack without its key: which pack
// it is and the digest of the tree it holds.
type Header struct {
	// Version is the format's version, 1.
	Version int `json:"v"`
	// AEAD names the frames' cipher, "AES-256-GCM".
	AEAD string `json:"aead"`
	// Pack is the pack's own id (its manifest's id).
	Pack string `json:"pack"`
	// Digest is the pack's tree digest ("sha256:<hex>"), as its maker
	// computed it; whoever opens it may check it against the tree.
	Digest string `json:"digest"`
	// Nonce is the random prefix of every frame's nonce, 8 bytes; the
	// frame's index fills the last 4.
	Nonce []byte `json:"nonce"`
	// Chunk is the most plaintext a frame carries, ChunkSize.
	Chunk int `json:"chunk"`
}

var (
	// ErrFormat is a stream that is not a sealed pack of this version.
	ErrFormat = errors.New("packseal: not a sealed knowledge pack")
	// ErrOpen is every failure to open one: a wrong key, a header or a
	// frame altered, moved or missing. Which check failed is not the
	// reader's to learn.
	ErrOpen = errors.New("packseal: the sealed pack does not open with this key")
	// ErrKey is a data key of the wrong size.
	ErrKey = errors.New("packseal: a data key is 32 bytes")
)

// MaxSealedSize is the most a sealed pack of plain bytes of plaintext can
// be, for a caller that bounds an upload by the pack's own cap.
func MaxSealedSize(plain int64) int64 {
	frames := plain/ChunkSize + 1
	return int64(len(Magic)) + 4 + MaxHeader + plain + frames*frameOverhead
}

// NewKey is a fresh random data key.
func NewKey() ([]byte, error) {
	k := make([]byte, KeySize)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// Seal writes plain, sealed under key, to w with the header h (its
// Version, AEAD, Nonce and Chunk are set here).
func Seal(w io.Writer, key []byte, h Header, plain io.Reader) error {
	aead, err := newAEAD(key)
	if err != nil {
		return err
	}
	h.Version, h.AEAD, h.Chunk = 1, "AES-256-GCM", ChunkSize
	h.Nonce = make([]byte, nonceSize-4)
	if _, err := rand.Read(h.Nonce); err != nil {
		return err
	}
	raw, err := json.Marshal(h)
	if err != nil {
		return err
	}
	if len(raw) > MaxHeader {
		return fmt.Errorf("packseal: the header is %d bytes, past %d", len(raw), MaxHeader)
	}
	hsum := sha256.Sum256(raw)
	bw := bufio.NewWriter(w)
	if _, err := bw.WriteString(Magic); err != nil {
		return err
	}
	if err := binary.Write(bw, binary.BigEndian, uint32(len(raw))); err != nil {
		return err
	}
	if _, err := bw.Write(raw); err != nil {
		return err
	}
	// Read one frame ahead, so the frame that is last knows it.
	cur := make([]byte, ChunkSize)
	next := make([]byte, ChunkSize)
	n, err := io.ReadFull(plain, cur)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return err
	}
	for index := uint32(0); ; index++ {
		m, rerr := 0, error(nil)
		if n == ChunkSize {
			m, rerr = io.ReadFull(plain, next)
			if rerr != nil && !errors.Is(rerr, io.EOF) && !errors.Is(rerr, io.ErrUnexpectedEOF) {
				return rerr
			}
		}
		last := n < ChunkSize || m == 0
		ct := aead.Seal(nil, nonce(h.Nonce, index), cur[:n], frameAAD(hsum, index, last))
		if err := binary.Write(bw, binary.BigEndian, uint32(len(ct))); err != nil {
			return err
		}
		if _, err := bw.Write(ct); err != nil {
			return err
		}
		if last {
			break
		}
		cur, next, n = next, cur, m
	}
	return bw.Flush()
}

// ReadHeader reads a sealed pack's header, which needs no key.
func ReadHeader(r io.Reader) (Header, error) {
	h, _, err := readHeader(r)
	return h, err
}

func readHeader(r io.Reader) (Header, [32]byte, error) {
	var h Header
	var sum [32]byte
	magic := make([]byte, len(Magic))
	if _, err := io.ReadFull(r, magic); err != nil || string(magic) != Magic {
		return h, sum, ErrFormat
	}
	var hl uint32
	if err := binary.Read(r, binary.BigEndian, &hl); err != nil || hl == 0 || hl > MaxHeader {
		return h, sum, ErrFormat
	}
	raw := make([]byte, hl)
	if _, err := io.ReadFull(r, raw); err != nil {
		return h, sum, ErrFormat
	}
	if err := json.Unmarshal(raw, &h); err != nil || h.Version != 1 || h.AEAD != "AES-256-GCM" || len(h.Nonce) != nonceSize-4 || h.Chunk != ChunkSize {
		return h, sum, ErrFormat
	}
	return h, sha256.Sum256(raw), nil
}

// Open reads a sealed pack's header and returns a reader of its plaintext,
// which fails with ErrOpen the moment a frame does not verify, and at the
// end if the last frame never came.
func Open(r io.Reader, key []byte) (Header, io.Reader, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return Header{}, nil, err
	}
	br := bufio.NewReader(r)
	h, hsum, err := readHeader(br)
	if err != nil {
		return h, nil, err
	}
	return h, &opener{r: br, aead: aead, h: h, hsum: hsum}, nil
}

type opener struct {
	r     *bufio.Reader
	aead  cipher.AEAD
	h     Header
	hsum  [32]byte
	index uint32
	buf   bytes.Reader
	done  bool
	err   error
}

func (o *opener) Read(p []byte) (int, error) {
	for o.buf.Len() == 0 {
		if o.err != nil {
			return 0, o.err
		}
		if o.done {
			return 0, io.EOF
		}
		o.err = o.nextFrame()
	}
	return o.buf.Read(p)
}

func (o *opener) nextFrame() error {
	var fl uint32
	if err := binary.Read(o.r, binary.BigEndian, &fl); err != nil {
		// No last frame: a stream cut short.
		return ErrOpen
	}
	if fl < 16 || fl > ChunkSize+16 {
		return ErrOpen
	}
	ct := make([]byte, fl)
	if _, err := io.ReadFull(o.r, ct); err != nil {
		return ErrOpen
	}
	for _, last := range []bool{false, true} {
		pt, err := o.aead.Open(nil, nonce(o.h.Nonce, o.index), ct, frameAAD(o.hsum, o.index, last))
		if err != nil {
			continue
		}
		o.index++
		if last {
			// Nothing may follow the last frame.
			if _, err := o.r.ReadByte(); !errors.Is(err, io.EOF) {
				return ErrOpen
			}
			o.done = true
		}
		o.buf.Reset(pt)
		return nil
	}
	return ErrOpen
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, ErrKey
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func nonce(prefix []byte, index uint32) []byte {
	n := make([]byte, nonceSize)
	copy(n, prefix)
	binary.BigEndian.PutUint32(n[nonceSize-4:], index)
	return n
}

func frameAAD(hsum [32]byte, index uint32, last bool) []byte {
	aad := make([]byte, 0, 32+4+1)
	aad = append(aad, hsum[:]...)
	aad = binary.BigEndian.AppendUint32(aad, index)
	if last {
		return append(aad, 1)
	}
	return append(aad, 0)
}
