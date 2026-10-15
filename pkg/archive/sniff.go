package archive

import (
	"bytes"
	"strings"
)

// Content sniffing for package inventories (S1). Detection is by MAGIC
// BYTES, never by extension — renaming evil.so to notes.md fools nobody. The
// server's S1 stage and the CLI's `agentry validate` both classify through
// these predicates, which is what makes local/remote parity a property
// of the code rather than a promise.

var execMagic = [][]byte{
	{0x7f, 0x45, 0x4c, 0x46}, // ELF
	{0xcf, 0xfa, 0xed, 0xfe}, // Mach-O 64 LE
	{0xfe, 0xed, 0xfa, 0xcf}, // Mach-O 64 BE
	{0xca, 0xfe, 0xba, 0xbe}, // Mach-O universal / Java class
	{0x4d, 0x5a},             // PE/DOS (MZ)
}

var archiveMagic = [][]byte{
	{0x50, 0x4b, 0x03, 0x04}, // zip
	{0x1f, 0x8b},             // gzip
	{0x28, 0xb5, 0x2f, 0xfd}, // zstd
	{0x42, 0x5a, 0x68},       // bzip2
	{0xfd, 0x37, 0x7a, 0x58}, // xz
}

// imageExt drives image classification: an image is not text, and not a
// finding either — S1 flags it in the inventory and caps its size.
var imageExt = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
	".webp": true, ".bmp": true, ".ico": true,
}

// IsExecutable reports whether data opens with an executable or shared
// library signature (ELF, Mach-O, PE, Java class).
func IsExecutable(data []byte) bool { return hasAnyPrefix(data, execMagic) }

// IsArchiveData reports whether data is a compressed container (zip, gzip,
// zstd, bzip2, xz) or a tar, whose "ustar" magic lives at offset 257.
func IsArchiveData(data []byte) bool {
	if hasAnyPrefix(data, archiveMagic) {
		return true
	}
	return len(data) > 262 && bytes.Equal(data[257:262], []byte("ustar"))
}

// IsImagePath reports whether path has a recognized raster-image extension.
func IsImagePath(path string) bool {
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		path = path[i+1:]
	}
	if i := strings.LastIndexByte(path, '.'); i > 0 {
		return imageExt[strings.ToLower(path[i:])]
	}
	return false
}

// LooksText reports whether head is plausibly text: no NUL byte, and under
// 5% control characters. Pass at most the first ~512 bytes.
func LooksText(head []byte) bool {
	if len(head) == 0 {
		return true
	}
	if bytes.IndexByte(head, 0) >= 0 {
		return false
	}
	nonPrint := 0
	for _, b := range head {
		if b < 0x09 || (b > 0x0d && b < 0x20) {
			nonPrint++
		}
	}
	return nonPrint*100/len(head) < 5
}

// Head returns the first 512 bytes of data, the window the sniffers use.
// Nothing in this repo calls it directly — the sniffers take the whole
// buffer — but it is part of pkg/archive's shared surface: the CLI and the
// desktop app feed it to LooksText so their offline scans classify files
// exactly as S1 does. Keep it.
func Head(data []byte) []byte {
	if len(data) > 512 {
		return data[:512]
	}
	return data
}

func hasAnyPrefix(data []byte, magics [][]byte) bool {
	for _, m := range magics {
		if bytes.HasPrefix(data, m) {
			return true
		}
	}
	return false
}
