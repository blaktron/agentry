package scan

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"io"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Image metadata text extraction for S3 (image alt-text/EXIF text
// extraction for instruction-bearing strings).
//
// Markdown alt-text needs no extraction — it is literal text in the .md file,
// so S3/S4 already read it (TestAltTextIsScanned pins that). The real blind
// spot is metadata inside the image bytes: a PNG tEXt chunk or a JPEG EXIF
// UserComment is invisible in every renderer and every diff, and an agent that
// ships one is shipping instructions the reviewer cannot see.
//
// These are hand-rolled chunk walkers over stdlib only. The parsers read
// attacker-controlled bytes, so every field is bounds-checked and every
// decompression is size-capped; an unparsable image yields no strings rather
// than an error (S1 already flags files that are not what they claim).

// imageMetaCaps bound the work an image can cause.
const (
	// maxImageBytes is the largest image file the extractor will read (the
	// release quotas cap images at 5 MB).
	maxImageBytes = 5 << 20
	// maxMetaChunkBytes caps one decompressed text chunk.
	maxMetaChunkBytes = 64 << 10
	// maxMetaStrings caps how many strings one image may contribute.
	maxMetaStrings = 64
)

// metaString is one text value recovered from an image's metadata.
type metaString struct {
	// Field names where it came from ("PNG:tEXt:Comment", "EXIF:UserComment").
	Field string
	// Text is the decoded value.
	Text string
}

// extractImageText returns the human-readable strings embedded in an image's
// metadata. Format is detected from the magic bytes, not the extension.
func extractImageText(data []byte) []metaString {
	if len(data) > maxImageBytes {
		data = data[:maxImageBytes]
	}
	switch {
	case bytes.HasPrefix(data, []byte("\x89PNG\r\n\x1a\n")):
		return pngText(data)
	case bytes.HasPrefix(data, []byte{0xFF, 0xD8}):
		return jpegText(data)
	}
	return nil
}

// pngText walks PNG chunks and decodes tEXt, zTXt and iTXt.
func pngText(data []byte) []metaString {
	var out []metaString
	pos := 8 // past the signature
	for pos+8 <= len(data) && len(out) < maxMetaStrings {
		length := int(binary.BigEndian.Uint32(data[pos : pos+4]))
		typ := string(data[pos+4 : pos+8])
		body := pos + 8
		// length is attacker-controlled: reject anything that would run past
		// the buffer or wrap around.
		if length < 0 || body+length+4 > len(data) {
			return out
		}
		chunk := data[body : body+length]
		switch typ {
		case "tEXt":
			if k, v, ok := bytes.Cut(chunk, []byte{0}); ok {
				out = appendMeta(out, "PNG:tEXt:"+string(k), string(v))
			}
		case "zTXt":
			// keyword \0 compressionMethod(1) compressedText
			if k, rest, ok := bytes.Cut(chunk, []byte{0}); ok && len(rest) > 1 {
				out = appendMeta(out, "PNG:zTXt:"+string(k), inflateBounded(rest[1:]))
			}
		case "iTXt":
			if f, v, ok := pngITXt(chunk); ok {
				out = appendMeta(out, "PNG:iTXt:"+f, v)
			}
		case "IEND":
			return out
		}
		pos = body + length + 4 // skip CRC
	}
	return out
}

// pngITXt decodes an iTXt chunk: keyword \0 compressed(1) method(1)
// language \0 translatedKeyword \0 text.
func pngITXt(chunk []byte) (field, text string, ok bool) {
	keyword, rest, ok := bytes.Cut(chunk, []byte{0})
	if !ok || len(rest) < 2 {
		return "", "", false
	}
	compressed := rest[0] == 1
	rest = rest[2:] // compression flag + method
	_, rest, ok = bytes.Cut(rest, []byte{0})
	if !ok {
		return "", "", false
	}
	_, rest, ok = bytes.Cut(rest, []byte{0})
	if !ok {
		return "", "", false
	}
	if compressed {
		return string(keyword), inflateBounded(rest), true
	}
	return string(keyword), string(rest), true
}

// inflateBounded zlib-inflates at most maxMetaChunkBytes. A zip bomb inside a
// PNG text chunk is a real shape; the cap is what makes walking one safe.
func inflateBounded(b []byte) string {
	zr, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		return ""
	}
	defer func() { _ = zr.Close() }()
	out, err := io.ReadAll(io.LimitReader(zr, maxMetaChunkBytes))
	if err != nil && len(out) == 0 {
		return ""
	}
	return string(out)
}

// jpegText walks JPEG markers, decoding COM comments and the text fields of an
// APP1/Exif segment.
func jpegText(data []byte) []metaString {
	var out []metaString
	pos := 2 // past SOI
	for pos+4 <= len(data) && len(out) < maxMetaStrings {
		if data[pos] != 0xFF {
			// Not on a marker boundary: entropy-coded data or a malformed
			// file. Either way there is nothing further to read structurally.
			return out
		}
		marker := data[pos+1]
		switch marker {
		case 0xD8, 0x01: // SOI, TEM — no payload
			pos += 2
			continue
		case 0xD9, 0xDA: // EOI, start of scan — metadata is behind us
			return out
		}
		if marker >= 0xD0 && marker <= 0xD7 { // RSTn — no payload
			pos += 2
			continue
		}
		segLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		if segLen < 2 || pos+2+segLen > len(data) {
			return out
		}
		seg := data[pos+4 : pos+2+segLen]
		switch {
		case marker == 0xFE: // COM
			out = appendMeta(out, "JPEG:COM", string(seg))
		case marker == 0xE1 && bytes.HasPrefix(seg, []byte("Exif\x00\x00")):
			out = append(out, exifText(seg[6:])...)
		}
		pos += 2 + segLen
	}
	return out
}

// EXIF tags whose values are human text (UserComment,
// ImageDescription and XPComment specifically).
var exifTextTags = map[uint16]string{
	0x010E: "ImageDescription",
	0x8298: "Copyright",
	0x9286: "UserComment",
	0x9C9B: "XPTitle",
	0x9C9C: "XPComment",
	0x9C9D: "XPAuthor",
	0x9C9E: "XPKeywords",
	0x9C9F: "XPSubject",
}

// exifIFDPointer is the tag whose value is the offset of the Exif sub-IFD,
// where UserComment actually lives.
const exifIFDPointer = 0x8769

// exifText parses the TIFF structure of an APP1/Exif payload and returns the
// text-bearing tags of IFD0 and the Exif sub-IFD.
func exifText(tiff []byte) []metaString {
	if len(tiff) < 8 {
		return nil
	}
	var bo binary.ByteOrder
	switch string(tiff[0:2]) {
	case "II":
		bo = binary.LittleEndian
	case "MM":
		bo = binary.BigEndian
	default:
		return nil
	}
	if bo.Uint16(tiff[2:4]) != 42 {
		return nil
	}
	off := int(bo.Uint32(tiff[4:8]))
	var out []metaString
	sub := readIFD(tiff, bo, off, &out)
	if sub > 0 {
		readIFD(tiff, bo, sub, &out)
	}
	return out
}

// readIFD reads one image file directory, appending text tags to out and
// returning the Exif sub-IFD offset when the directory carries one.
func readIFD(tiff []byte, bo binary.ByteOrder, off int, out *[]metaString) int {
	if off < 8 || off+2 > len(tiff) {
		return 0
	}
	count := int(bo.Uint16(tiff[off : off+2]))
	entry := off + 2
	subIFD := 0
	for i := 0; i < count; i++ {
		if entry+12 > len(tiff) || len(*out) >= maxMetaStrings {
			return subIFD
		}
		tag := bo.Uint16(tiff[entry : entry+2])
		typ := bo.Uint16(tiff[entry+2 : entry+4])
		n := int(bo.Uint32(tiff[entry+4 : entry+8]))
		valField := tiff[entry+8 : entry+12]
		entry += 12

		if tag == exifIFDPointer && typ == 4 && n == 1 {
			subIFD = int(bo.Uint32(valField))
			continue
		}
		name, wanted := exifTextTags[tag]
		if !wanted {
			continue
		}
		val := exifValue(tiff, bo, typ, n, valField)
		if val == nil {
			continue
		}
		for _, text := range decodeEXIFString(tag, typ, val, bo) {
			*out = appendMeta(*out, "EXIF:"+name, text)
		}
	}
	return subIFD
}

// exifValue returns the raw bytes of one tag value, resolving the inline /
// out-of-line distinction (values of 4 bytes or fewer live in the entry).
func exifValue(tiff []byte, bo binary.ByteOrder, typ uint16, n int, valField []byte) []byte {
	size := exifTypeSize(typ)
	if size == 0 || n < 0 {
		return nil
	}
	total := size * n
	if total > maxMetaChunkBytes {
		total = maxMetaChunkBytes
	}
	if total <= 4 {
		return valField[:total]
	}
	off := int(bo.Uint32(valField))
	if off < 0 || off+total > len(tiff) {
		return nil
	}
	return tiff[off : off+total]
}

func exifTypeSize(typ uint16) int {
	switch typ {
	case 1, 2, 6, 7: // BYTE, ASCII, SBYTE, UNDEFINED
		return 1
	case 3, 8: // SHORT, SSHORT
		return 2
	case 4, 9, 11: // LONG, SLONG, FLOAT
		return 4
	case 5, 10, 12: // RATIONAL, SRATIONAL, DOUBLE
		return 8
	}
	return 0
}

// decodeEXIFString turns a tag's raw bytes into text. UserComment is prefixed
// by an 8-byte character-code designator. Its UNICODE text is UTF-16: a byte
// order mark, when present, says which order; without one the text is read
// in the file's byte order and in the other, since writers disagree and the
// file chooses, and both readings are scanned. The XP* tags are UCS-2
// little-endian regardless of the file's byte order.
func decodeEXIFString(tag, typ uint16, val []byte, bo binary.ByteOrder) []string {
	switch {
	case tag == 0x9286 && len(val) >= 8: // UserComment
		code := strings.TrimRight(string(val[:8]), "\x00 ")
		body := val[8:]
		if code == "UNICODE" {
			switch {
			case bytes.HasPrefix(body, []byte{0xFE, 0xFF}):
				return []string{decodeUTF16(body[2:], binary.BigEndian)}
			case bytes.HasPrefix(body, []byte{0xFF, 0xFE}):
				return []string{decodeUTF16(body[2:], binary.LittleEndian)}
			}
			other := binary.ByteOrder(binary.LittleEndian)
			if bo == binary.LittleEndian {
				other = binary.BigEndian
			}
			return []string{decodeUTF16(body, bo), decodeUTF16(body, other)}
		}
		return []string{string(bytes.TrimRight(body, "\x00"))}
	case tag >= 0x9C9B && tag <= 0x9C9F && typ == 1: // XP* tags are UCS-2LE
		return []string{decodeUTF16(val, binary.LittleEndian)}
	}
	return []string{string(bytes.TrimRight(val, "\x00"))}
}

// decodeUTF16 decodes UTF-16 bytes in byte order bo, stopping at the first
// NUL.
func decodeUTF16(b []byte, bo binary.ByteOrder) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		c := bo.Uint16(b[i : i+2])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}

// appendMeta records a non-trivial, valid-UTF-8 string. Metadata routinely
// carries camera model numbers and software names; the length floor keeps
// those out of the finding stream without needing an allowlist.
func appendMeta(out []metaString, field, text string) []metaString {
	text = strings.TrimSpace(text)
	if len(text) < 8 || len(out) >= maxMetaStrings {
		return out
	}
	if !utf8.ValidString(text) {
		text = strings.ToValidUTF8(text, "")
	}
	return append(out, metaString{Field: field, Text: text})
}
