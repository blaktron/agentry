package gitsrv

import (
	"bytes"
	"encoding/hex"
	"strings"
)

// commandCapture tees the leading pkt-line command section of a
// receive-pack request (everything before the PACK payload) into a bounded
// buffer for post-receive processing. Never blocks or fails the stream.
type commandCapture struct {
	buf  *bytes.Buffer
	done bool
}

const commandCaptureMax = 64 << 10 // commands are tiny; hard cap regardless

func newCommandCapture(buf *bytes.Buffer) *commandCapture {
	return &commandCapture{buf: buf}
}

func (c *commandCapture) Write(p []byte) (int, error) {
	if !c.done && c.buf.Len() < commandCaptureMax {
		room := commandCaptureMax - c.buf.Len()
		if len(p) < room {
			room = len(p)
		}
		c.buf.Write(p[:room])
		if bytes.Contains(c.buf.Bytes(), []byte("PACK")) {
			c.done = true
		}
	}
	return len(p), nil
}

// parseReceiveCommands extracts "old new ref" commands from a captured
// receive-pack request prefix. Tolerant: returns what it can parse.
func parseReceiveCommands(data []byte) []RefUpdate {
	var out []RefUpdate
	rest := data
	for len(rest) >= 4 {
		size, err := hex.DecodeString(string(rest[:4]))
		if err != nil || len(size) != 2 {
			break
		}
		n := int(size[0])<<8 | int(size[1])
		if n == 0 { // flush-pkt ends the command section
			break
		}
		if n < 4 || n > len(rest) {
			break
		}
		line := string(rest[4:n])
		rest = rest[n:]
		// First command line carries \x00 capability list; strip it.
		if i := strings.IndexByte(line, 0); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSuffix(line, "\n")
		parts := strings.SplitN(line, " ", 3)
		if len(parts) == 3 && len(parts[0]) == 40 && len(parts[1]) == 40 {
			out = append(out, RefUpdate{Old: parts[0], New: parts[1], Ref: parts[2]})
		}
	}
	return out
}
