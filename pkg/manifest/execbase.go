package manifest

import "slices"

// baseExecCommands are the commands every machine provides to a QuickAgent
// that declares them, a hosted run included: the busybox applets of DR-64,
// agentry-cli's policy.BaseExecCommands, whose test holds the two lists
// equal. A declared command outside them is one only a run on the person's
// own computer, with that program installed, can provide. The rating by
// declaration (ruleset 0.4.0, agentry#893) reads it: a finding about a base
// command is low, one about any other declared command medium.
var baseExecCommands = []string{
	// reading and comparing text
	"cat", "head", "tail", "wc", "cut", "tr", "sort", "uniq", "grep", "comm", "diff", "cmp",
	"nl", "fold", "rev", "tac", "paste", "od", "hexdump", "strings",
	// files and paths
	"ls", "tree", "stat", "du", "basename", "dirname", "realpath",
	// checksums and encodings
	"base64", "md5sum", "sha1sum", "sha256sum", "sha512sum", "cksum",
	// archives
	"tar", "unzip", "gunzip", "bunzip2", "unxz", "zcat", "bzcat", "xzcat",
}

// BaseExecCommands returns the commands every machine provides, sorted.
func BaseExecCommands() []string {
	out := slices.Clone(baseExecCommands)
	slices.Sort(out)
	return out
}
