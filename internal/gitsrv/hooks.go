package gitsrv

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// RunPreReceiveHook implements `agentryd hook pre-receive`. git runs
// it inside the bare repo with "old new ref" lines on stdin; the request
// context (pusher permissions, quotas) arrives via AGENTRY_HOOK_* env vars
// set by the serving process. Exit non-zero rejects the push; stderr lines
// reach the git client.
//
// Enforced here (object-level checks are possible because git exposes the
// quarantined incoming objects to hooks):
//   - v* tags: creation requires publish permission; updating or deleting
//     an existing v* tag is always denied (immutable version namespace)
//   - default branch: no deletion; no force-push unless allowed
//   - new tips: no nested .git entries, no blobs over the size cap
//   - repo quota: approximate disk usage check; over the warn tier
//     the push succeeds and the pusher is told (git relays hook stderr as
//     "remote:" lines)
func RunPreReceiveHook(stdin io.Reader, stderr io.Writer) int {
	deny := func(format string, args ...any) int {
		_, _ = fmt.Fprintf(stderr, "agentry: "+format+"\n", args...)
		return 1
	}

	defaultBranch := envOr("AGENTRY_HOOK_DEFAULT_BRANCH", "main")
	canPublish := os.Getenv("AGENTRY_HOOK_CAN_PUBLISH") == "true"
	allowForce := os.Getenv("AGENTRY_HOOK_ALLOW_FORCE") == "true"
	maxBlob := envInt("AGENTRY_HOOK_MAX_BLOB_BYTES", 25<<20)
	quota := envInt("AGENTRY_HOOK_QUOTA_BYTES", 100<<20)
	warn := envInt("AGENTRY_HOOK_WARN_BYTES", 25<<20)

	scanner := bufio.NewScanner(stdin)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		if len(parts) != 3 {
			// git speaks exactly "<old> <new> <ref>" here. Anything else
			// means we cannot tell what is being pushed, so we refuse it
			// rather than let an unchecked ref update through.
			return deny("unreadable ref update from git: %q", line)
		}
		oldOID, newOID, ref := parts[0], parts[1], parts[2]

		// Protected version-tag namespace. The leading letter is matched
		// without regard to case, so refs/tags/V1.0.0 is held like
		// refs/tags/v1.0.0.
		if isVersionTagRef(ref) {
			if oldOID != zeroOID {
				return deny("version tags are immutable: %s cannot be updated or deleted", ref)
			}
			if !canPublish {
				return deny("creating %s requires publish permission on this agent", ref)
			}
		}

		if ref == "refs/heads/"+defaultBranch {
			if newOID == zeroOID {
				return deny("the default branch cannot be deleted")
			}
			if oldOID != zeroOID && !allowForce {
				// Non-fast-forward = old is not an ancestor of new.
				if err := gitOK("merge-base", "--is-ancestor", oldOID, newOID); err != nil {
					return deny("force-push to the default branch is not allowed")
				}
			}
		}

		// Content policy on the new tip (branch or tag target).
		if newOID != zeroOID {
			if msg := checkTree(newOID, maxBlob); msg != "" {
				return deny("%s", msg)
			}
		}
	}
	// Fail closed on a truncated or unreadable stdin: the ref lines we never
	// saw would otherwise be applied without ever being policed.
	if err := scanner.Err(); err != nil {
		return deny("could not read the ref updates from git: %v", err)
	}

	// Approximate quota: current repo dir + incoming quarantine.
	usage := duCwd()
	if usage > quota {
		return deny("repository exceeds the %d MB size quota", quota>>20)
	}
	if warn > 0 && usage > warn {
		_, _ = fmt.Fprintf(stderr, "agentry: warning: repository is %d MB of the %d MB quota\n", usage>>20, quota>>20)
	}
	return 0
}

// isVersionTagRef reports whether ref names a tag in the version namespace:
// refs/tags/ followed by a v or a V.
func isVersionTagRef(ref string) bool {
	rest, ok := strings.CutPrefix(ref, "refs/tags/")
	return ok && (strings.HasPrefix(rest, "v") || strings.HasPrefix(rest, "V"))
}

// checkTree scans the tip tree for nested .git entries and oversized blobs.
// History interior is intentionally not scanned: receive.maxInputSize caps
// pack size and the tip is what archives/scans consume.
//
// It fails closed: a tip that git cannot resolve or list is refused. The one
// object with no tree to scan is a tag that peels to a single file, which is
// held to the file-size limit alone.
func checkTree(oid string, maxBlob int) string {
	// Peel any chain of tags to the commit, tree or blob underneath.
	peeled, err := gitOutput("rev-parse", "--verify", "--end-of-options", oid+"^{}")
	if err != nil {
		return "could not read the pushed object " + oid
	}
	kind, err := gitOutput("cat-file", "-t", peeled)
	if err != nil {
		return "could not read the pushed object " + oid
	}
	if kind == "blob" {
		sz, err := gitOutput("cat-file", "-s", peeled)
		if err != nil {
			return "could not read the pushed object " + oid
		}
		if size, err := strconv.Atoi(sz); err == nil && size > maxBlob {
			return fmt.Sprintf("%s exceeds the %d MB single-file limit", oid, maxBlob>>20)
		}
		return ""
	}
	// -z prints each path verbatim, NUL-terminated; without it git wraps a
	// path with an unusual byte in quotes and escapes it, and a ".git"
	// segment at either end of such a path would no longer compare equal.
	out, err := exec.Command("git", "ls-tree", "-r", "-l", "-z", "--end-of-options", peeled+"^{tree}").Output() //nolint:gosec // fixed binary, oid resolved by git above
	if err != nil {
		return "could not read the tree of the pushed object " + oid
	}
	for _, line := range strings.Split(string(out), "\x00") {
		// <mode> <type> <oid> <size>\t<path>
		tab := strings.IndexByte(line, '\t')
		if tab < 0 {
			continue
		}
		meta := strings.Fields(line[:tab])
		path := line[tab+1:]
		for _, seg := range strings.Split(path, "/") {
			if strings.EqualFold(seg, ".git") {
				return "nested .git entries are not allowed: " + path
			}
		}
		if len(meta) == 4 && meta[1] == "blob" {
			if size, err := strconv.Atoi(meta[3]); err == nil && size > maxBlob {
				return fmt.Sprintf("%s exceeds the %d MB single-file limit", path, maxBlob>>20)
			}
		}
	}
	return ""
}

// gitOutput runs git with fixed arguments and returns its trimmed stdout.
func gitOutput(args ...string) (string, error) {
	out, err := exec.Command("git", args...).Output() //nolint:gosec // fixed binary, arguments built by the hook
	return strings.TrimSpace(string(out)), err
}

func gitOK(args ...string) error {
	cmd := exec.Command("git", args...) //nolint:gosec // fixed args from hook logic
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	return cmd.Run()
}

func duCwd() int {
	total := 0
	_ = filepath.Walk(".", func(_ string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			total += int(info.Size())
		}
		return nil
	})
	return total
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
