package scan

import (
	"encoding/json"
	"path/filepath"
	"strings"
)

// Lockfile parsing for S7 (§8.3: "Lockfile audit"). The stage needs the actual
// resolved dependency set — not merely "a lockfile exists" — to answer three
// questions offline: does the lockfile cover everything package.json declares
// (V6), is every entry pinned by an integrity hash, and what names should the
// typosquat and OSV checks be run against.
//
// Three formats are understood, matching the kinds Agentry accepts (D-14:
// JS/TS + Python):
//
//   - package-lock.json — npm v1 ("dependencies" tree) and v2/v3 ("packages"
//     map keyed by install path).
//   - uv.lock — TOML, an array of [[package]] tables.
//   - requirements.txt — pinned `name==version` lines, optionally with
//     `--hash=` continuations (pip's hash-checking mode).

// lockEntry is one resolved dependency as the lockfile records it.
type lockEntry struct {
	// Name is the package name as the registry knows it.
	Name string
	// Version is the exact resolved version, when the format records one.
	Version string
	// Pinned reports whether the entry carries an integrity/hash pin
	// (npm `integrity`, uv/pip `--hash=`). An unpinned entry is installable
	// from mutable bytes.
	Pinned bool
	// License is the license the lockfile records for the entry, when it does
	// (npm v2/v3 sometimes carries one). Empty means "not recorded".
	License string
}

// lockfile is one parsed dependency lock.
type lockfile struct {
	// Path is the archive-relative path the lock was read from.
	Path string
	// Kind is the format ("npm", "uv", "pip").
	Kind string
	// Entries is name → resolved entry.
	Entries map[string]lockEntry
}

// lockfileNames maps a base filename to the parser that understands it.
func lockfileKind(base string) string {
	switch base {
	case "package-lock.json", "npm-shrinkwrap.json":
		return "npm"
	case "uv.lock":
		return "uv"
	case "requirements.txt":
		return "pip"
	}
	return ""
}

// parseLockfile dispatches on the file's base name. It returns nil for files
// it does not recognise and for locks it cannot parse — a malformed lock is
// reported by the caller as a finding, never as a silent "no dependencies".
func parseLockfile(path string, data []byte) *lockfile {
	switch lockfileKind(filepath.Base(path)) {
	case "npm":
		return parsePackageLock(path, data)
	case "uv":
		return parseUVLock(path, data)
	case "pip":
		return parseRequirements(path, data)
	}
	return nil
}

// npmLock is the subset of package-lock.json S7 reads. Both the v1
// "dependencies" tree and the v2/v3 "packages" map are present in a v2 lock;
// "packages" wins because it is the authoritative one from npm 7 onward.
type npmLock struct {
	LockfileVersion int `json:"lockfileVersion"`
	Packages        map[string]struct {
		Version   string `json:"version"`
		Integrity string `json:"integrity"`
		License   string `json:"license"`
		Dev       bool   `json:"dev"`
	} `json:"packages"`
	Dependencies map[string]struct {
		Version   string `json:"version"`
		Integrity string `json:"integrity"`
	} `json:"dependencies"`
}

// parsePackageLock reads npm lockfile v1, v2 and v3.
func parsePackageLock(path string, data []byte) *lockfile {
	var l npmLock
	if err := json.Unmarshal(data, &l); err != nil {
		return nil
	}
	lf := &lockfile{Path: path, Kind: "npm", Entries: map[string]lockEntry{}}
	for key, p := range l.Packages {
		// "" is the root project; nested paths are "node_modules/<name>" or
		// "packages/x/node_modules/<name>" for workspaces. The package name is
		// everything after the LAST "node_modules/" so scoped names survive.
		name := npmPackageName(key)
		if name == "" {
			continue
		}
		lf.Entries[name] = lockEntry{
			Name: name, Version: p.Version,
			Pinned: p.Integrity != "", License: p.License,
		}
	}
	// v1 locks have no "packages" map at all.
	for name, d := range l.Dependencies {
		if _, ok := lf.Entries[name]; ok {
			continue
		}
		lf.Entries[name] = lockEntry{Name: name, Version: d.Version, Pinned: d.Integrity != ""}
	}
	return lf
}

// npmPackageName extracts the dependency name from a package-lock "packages"
// key. Returns "" for the root entry and for workspace-local packages, which
// are not registry dependencies.
func npmPackageName(key string) string {
	const marker = "node_modules/"
	i := strings.LastIndex(key, marker)
	if i < 0 {
		return ""
	}
	return key[i+len(marker):]
}

// parseUVLock reads the [[package]] tables out of a uv.lock. It is a
// deliberately small TOML reader rather than a dependency: uv.lock's shape is
// a flat array of tables with scalar name/version keys, and adding a TOML
// library to parse three keys would be a supply-chain cost for the scanner
// itself (see DEV-026).
func parseUVLock(path string, data []byte) *lockfile {
	lf := &lockfile{Path: path, Kind: "uv", Entries: map[string]lockEntry{}}
	var cur lockEntry
	table := ""
	flush := func() {
		if cur.Name != "" {
			lf.Entries[cur.Name] = cur
		}
		cur = lockEntry{}
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			// A new table header ends the scalar section of the current one.
			// [[package]] starts a new entry; any other header (including
			// [package.metadata]) only changes the context.
			if line == "[[package]]" {
				flush()
			}
			table = strings.Trim(line, "[]")
			continue
		}
		key, val, ok := tomlScalar(line)
		if !ok {
			continue
		}
		switch {
		case table == "package" && key == "name":
			cur.Name = val
		case table == "package" && key == "version":
			cur.Version = val
		case strings.HasPrefix(table, "package.") && key == "hash":
			// wheels/sdist hashes live in nested tables of the current package.
			cur.Pinned = true
		case table == "package" && key == "hash":
			cur.Pinned = true
		}
		// Inline hashes on wheel arrays: `{ url = "...", hash = "sha256:..." }`.
		if strings.HasPrefix(table, "package") && strings.Contains(line, "hash = \"") {
			cur.Pinned = true
		}
	}
	flush()
	return lf
}

// tomlScalar splits `key = "value"` (or a bare value) into its parts.
func tomlScalar(line string) (key, val string, ok bool) {
	i := strings.Index(line, "=")
	if i < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:i])
	val = strings.TrimSpace(line[i+1:])
	val = strings.TrimSuffix(strings.TrimSpace(strings.Trim(val, ",")), ",")
	if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
		val = val[1 : len(val)-1]
	}
	return key, val, key != ""
}

// parseRequirements reads a pinned requirements.txt. Only `name==version`
// lines count as resolved entries: a bare `requests` or a range is not a lock,
// and treating it as one would report coverage the file does not provide.
func parseRequirements(path string, data []byte) *lockfile {
	lf := &lockfile{Path: path, Kind: "pip", Entries: map[string]lockEntry{}}
	// pip continues a requirement across lines with a trailing backslash; join
	// them so a `--hash=` on the next line belongs to its requirement.
	joined := strings.ReplaceAll(string(data), "\\\n", " ")
	for _, raw := range strings.Split(joined, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-r") ||
			strings.HasPrefix(line, "--index") || strings.HasPrefix(line, "-i ") {
			continue
		}
		hashed := strings.Contains(line, "--hash=")
		// Strip options and inline comments before splitting the pin.
		if i := strings.Index(line, " --"); i >= 0 {
			line = line[:i]
		}
		if i := strings.Index(line, " #"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		name, version, ok := strings.Cut(line, "==")
		if !ok {
			continue
		}
		name = strings.TrimSpace(pipBaseName(name))
		version = strings.TrimSpace(version)
		if name == "" {
			continue
		}
		lf.Entries[normalizePyName(name)] = lockEntry{
			Name: normalizePyName(name), Version: version, Pinned: hashed,
		}
	}
	return lf
}

// pipBaseName drops an extras suffix: `uvicorn[standard]` → `uvicorn`.
func pipBaseName(s string) string {
	if i := strings.Index(s, "["); i >= 0 {
		return s[:i]
	}
	return s
}

// normalizePyName applies PEP 503 name normalization so `Flask_Login` and
// `flask-login` compare equal.
func normalizePyName(s string) string {
	s = strings.ToLower(s)
	repl := strings.NewReplacer("_", "-", ".", "-")
	out := repl.Replace(s)
	for strings.Contains(out, "--") {
		out = strings.ReplaceAll(out, "--", "-")
	}
	return out
}

// packageJSON is the subset of package.json S7 reads.
type packageJSON struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	License      string            `json:"license"`
	Scripts      map[string]string `json:"scripts"`
	Dependencies map[string]string `json:"dependencies"`
	DevDeps      map[string]string `json:"devDependencies"`
	OptionalDeps map[string]string `json:"optionalDependencies"`
}

// parsePackageJSON returns the parsed manifest, or nil when it will not parse.
func parsePackageJSON(data []byte) *packageJSON {
	var p packageJSON
	if err := json.Unmarshal(data, &p); err != nil {
		return nil
	}
	return &p
}

// runtimeDeps are the dependencies that ship to a consumer — devDependencies
// are excluded from the V6 coverage check because they are not installed by
// `npm install --omit=dev` and their absence from a production lock is normal.
func (p *packageJSON) runtimeDeps() map[string]string {
	return merged(p.Dependencies, p.OptionalDeps)
}

// pyprojectDeps extracts the `dependencies = [...]` list of a pyproject.toml
// well enough to check lock coverage. Same reasoning as parseUVLock: the shape
// is a flat array of requirement strings.
func pyprojectDeps(data []byte) map[string]string {
	out := map[string]string{}
	inList := false
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "dependencies") && strings.Contains(line, "["):
			inList = true
			if i := strings.Index(line, "["); i >= 0 {
				line = line[i+1:]
			}
		case !inList:
			continue
		}
		if strings.Contains(line, "]") {
			line = line[:strings.Index(line, "]")]
			inList = false
		}
		for _, part := range strings.Split(line, ",") {
			part = strings.TrimSpace(strings.Trim(strings.TrimSpace(part), `"'`))
			if part == "" {
				continue
			}
			name := part
			if i := strings.IndexAny(part, "=<>!~ ;["); i >= 0 {
				name = part[:i]
			}
			if name = normalizePyName(strings.TrimSpace(name)); name != "" {
				out[name] = part
			}
		}
	}
	return out
}
