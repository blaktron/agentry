// Command notices writes THIRD_PARTY_NOTICES, the licence and notice texts of
// the Go modules compiled into agentryd, in a form that is the same on every
// machine: modules sorted by path, no timestamps, the linux/amd64 build the
// container image uses.
//
//	go run ./scripts/notices            write THIRD_PARTY_NOTICES
//	go run ./scripts/notices -check     fail when the committed file differs
//
// For each module it takes the licence files nearest to each package that is
// compiled in (the package's directory, then its parents up to the module
// root), classifies each by its text, and copies the text in full, followed by
// the module's NOTICE files. A licence file it cannot classify fails the run,
// so a new dependency is never listed under a guessed licence. It reads only
// the module cache; it needs no network once the modules are downloaded.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	target = "THIRD_PARTY_NOTICES"
	root   = "./cmd/agentryd"
)

// platforms are the GOOS/GOARCH pairs agentryd is released for. A module
// compiled in on any one of them is listed, because each binary carries the
// notices of everything linked into it.
var platforms = [][2]string{
	{"linux", "amd64"}, {"linux", "arm64"},
	{"darwin", "amd64"}, {"darwin", "arm64"},
	{"windows", "amd64"},
}

var (
	licenceName = regexp.MustCompile(`(?i)^(licen[sc]e|copying|unlicen[sc]e)(\.(txt|md|mit|apache|bsd))?(-[A-Za-z0-9._-]*)?$`)
	noticeName  = regexp.MustCompile(`(?i)^notice(\.(txt|md))?$`)
)

type licenceFile struct {
	rel  string // path relative to the module root
	spdx string
	text string
}

type module struct {
	path, version string
	dir           string
	pkgDirs       map[string]bool
	licences      []licenceFile
	notices       []licenceFile
}

func main() {
	check := flag.Bool("check", false, "compare with the committed file instead of writing it")
	out := flag.String("o", target, "file to write or compare")
	flag.Parse()

	body, err := render()
	if err != nil {
		fmt.Fprintln(os.Stderr, "notices:", err)
		os.Exit(1)
	}
	if *check {
		have, err := os.ReadFile(*out)
		if err != nil || !bytes.Equal(have, body) {
			fmt.Fprintf(os.Stderr, "notices: %s is stale: run scripts/notices/generate.sh and commit the result\n", *out)
			os.Exit(1)
		}
		return
	}
	if err := os.WriteFile(*out, body, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "notices:", err)
		os.Exit(1)
	}
}

func goCmd(goos, goarch string, args ...string) (string, error) {
	cmd := exec.Command("go", args...)
	cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED=0", "GOWORK=off")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("go %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return string(out), nil
}

func render() ([]byte, error) {
	var listing strings.Builder
	for _, pl := range platforms {
		out, err := goCmd(pl[0], pl[1], "list", "-deps", "-f",
			`{{if .Module}}{{if not .Module.Main}}{{.Module.Path}}{{"\t"}}{{.Module.Version}}{{"\t"}}{{.Module.Dir}}{{"\t"}}{{.Dir}}{{end}}{{end}}`, root)
		if err != nil {
			return nil, err
		}
		listing.WriteString(out)
		listing.WriteString("\n")
	}
	mods := map[string]*module{}
	for _, line := range strings.Split(strings.TrimSpace(listing.String()), "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 4 {
			continue
		}
		m := mods[f[0]]
		if m == nil {
			m = &module{path: f[0], version: f[1], dir: f[2], pkgDirs: map[string]bool{}}
			mods[f[0]] = m
		}
		m.pkgDirs[f[3]] = true
	}
	if len(mods) == 0 {
		return nil, fmt.Errorf("no third-party modules found under %s", root)
	}
	paths := make([]string, 0, len(mods))
	for p := range mods {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		if err := mods[p].collect(); err != nil {
			return nil, err
		}
	}

	goVersion, err := goCmd("linux", "amd64", "list", "-m", "-f", "{{.GoVersion}}")
	if err != nil {
		return nil, err
	}
	goRoot, err := goCmd("linux", "amd64", "env", "GOROOT")
	if err != nil {
		return nil, err
	}
	goText, err := os.ReadFile(filepath.Join(strings.TrimSpace(goRoot), "LICENSE"))
	if err != nil {
		return nil, err
	}

	var b strings.Builder
	b.WriteString(preamble)
	section(&b, "Go standard library "+strings.TrimSpace(goVersion), "BSD-3-Clause", nil)
	b.WriteString(clean(string(goText)))
	for _, p := range paths {
		m := mods[p]
		section(&b, m.path+" "+m.version, m.spdx(), m.sourceNote())
		for i, l := range m.licences {
			if len(m.licences) > 1 {
				fmt.Fprintf(&b, "%s%s (%s)\n\n", sep(i), l.rel, l.spdx)
			}
			b.WriteString(clean(l.text))
		}
		for _, n := range m.notices {
			fmt.Fprintf(&b, "\nNOTICE (%s)\n\n", n.rel)
			b.WriteString(clean(n.text))
		}
	}
	return []byte(b.String()), nil
}

const preamble = `Third-party notices for agentryd

agentryd is distributed under the MIT licence (see LICENSE). It is built from
the Go standard library and the modules below, each under the licence stated
with it. The text of every licence and every NOTICE file follows. This file is
generated by scripts/notices/generate.sh from the modules compiled into
cmd/agentryd on every platform it is released for (linux, darwin and windows);
do not edit it by hand.
`

func sep(i int) string {
	if i == 0 {
		return ""
	}
	return "\n"
}

func section(b *strings.Builder, title, spdx string, notes []string) {
	b.WriteString("\n" + strings.Repeat("=", 78) + "\n")
	b.WriteString(title + "\n")
	b.WriteString("License: " + spdx + "\n")
	for _, n := range notes {
		b.WriteString(n + "\n")
	}
	b.WriteString(strings.Repeat("-", 78) + "\n\n")
}

// clean normalises line endings and ends the text with exactly one newline.
func clean(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.TrimRight(s, " \n\t") + "\n"
}

func (m *module) spdx() string {
	seen := map[string]bool{}
	var ids []string
	for _, l := range m.licences {
		if !seen[l.spdx] {
			seen[l.spdx] = true
			ids = append(ids, l.spdx)
		}
	}
	sort.Strings(ids)
	return strings.Join(ids, " AND ")
}

// sourceNote tells a recipient where the source of a file-level copyleft
// module is: the module is used as published, so its upstream repository
// holds exactly the files in the binary.
func (m *module) sourceNote() []string {
	for _, l := range m.licences {
		if l.spdx == "MPL-2.0" {
			parts := strings.Split(m.path, "/")
			if len(parts) > 3 && parts[0] == "github.com" {
				parts = parts[:3]
			}
			return []string{"Used unmodified. Source: https://" + strings.Join(parts, "/") + " at version " + m.version + "."}
		}
	}
	return nil
}

// collect finds, for every compiled-in package, the nearest directory at or
// above it (up to the module root) that holds a licence file, then reads
// the licence files there and the NOTICE files there and at the module root.
func (m *module) collect() error {
	dirs := map[string]bool{}
	for d := range m.pkgDirs {
		found := false
		for cur := d; ; cur = filepath.Dir(cur) {
			if hasMatch(cur, licenceName) {
				dirs[cur] = true
				found = true
				break
			}
			if cur == m.dir || !strings.HasPrefix(cur, m.dir) {
				break
			}
		}
		if !found {
			return fmt.Errorf("%s %s: no licence file at or above %s", m.path, m.version, d)
		}
	}
	noticeDirs := map[string]bool{m.dir: true}
	for d := range dirs {
		noticeDirs[d] = true
	}
	for _, d := range sortedKeys(dirs) {
		for _, name := range matching(d, licenceName) {
			text, err := os.ReadFile(filepath.Join(d, name))
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(m.dir, filepath.Join(d, name))
			id := classify(string(text))
			if id == "" {
				return fmt.Errorf("%s %s: cannot classify %s: add its licence to classify() in scripts/notices/main.go", m.path, m.version, rel)
			}
			m.licences = append(m.licences, licenceFile{rel: filepath.ToSlash(rel), spdx: id, text: string(text)})
		}
	}
	for _, d := range sortedKeys(noticeDirs) {
		for _, name := range matching(d, noticeName) {
			text, err := os.ReadFile(filepath.Join(d, name))
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(m.dir, filepath.Join(d, name))
			m.notices = append(m.notices, licenceFile{rel: filepath.ToSlash(rel), text: string(text)})
		}
	}
	return nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func hasMatch(dir string, re *regexp.Regexp) bool { return len(matching(dir, re)) > 0 }

// matching lists the regular files in dir whose names match re, sorted.
func matching(dir string, re *regexp.Regexp) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.Type().IsRegular() && re.MatchString(e.Name()) {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// classify names the SPDX identifier of a licence text by its distinctive
// wording, or returns "" for a text it does not know.
func classify(text string) string {
	t := strings.Join(strings.Fields(strings.ToLower(text)), " ")
	has := func(s ...string) bool {
		for _, x := range s {
			if !strings.Contains(t, x) {
				return false
			}
		}
		return true
	}
	switch {
	case has("apache license", "version 2.0, january 2004"):
		return "Apache-2.0"
	case has("mozilla public license version 2.0"):
		return "MPL-2.0"
	case has("redistribution and use in source and binary forms", "neither the name"):
		return "BSD-3-Clause"
	case has("redistribution and use in source and binary forms", "redistributions in binary form must reproduce"):
		return "BSD-2-Clause"
	case has("permission is hereby granted, free of charge", "the software is provided \"as is\""):
		return "MIT"
	case has("permission to use, copy, modify, and/or distribute this software for any purpose with or without fee"):
		return "ISC"
	}
	return ""
}
