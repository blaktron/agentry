package manifest

import "strings"

// spdxIDs is a small embedded allowlist of ~60 common SPDX license
// identifiers used by V7 to check that a public manifest declares a
// plausible license. It is intentionally not the full SPDX list; unknown
// ids fail public publish (§5.3 V7). Lookup is case-insensitive; keys are
// stored lowercase and values carry the canonical spelling.
var spdxIDs = func() map[string]string {
	canonical := []string{
		"0BSD",
		"AFL-3.0",
		"AGPL-3.0-only",
		"AGPL-3.0-or-later",
		"Apache-1.1",
		"Apache-2.0",
		"Artistic-2.0",
		"BlueOak-1.0.0",
		"BSD-1-Clause",
		"BSD-2-Clause",
		"BSD-2-Clause-Patent",
		"BSD-3-Clause",
		"BSD-3-Clause-Clear",
		"BSD-4-Clause",
		"BSL-1.0",
		"CC-BY-3.0",
		"CC-BY-4.0",
		"CC-BY-SA-4.0",
		"CC0-1.0",
		"CDDL-1.0",
		"CDDL-1.1",
		"CECILL-2.1",
		"ECL-2.0",
		"EPL-1.0",
		"EPL-2.0",
		"EUPL-1.1",
		"EUPL-1.2",
		"GFDL-1.3-only",
		"GPL-2.0-only",
		"GPL-2.0-or-later",
		"GPL-3.0-only",
		"GPL-3.0-or-later",
		"ISC",
		"LGPL-2.0-only",
		"LGPL-2.1-only",
		"LGPL-2.1-or-later",
		"LGPL-3.0-only",
		"LGPL-3.0-or-later",
		"LPPL-1.3c",
		"MIT",
		"MIT-0",
		"MPL-1.1",
		"MPL-2.0",
		"MS-PL",
		"MS-RL",
		"NCSA",
		"ODbL-1.0",
		"OFL-1.1",
		"OSL-3.0",
		"PHP-3.01",
		"PostgreSQL",
		"Python-2.0",
		"Ruby",
		"Unlicense",
		"UPL-1.0",
		"Vim",
		"WTFPL",
		"X11",
		"Zlib",
		"zlib-acknowledgement",
	}
	m := make(map[string]string, len(canonical))
	for _, id := range canonical {
		m[strings.ToLower(id)] = id
	}
	return m
}()

// KnownSPDXID reports whether id is on the embedded SPDX allowlist,
// matching case-insensitively, and returns the canonical spelling.
func KnownSPDXID(id string) (canonical string, ok bool) {
	canonical, ok = spdxIDs[strings.ToLower(id)]
	return canonical, ok
}
