package manifest

import "sort"

// ResolveInclude returns the files selected by publish.include
// patterns, in sorted path order. It is the shared filter between
// validation (V4) and the registry's archive builder, so the archive
// can never contain a file validation did not see. Symlinks and unsafe
// patterns are NOT filtered here: V4 rejects them; callers validate
// first.
func ResolveInclude(patterns []string, files []FileInfo) []FileInfo {
	var out []FileInfo
	for _, f := range files {
		for _, pat := range patterns {
			ok, err := matchGlob(pat, f.Path)
			if err == nil && ok {
				out = append(out, f)
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}
