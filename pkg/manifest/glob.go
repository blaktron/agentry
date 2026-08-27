package manifest

import (
	"fmt"
	"path"
	"strings"
)

// matchGlob reports whether the slash-separated, repo-relative file path p
// matches pattern. Each pattern segment uses path.Match syntax; the whole
// segment "**" additionally matches any number (including zero) of path
// segments. "**" is only special as an entire segment — inside a segment
// (e.g. "a**b") the stars are ordinary path.Match wildcards.
func matchGlob(pattern, p string) (bool, error) {
	pat := collapseDoubleStars(strings.Split(pattern, "/"))
	segs := strings.Split(p, "/")
	failed := make(map[[2]int]bool)
	ok, err := matchSegs(pat, segs, 0, 0, failed)
	if err != nil {
		return false, fmt.Errorf("include pattern %q: %w", pattern, err)
	}
	return ok, nil
}

// collapseDoubleStars removes redundant adjacent "**" segments so the
// matcher's branching is bounded.
func collapseDoubleStars(pat []string) []string {
	out := pat[:0:0]
	for _, s := range pat {
		if s == "**" && len(out) > 0 && out[len(out)-1] == "**" {
			continue
		}
		out = append(out, s)
	}
	return out
}

// matchSegs matches pat[pi:] against segs[si:]. failed memoizes entry
// states already proven not to match, bounding the walk by
// len(pat)*len(segs) entry states even for adversarial patterns.
func matchSegs(pat, segs []string, pi, si int, failed map[[2]int]bool) (bool, error) {
	key := [2]int{pi, si}
	if failed[key] {
		return false, nil
	}
	ok, err := matchSegsUncached(pat, segs, pi, si, failed)
	if err == nil && !ok {
		failed[key] = true
	}
	return ok, err
}

// matchSegsUncached does the actual walk; every recursion goes back
// through the memoizing matchSegs.
func matchSegsUncached(pat, segs []string, pi, si int, failed map[[2]int]bool) (bool, error) {
	for pi < len(pat) {
		if pat[pi] == "**" {
			for i := si; i <= len(segs); i++ {
				ok, err := matchSegs(pat, segs, pi+1, i, failed)
				if err != nil || ok {
					return ok, err
				}
			}
			return false, nil
		}
		if si == len(segs) {
			return false, nil
		}
		ok, err := path.Match(pat[pi], segs[si])
		if err != nil || !ok {
			return false, err
		}
		pi++
		si++
	}
	return si == len(segs), nil
}
