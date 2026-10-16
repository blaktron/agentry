package handle

import (
	"slices"
	"strings"
	"testing"
)

func TestValid(t *testing.T) {
	for h, want := range map[string]bool{
		"a":                     true,
		"blaktron":              true,
		"a-b":                   true,
		"0x1":                   true,
		strings.Repeat("a", 40): true,
		strings.Repeat("a", 41): false,
		"":                      false,
		"-a":                    false,
		"a-":                    false,
		"A":                     false,
		"a_b":                   false,
		"a.b":                   false,
		"ünï":                   false,
	} {
		if got := Valid(h); got != want {
			t.Errorf("Valid(%q) = %v, want %v", h, got, want)
		}
	}
}

func TestReserved(t *testing.T) {
	for h, want := range map[string]bool{
		"ui": true, "api": true, "login": true, "agentry": true, "secureagentry": true,
		"blaktron": false, "agentry-examples": false,
	} {
		if got := Reserved(h); got != want {
			t.Errorf("Reserved(%q) = %v, want %v", h, got, want)
		}
	}
	if IsPath("agentry") || !IsFirstParty("agentry") {
		t.Error("agentry is a first-party name, not a path")
	}
}

// TestNamesAreSortedValidHandles: the lists a directory copies are sorted,
// free of duplicates, and every entry is something a person could
// otherwise have chosen, so reserving it means something.
func TestNamesAreSortedValidHandles(t *testing.T) {
	for name, list := range map[string][]string{"path": PathNames(), "first-party": FirstPartyNames()} {
		if !slices.IsSorted(list) {
			t.Errorf("%s names are not sorted: %v", name, list)
		}
		if len(slices.Compact(slices.Clone(list))) != len(list) {
			t.Errorf("%s names repeat: %v", name, list)
		}
		for _, h := range list {
			if !Valid(h) {
				t.Errorf("%s name %q is not a valid handle", name, h)
			}
		}
	}
	got := PathNames()
	got[0] = "changed"
	if PathNames()[0] == "changed" {
		t.Error("PathNames hands out the package's own list")
	}
}
