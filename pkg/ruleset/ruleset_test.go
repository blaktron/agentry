package ruleset

import "testing"

// releasedDigests is every bundle version that has reached a registry, with
// the digest the server records for it in ruleset_releases (agentry#772).
// Entries are only ever added. A bundle whose content changes keeps its old
// digest here and fails the test below until its version is bumped and the
// new version pinned: a ruleset_releases row is keyed by semver, so two
// bundles under one semver would rewrite the row's digest and break the
// check against its ruleset/v<semver> tag (README.md). Compute a digest with
// `go run ./scripts/dev/ruleset-digest`.
var releasedDigests = map[string]string{
	"0.2.0": "9395e31404aefa5256103a3977d86ec482927a6717235a4a487952a65b9b4ed5",
	"0.2.1": "24def4274e46f12a7dddd6b10d018b166ce6a0414cc62c28e05f1718ece3c030",
	"0.2.2": "ba992698f2aac91d6a4ebdc570e1b26c5e73e62888a78dbce74882dde9f486d8",
	"0.2.3": "ac5f7cb4035e8c31e576ed311b6b33ffc4397f3cb461380cd3befdb59d63ccbd",
}

func TestEmbeddedBundleDigestIsPinnedForItsVersion(t *testing.T) {
	b, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	want, ok := releasedDigests[b.Version()]
	if !ok {
		t.Fatalf("bundle %s is not pinned: add %q: %q to releasedDigests", b.Version(), b.Version(), b.Digest())
	}
	if b.Digest() != want {
		t.Fatalf("bundle %s changed content under a released version (digest %s, pinned %s): bump the version in rules/bundle.yaml and pin the new one",
			b.Version(), b.Digest(), want)
	}
}
