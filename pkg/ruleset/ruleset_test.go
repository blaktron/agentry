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
	"0.3.0": "727f7cf4ed91e09e127a1826cdd80c27da89c1431657fa4af01058434416d320",
	"0.3.1": "781d4e9788989bff4a2c5507a988c84bc9737898fb5254896d9caef8900b0c7a",
	"0.3.2": "9f626807737fec785dd4bf1d170fcc5abc6fee16e7f35b76422bee8a8b92f275",
	"0.3.3": "70613140ee82c520a8d1bfe294896a2c064b74f4237324224808afe0538ccff8",
	"0.3.4": "fe314e7919459a75dad54ec877c178f8257ec7dffbf5927d0e14eb6a7275d581",
	"0.4.0": "edb8b362b370edf7ff55375795e535155033138b7164fdb76c07a3811b5b917a",
	"0.4.1": "fb63d649b09993b2d8c414909929cad58d1628e1b640f73f75824ec9ac539e5f",
	"0.4.2": "24263e3ac50b399bb59ad33bafeae902f9ceee317211e0fb1c48e37777fcc7ac",
	"0.4.3": "ef91b334344c20bf9acf7dd7877d840483d1c9b67172b6b31b24310195b898de",
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

func TestEveryReleasedVersionNamesItsThreshold(t *testing.T) {
	b, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for v := range releasedDigests {
		if _, ok := baselineThresholds[v]; !ok {
			t.Errorf("released bundle %s has no baseline threshold: add it to baselineThresholds", v)
		}
	}
	if _, ok := baselineThresholds[b.Version()]; !ok {
		t.Fatalf("the embedded bundle %s has no baseline threshold", b.Version())
	}
	if got := BaselineMaxAutoPublishSeverity(); got != baselineThresholds[b.Version()] {
		t.Fatalf("BaselineMaxAutoPublishSeverity() = %q, want %q for bundle %s", got, baselineThresholds[b.Version()], b.Version())
	}
}

// The thresholds of released versions are history: 0.3.0 is the first
// version that publishes on medium (agentry#773).
func TestReleasedThresholdsAreHistory(t *testing.T) {
	for v, want := range map[string]string{"0.2.3": "low", "0.3.0": "medium", "0.3.1": "medium", "0.3.2": "medium", "0.3.3": "medium", "0.3.4": "medium", "0.4.0": "medium", "0.4.1": "medium", "0.4.2": "medium", "0.4.3": "medium", "0.0.0-unknown": "low"} {
		if got := BaselineMaxAutoPublishSeverityFor(v); got != want {
			t.Errorf("BaselineMaxAutoPublishSeverityFor(%q) = %q, want %q", v, got, want)
		}
	}
}
