package scan

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
)

// TestS2HistoryReportsEachDistinctSecret pins that two different secrets one
// rule matches are two findings, each naming where it was committed, whether
// they sit in two files, in two commits of one file, or on one line; and that
// one secret committed again and again stays one finding.
func TestS2HistoryReportsEachDistinctSecret(t *testing.T) {
	const (
		first  = "AKIAI44QH8DHBEXAMPLE"
		second = "AKIAJ5ZCLPN4EXAMPLE0"
	)
	cases := []struct {
		name    string
		steps   []map[string]*string
		want    []string // the file each finding names
		commits int      // how many commits the findings name apart
		columns int      // how many columns the findings name apart
	}{
		{"two files", []map[string]*string{
			{"a.env": textOf("AWS_ACCESS_KEY_ID=" + first + "\n"), "b.env": textOf("AWS_ACCESS_KEY_ID=" + second + "\n")},
			{"a.env": nil, "b.env": nil},
		}, []string{"a.env", "b.env"}, 1, 1},
		{"two commits of one file", []map[string]*string{
			{"deploy.env": textOf("AWS_ACCESS_KEY_ID=" + first + "\n")},
			{"deploy.env": textOf("AWS_ACCESS_KEY_ID=" + second + "\n")},
			{"deploy.env": nil},
		}, []string{"deploy.env", "deploy.env"}, 2, 1},
		{"one line", []map[string]*string{
			{"keys.txt": textOf("old " + first + " new " + second + "\n")},
			{"keys.txt": nil},
		}, []string{"keys.txt", "keys.txt"}, 1, 2},
		{"one secret in every commit", []map[string]*string{
			{"a.env": textOf("AWS_ACCESS_KEY_ID=" + first + "\n")},
			{"a.env": textOf("AWS_ACCESS_KEY_ID=" + first + "\nREGION=eu-west-1\n")},
			{"b.env": textOf("AWS_ACCESS_KEY_ID=" + first + "\n")},
		}, []string{"b.env"}, 1, 1}, // one finding, for the first commit the newest-first stream shows
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			patch := gitHistoryOf(t, c.steps...)
			findings, truncated, err := scanHistoryPatch(strings.NewReader(patch))
			if err != nil || truncated {
				t.Fatalf("err=%v truncated=%v", err, truncated)
			}
			var got []string
			commits, columns := map[string]bool{}, map[int]bool{}
			for _, f := range findings {
				if f.Scanner != "S2/history-aws-access-key" {
					continue
				}
				got = append(got, f.FilePath)
				commits[f.Detail["commit"].(string)] = true
				columns[f.Detail["column"].(int)] = true
				if strings.Contains(f.Excerpt, first) || strings.Contains(f.Excerpt, second) {
					t.Errorf("excerpt is not redacted: %q", f.Excerpt)
				}
			}
			// Git lists the newest commit first, so read the files as a set.
			got = slices.Sorted(slices.Values(got))
			want := slices.Sorted(slices.Values(c.want))
			if !slices.Equal(got, want) {
				t.Fatalf("findings name %v, want %v", got, want)
			}
			if len(commits) != c.commits || len(columns) != c.columns {
				t.Errorf("findings name %d commits and %d columns, want %d and %d", len(commits), len(columns), c.commits, c.columns)
			}
		})
	}
}

// TestS2HistoryFindingLimitSaysWhichLimit pins that a history with more
// findings than the report lists says how many more, and is not reported as
// truncated, which is the size cap's finding.
func TestS2HistoryFindingLimitSaysWhichLimit(t *testing.T) {
	in := &Input{Source: "git-tag", History: func(context.Context) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(historyAssignments(historyMaxFindings + 1))), nil
	}}
	findings, _ := s2History(context.Background(), in)
	limit := 0
	for _, f := range findings {
		switch f.Scanner {
		case scannerHistoryTruncated:
			t.Fatalf("a history read to its end is reported truncated: %+v", f)
		case scannerHistoryFindingLimit:
			limit++
			if f.Severity != SevLow || f.Detail["maxFindings"] != historyMaxFindings || f.Detail["notShown"] != 1 {
				t.Errorf("finding-limit finding = %+v", f)
			}
		}
	}
	if limit != 1 {
		t.Fatalf("%d finding-limit findings after %d distinct secrets, want 1", limit, historyMaxFindings+1)
	}
}

// TestS2HistoryDecoysCannotHideAnOlderSecret pins that newer commits full of
// distinct medium-rated decoys cannot push an older high-severity secret off
// the report: the scan reads every commit, keeps the most severe findings,
// and the version is held rather than published at the baseline.
func TestS2HistoryDecoysCannotHideAnOlderSecret(t *testing.T) {
	var decoys strings.Builder
	for i := range historyMaxFindings {
		fmt.Fprintf(&decoys, "token = %q\n", fakeBase64(fmt.Sprintf("decoy %d", i), 24))
	}
	patch := gitHistoryOf(t,
		map[string]*string{"old.env": textOf("AWS_ACCESS_KEY_ID=AKIAI44QH8DHBEXAMPLE\n")},
		map[string]*string{"old.env": nil},
		map[string]*string{"decoys.conf": textOf(decoys.String())},
	)
	findings, _ := s2History(context.Background(), &Input{Source: "git-tag", History: func(context.Context) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(patch)), nil
	}})
	var aws, decoyFindings, limit int
	for _, f := range findings {
		switch f.Scanner {
		case "S2/history-aws-access-key":
			aws++
			if f.FilePath != "old.env" {
				t.Errorf("the older secret is placed in %q", f.FilePath)
			}
		case "S2/history-generic-assignment":
			decoyFindings++
		case scannerHistoryFindingLimit:
			limit++
		}
	}
	if aws != 1 || decoyFindings != historyMaxFindings-1 || limit != 1 {
		t.Fatalf("aws=%d decoys=%d limit=%d, want 1, %d, 1: %+v", aws, decoyFindings, limit, historyMaxFindings-1, findings)
	}
	if got := Evaluate(GateInput{Findings: findings, Policy: DefaultBaseline()}); got.Outcome == OutcomePublish {
		t.Fatalf("a history whose older secret sits behind decoys published: %+v", got)
	}
}

// TestS2HistorySizeCapHoldsTheVersion pins that a history the scan stopped
// reading at the size cap is not published at the baseline: older commits
// went unread, so the gate sends it to a person whatever its other findings.
func TestS2HistorySizeCapHoldsTheVersion(t *testing.T) {
	findings, ran := s2History(context.Background(), &Input{Source: "git-tag", History: func(context.Context) (io.ReadCloser, error) {
		return io.NopCloser(io.MultiReader(&contextLines{size: historyPatchCap}, strings.NewReader("\n"))), nil
	}})
	if !ran || len(findings) != 1 || findings[0].Scanner != scannerHistoryTruncated {
		t.Fatalf("findings = %+v ran=%v, want one %s", findings, ran, scannerHistoryTruncated)
	}
	got := Evaluate(GateInput{Findings: findings, Policy: DefaultBaseline()})
	if got.Outcome != OutcomeNeedsReview || got.branch != branchCouldNotScan {
		t.Fatalf("a history stopped at the size cap: %+v", got)
	}
}
