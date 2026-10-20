package scan

import (
	"context"
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

// TestS2HistoryFindingLimitSaysWhichLimit pins that a history stopped by the
// finding limit says so, rather than claiming the size cap stopped it.
func TestS2HistoryFindingLimitSaysWhichLimit(t *testing.T) {
	in := &Input{Source: "git-tag", History: func(context.Context) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(historyAssignments(historyMaxFindings + 1))), nil
	}}
	findings, _ := s2History(context.Background(), in)
	for _, f := range findings {
		if f.Scanner == "S2/history-truncated" {
			if f.Detail["maxFindings"] != historyMaxFindings || !strings.Contains(f.Title, "finding limit") {
				t.Fatalf("truncation by the finding limit reads %q %v", f.Title, f.Detail)
			}
			return
		}
	}
	t.Fatalf("no S2/history-truncated finding after %d distinct secrets", historyMaxFindings+1)
}
