// `agentry info` and `agentry search` (§11 discovery). There is no
// full-text search endpoint until M5, so search lists a namespace
// (GET /agents?namespace=) or, given ns/name, shows that agent's info.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/PLACEHOLDER_ORG/agentry/pkg/apiclient"
)

// newInfoCmd builds the info command.
func newInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info <ns/name>",
		Short: "Show an agent, its latest published version, and its capability contract",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInfo(cmd, args[0])
		},
	}
}

// newSearchCmd builds the search command.
func newSearchCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "search <query>",
		Short: "Find agents (namespace listing until full-text search lands in M5)",
		Long: "Find agents. A query containing \"/\" is treated as ns/name and shows that\n" +
			"agent's info; anything else lists the namespace's agents via\n" +
			"GET /agents?namespace=. Real full-text search lands with M5.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSearch(cmd, args[0])
		},
	}
}

// runInfo fetches and renders one agent.
func runInfo(cmd *cobra.Command, ref string) error {
	parts := strings.SplitN(ref, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("info wants ns/name, got %q", ref)
	}
	ns, name := parts[0], parts[1]

	reg := registryURL()
	client, err := newAPIClient(reg, credentialFor(reg))
	if err != nil {
		return err
	}

	agentResp, err := client.GetAgentWithResponse(cmd.Context(), ns, name)
	if err != nil {
		return fmt.Errorf("get agent %s: %w", ref, err)
	}
	if agentResp.JSON200 == nil {
		return apiProblem("get agent "+ref, agentResp.StatusCode(), agentResp.ApplicationproblemJSONDefault, agentResp.Body)
	}
	agent := agentResp.JSON200

	// Latest published version on the default (stable) channel; absence is
	// not an error — the agent may simply have no published versions yet.
	latest, latestErr := resolveRef(cmd.Context(), client, ns+"/"+name, false)

	if flags.jsonOut {
		doc := map[string]any{"agent": agent}
		if latestErr == nil {
			doc["latest"] = latest
		}
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		if err := enc.Encode(doc); err != nil {
			return fmt.Errorf("encode info: %w", err)
		}
		return nil
	}
	renderAgentInfo(cmd.OutOrStdout(), agent, latest, latestErr)
	return nil
}

// renderAgentInfo prints the human-readable info block.
func renderAgentInfo(out io.Writer, agent *apiclient.Agent, latest *apiclient.ResolveResult, latestErr error) {
	_, _ = fmt.Fprintf(out, "%s/%s — %s, %s\n", agent.Namespace, agent.Name, agent.Kind, agent.Visibility)
	if agent.Summary != "" {
		_, _ = fmt.Fprintf(out, "  summary: %s\n", agent.Summary)
	}
	_, _ = fmt.Fprintf(out, "  git:     %s\n", agent.GitHttpUrl)
	_, _ = fmt.Fprintf(out, "  created: %s\n", agent.CreatedAt.Format("2006-01-02"))
	if latestErr != nil {
		_, _ = fmt.Fprintln(out, "  latest:  no published version")
		return
	}
	_, _ = fmt.Fprintf(out, "  latest:  %s (%s)\n", latest.Version, latest.Digest)
	if m, err := manifestFromResolve(latest); err == nil {
		_, _ = fmt.Fprintln(out, "  capabilities:")
		for _, line := range capabilityLines(m.Capabilities) {
			_, _ = fmt.Fprintf(out, "    %s\n", line)
		}
		_, _ = fmt.Fprintf(out, "  install: agentry install %s/%s\n", agent.Namespace, agent.Name)
	}
}

// runSearch lists a namespace or delegates ns/name queries to info.
func runSearch(cmd *cobra.Command, query string) error {
	if strings.Contains(query, "/") {
		return runInfo(cmd, query)
	}
	if !flags.jsonOut {
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "note: listing agents in namespace "+query+" (full-text search lands with M5)")
	}

	reg := registryURL()
	client, err := newAPIClient(reg, credentialFor(reg))
	if err != nil {
		return err
	}
	agents, err := listNamespace(cmd.Context(), client, query)
	if err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	if flags.jsonOut {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(agents); err != nil {
			return fmt.Errorf("encode search results: %w", err)
		}
		return nil
	}
	if len(agents) == 0 {
		_, _ = fmt.Fprintf(out, "no agents in namespace %q\n", query)
		return nil
	}
	for _, a := range agents {
		summary := a.Summary
		if summary == "" {
			summary = "-"
		}
		_, _ = fmt.Fprintf(out, "%-40s %-13s %-8s %s\n", a.Namespace+"/"+a.Name, a.Kind, a.Visibility, summary)
	}
	return nil
}

// listNamespace calls GET /agents?namespace=.
func listNamespace(ctx context.Context, client *apiclient.ClientWithResponses, namespace string) ([]apiclient.Agent, error) {
	resp, err := client.ListAgentsWithResponse(ctx, &apiclient.ListAgentsParams{Namespace: namespace})
	if err != nil {
		return nil, fmt.Errorf("list namespace %s: %w", namespace, err)
	}
	if resp.JSON200 == nil {
		return nil, apiProblem("list namespace "+namespace, resp.StatusCode(), resp.ApplicationproblemJSONDefault, resp.Body)
	}
	return *resp.JSON200, nil
}
