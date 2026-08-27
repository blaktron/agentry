// `agentry install` (§11): resolve → download → verify digest → show the
// declared capability contract (confirming network/exec in interactive
// mode) → extract → export to one §5.6 target (claude-skill, mcp, or
// agents-md). DSSE signature verification arrives with M4 signing.
package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/PLACEHOLDER_ORG/agentry/internal/registry"
	"github.com/PLACEHOLDER_ORG/agentry/pkg/manifest"
)

// newInstallCmd builds the install command.
func newInstallCmd() *cobra.Command {
	var target, dir string
	var yes bool
	cmd := &cobra.Command{
		Use:   "install <ns/name[@range]>",
		Short: "Resolve, download, verify, and export an agent to a runtime format",
		Long: "Resolve ns/name[@range] (§9.4), download the release archive, verify its\n" +
			"sha256 digest, show the declared capability contract (§5.4), and export\n" +
			"to one install target (§5.6):\n\n" +
			"  claude-skill  {--dir | ~/.claude/skills}/<name>/ with SKILL.md frontmatter\n" +
			"  mcp           extract to {--dir | ./agents/<name>} and merge .mcp.json\n" +
			"  agents-md     extract to {--dir | ./agents/<name>} and update ./AGENTS.md\n\n" +
			"Declared network egress or exec requires typed confirmation in interactive\n" +
			"mode; pass --yes for CI. Attestation signature verification lands with M4.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInstall(cmd, args[0], target, dir, yes)
		},
	}
	cmd.Flags().StringVar(&target, "target", "", "install target: claude-skill | mcp | agents-md (default: by agent kind)")
	cmd.Flags().StringVar(&dir, "dir", "", "override the target directory (see help for per-target defaults)")
	cmd.Flags().BoolVar(&yes, "yes", false, "skip the capability confirmation prompt (CI)")
	return cmd
}

// runInstall executes the install flow.
func runInstall(cmd *cobra.Command, ref, target, dir string, yes bool) error {
	if _, err := registry.ParseRef(ref); err != nil {
		return err
	}
	reg := registryURL()
	token := credentialFor(reg)
	client, err := newAPIClient(reg, token)
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()

	res, err := resolveRef(cmd.Context(), client, ref, true)
	if err != nil {
		return err
	}
	if res.Yanked {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s/%s@%s is YANKED — installing only because the version was pinned exactly\n",
			res.Namespace, res.Name, res.Version)
	}
	m, err := manifestFromResolve(res)
	if err != nil {
		return err
	}

	archive, err := downloadArchive(cmd.Context(), reg, token, res)
	if err != nil {
		return err
	}
	if got := sha256Digest(archive); got != res.Digest {
		return fmt.Errorf("digest mismatch: registry says %s, archive is %s — refusing to install", res.Digest, got)
	}

	_, _ = fmt.Fprintf(out, "%s/%s@%s (%s)\n", res.Namespace, res.Name, res.Version, m.Kind)
	if m.Summary != "" {
		_, _ = fmt.Fprintf(out, "  %s\n", m.Summary)
	}
	_, _ = fmt.Fprintln(out, "capabilities:")
	for _, line := range capabilityLines(m.Capabilities) {
		_, _ = fmt.Fprintf(out, "  %s\n", line)
	}
	if err := confirmCapabilities(cmd, m.Capabilities, yes); err != nil {
		return err
	}

	if target == "" {
		target = defaultTarget(m.Kind)
	}
	warnUndeclaredTarget(cmd.ErrOrStderr(), m, target)

	staging, err := os.MkdirTemp("", "agentry-install-*")
	if err != nil {
		return fmt.Errorf("create staging dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(staging) }()
	if err := registry.ExtractArchive(bytes.NewReader(archive), staging, extractMaxFileBytes, extractMaxTotalBytes); err != nil {
		return fmt.Errorf("extract archive: %w", err)
	}

	switch target {
	case manifest.InterfaceClaudeSkill:
		return exportClaudeSkill(out, staging, dir, m, res.Namespace, res.Version)
	case manifest.InterfaceMCP:
		return exportMCP(out, staging, dir, m, res.Namespace, res.Version)
	case manifest.InterfaceAgentsMD:
		return exportAgentsMD(out, staging, dir, m, res.Namespace, res.Version)
	default:
		return fmt.Errorf("unknown --target %q (want claude-skill, mcp, or agents-md)", target)
	}
}

// confirmCapabilities enforces the §11 install gate: declared network egress
// or exec needs typed confirmation, skipped by --yes; non-interactive runs
// must pass --yes.
func confirmCapabilities(cmd *cobra.Command, caps manifest.Capabilities, yes bool) error {
	if yes || !capabilityNeedsConfirm(caps) {
		return nil
	}
	if !stdinIsTTY(cmd.InOrStdin()) {
		return errors.New("this agent declares network egress and/or exec; re-run with --yes to accept in non-interactive mode")
	}
	_, _ = fmt.Fprint(cmd.ErrOrStderr(), "this agent declares network egress and/or exec — type \"yes\" to continue: ")
	line, err := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
	if err != nil && strings.TrimSpace(line) == "" {
		return fmt.Errorf("read confirmation: %w", err)
	}
	if strings.TrimSpace(line) != "yes" {
		return errors.New("install aborted (capability contract not accepted)")
	}
	return nil
}

// stdinIsTTY reports whether in is an interactive terminal.
func stdinIsTTY(in io.Reader) bool {
	f, ok := in.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// warnUndeclaredTarget warns when runtime.interfaces exists but omits the
// chosen target (§5.2: interfaces lists what §5.6 may emit).
func warnUndeclaredTarget(w io.Writer, m *manifest.Manifest, target string) {
	if len(m.Runtime.Interfaces) == 0 {
		return
	}
	for _, it := range m.Runtime.Interfaces {
		if it == target {
			return
		}
	}
	_, _ = fmt.Fprintf(w, "warning: manifest runtime.interfaces %v does not list target %q\n", m.Runtime.Interfaces, target)
}

// exportClaudeSkill writes the archive into {dir|~/.claude/skills}/<name>/,
// guaranteeing SKILL.md frontmatter (§5.6 claude-skill row).
func exportClaudeSkill(out io.Writer, staging, dir string, m *manifest.Manifest, ns, version string) error {
	root := dir
	if root == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("locate home directory (pass --dir): %w", err)
		}
		root = filepath.Join(home, ".claude", "skills")
	}
	dest := filepath.Join(root, m.Name)
	// A reinstall replaces the skill directory so stale files never linger.
	if err := os.RemoveAll(dest); err != nil {
		return fmt.Errorf("clear %s: %w", dest, err)
	}
	if err := copyTree(staging, dest); err != nil {
		return err
	}

	skillRel := m.Entrypoints.Skill
	if skillRel == "" {
		skillRel = "SKILL.md"
	}
	skillPath := filepath.Join(dest, filepath.FromSlash(skillRel))
	content, err := os.ReadFile(skillPath) //nolint:gosec // path derives from the verified archive
	if err != nil {
		return fmt.Errorf("read skill entrypoint %s: %w", skillRel, err)
	}
	withFM := ensureSkillFrontmatter(content, m.Name, m.Summary)
	if err := os.WriteFile(skillPath, withFM, 0o644); err != nil { //nolint:gosec // skill files are world-readable content
		return fmt.Errorf("write skill entrypoint: %w", err)
	}

	_, _ = fmt.Fprintf(out, "installed %s/%s@%s as Claude skill: %s\n", ns, m.Name, version, dest)
	return nil
}

// exportMCP extracts to {dir|./agents/<name>} and merges a server entry into
// the client config: {dir}/.mcp.json when --dir is given, else ./.mcp.json
// with args re-rooted at the extraction path (§5.6 mcp row).
func exportMCP(out io.Writer, staging, dir string, m *manifest.Manifest, ns, version string) error {
	dest := dir
	configPath := ""
	extractedRel := ""
	if dest == "" {
		dest = filepath.Join("agents", m.Name)
		if err := os.RemoveAll(dest); err != nil {
			return fmt.Errorf("clear %s: %w", dest, err)
		}
		configPath = ".mcp.json"
		extractedRel = path.Join("agents", m.Name)
	} else {
		configPath = filepath.Join(dir, ".mcp.json")
	}
	if err := copyTree(staging, dest); err != nil {
		return err
	}

	entry, err := mcpEntryFromManifest(m, extractedRel, treeFiles(staging))
	if err != nil {
		return err
	}
	existing, err := os.ReadFile(configPath) //nolint:gosec // fixed config name under a user-chosen dir
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", configPath, err)
	}
	merged, err := mergeMCPConfig(existing, m.Name, entry)
	if err != nil {
		return err
	}
	if err := os.WriteFile(configPath, merged, 0o644); err != nil { //nolint:gosec // client config, not a secret
		return fmt.Errorf("write %s: %w", configPath, err)
	}

	_, _ = fmt.Fprintf(out, "installed %s/%s@%s as MCP server: %s\n", ns, m.Name, version, dest)
	_, _ = fmt.Fprintf(out, "merged server entry %q into %s", m.Name, configPath)
	if len(m.Capabilities.Secrets) > 0 {
		_, _ = fmt.Fprintf(out, " — fill in env: %s", strings.Join(m.Capabilities.Secrets, ", "))
	}
	_, _ = fmt.Fprintln(out)
	return nil
}

// exportAgentsMD extracts to {dir|./agents/<name>} and upserts the agent's
// section in ./AGENTS.md (§5.6 agents-md row).
func exportAgentsMD(out io.Writer, staging, dir string, m *manifest.Manifest, ns, version string) error {
	dest := dir
	if dest == "" {
		dest = filepath.Join("agents", m.Name)
		if err := os.RemoveAll(dest); err != nil {
			return fmt.Errorf("clear %s: %w", dest, err)
		}
	}
	if err := copyTree(staging, dest); err != nil {
		return err
	}

	const agentsPath = "AGENTS.md"
	existing, err := os.ReadFile(agentsPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", agentsPath, err)
	}
	updated := upsertAgentsMDSection(existing, ns, m.Name, version, m.Summary, dest)
	if err := os.WriteFile(agentsPath, updated, 0o644); err != nil { //nolint:gosec // project doc, not a secret
		return fmt.Errorf("write %s: %w", agentsPath, err)
	}

	_, _ = fmt.Fprintf(out, "installed %s/%s@%s as prompt agent: %s (section updated in %s)\n", ns, m.Name, version, dest, agentsPath)
	return nil
}

// copyTree copies the extracted archive into dest, preserving each file's
// permission bits (the archive normalizes modes, D-15).
func copyTree(src, dest string) error {
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(src, p)
		if rerr != nil {
			return rerr
		}
		target := filepath.Join(dest, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, rerr := os.ReadFile(p) //nolint:gosec // reading our own staging dir
		if rerr != nil {
			return rerr
		}
		return os.WriteFile(target, data, info.Mode().Perm())
	})
	if err != nil {
		return fmt.Errorf("copy files to %s: %w", dest, err)
	}
	return nil
}

// treeFiles lists the slash-separated relative file paths under root, for
// the exporter's arg re-rooting.
func treeFiles(root string) map[string]bool {
	files := map[string]bool{}
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		files[filepath.ToSlash(rel)] = true
		return nil
	})
	return files
}
