import { describe, expect, it } from "vitest";
import { embeddedAllowedTools, gatewayToolRows, parseContract } from "../mcp";

// The MCP servers & tools section tells an operator what tool surface a
// contract becomes — through the runner's gateway and as host built-ins in
// an embedded install. The failure that matters is describing a tool the
// runner would not grant (or hiding one it would), so these pin the mapping
// against every union shape the manifest allows: egress "none" | "*" |
// [hosts], filesystem none | workspace | {paths}, exec none | {commands}.

describe("parseContract", () => {
  it("treats absent capabilities as a pure-text contract", () => {
    for (const caps of [undefined, {}]) {
      const c = parseContract(caps);
      expect(c.egress).toEqual({ kind: "none" });
      expect(c.fsRead).toEqual({ kind: "none" });
      expect(c.fsWrite).toEqual({ kind: "none" });
      expect(c.exec).toEqual({ kind: "none" });
      expect(c.secrets).toEqual([]);
      expect(c.dataAccess).toEqual([]);
    }
  });

  it("treats explicit none declarations like omissions", () => {
    const c = parseContract({
      network: { egress: "none" },
      filesystem: { read: "none", write: "none" },
      exec: "none",
    });
    expect(c.egress).toEqual({ kind: "none" });
    expect(c.fsRead).toEqual({ kind: "none" });
    expect(c.fsWrite).toEqual({ kind: "none" });
    expect(c.exec).toEqual({ kind: "none" });
  });

  it("parses every declared union arm", () => {
    const c = parseContract({
      network: { egress: ["api.pagerduty.com"] },
      filesystem: { read: "workspace", write: { paths: ["out/", "notes.md"] } },
      exec: { commands: ["jq", "git"] },
      secrets: ["PAGERDUTY_TOKEN"],
      dataAccess: ["tickets"],
    });
    expect(c.egress).toEqual({ kind: "hosts", hosts: ["api.pagerduty.com"], wildcard: false });
    expect(c.fsRead).toEqual({ kind: "workspace" });
    expect(c.fsWrite).toEqual({ kind: "paths", paths: ["out/", "notes.md"] });
    expect(c.exec).toEqual({ kind: "commands", commands: ["jq", "git"] });
    expect(c.secrets).toEqual(["PAGERDUTY_TOKEN"]);
    expect(c.dataAccess).toEqual(["tickets"]);
  });

  it("normalizes the scalar egress wildcard to a wildcard host list", () => {
    // The manifest decoder normalizes scalar "*" to ["*"]; both wire forms
    // must read as the same contract.
    expect(parseContract({ network: { egress: "*" } }).egress).toEqual({
      kind: "hosts",
      hosts: ["*"],
      wildcard: true,
    });
    expect(parseContract({ network: { egress: ["*"] } }).egress).toEqual({
      kind: "hosts",
      hosts: ["*"],
      wildcard: true,
    });
  });

  it("does not read an empty or unrecognized shape as a grant", () => {
    const c = parseContract({
      network: { egress: [] },
      filesystem: { read: { paths: [] }, write: 7 },
      exec: { commands: [] },
      secrets: "TOKEN", // not a list — junk, not a declaration
    });
    expect(c.egress).toEqual({ kind: "none" });
    expect(c.fsRead).toEqual({ kind: "none" });
    expect(c.fsWrite).toEqual({ kind: "none" });
    expect(c.exec).toEqual({ kind: "none" });
    expect(c.secrets).toEqual([]);
  });
});

describe("gatewayToolRows", () => {
  it("always grants the report and input channels, even pure text", () => {
    const rows = gatewayToolRows(parseContract(undefined));
    expect(rows).toHaveLength(2);
    expect(rows[0].tools).toEqual(["write_report"]);
    expect(rows[0].note).toBe("reports → the run's output folder");
    expect(rows[1].tools).toEqual(["list_inputs", "read_input"]);
    expect(rows[1].note).toBe("operator-provided input files, read-only");
  });

  it("maps each declared capability to its gateway tools", () => {
    const rows = gatewayToolRows(
      parseContract({
        network: { egress: ["api.pagerduty.com"] },
        filesystem: { read: "workspace", write: { paths: ["out/"] } },
        exec: { commands: ["jq"] },
      }),
    );
    const by = Object.fromEntries(rows.map((r) => [r.declaration, r]));
    expect(by["filesystem.read"].tools).toEqual(["fs_read", "fs_list"]);
    expect(by["filesystem.read"].note).toBe("the whole task workspace");
    expect(by["filesystem.write"].tools).toEqual(["fs_write"]);
    expect(by["filesystem.write"].note).toBe("only out/");
    expect(by["network.egress"].tools).toEqual(["fetch"]);
    expect(by["network.egress"].note).toBe("pinned to api.pagerduty.com");
    expect(by["exec.commands"].tools).toEqual(["run_command"]);
    expect(by["exec.commands"].note).toBe("restricted to jq");
  });

  it("omits rows for undeclared capabilities instead of showing them empty", () => {
    const rows = gatewayToolRows(parseContract({ filesystem: { read: "workspace" } }));
    expect(rows.map((r) => r.declaration)).toEqual(["(always)", "(always)", "filesystem.read"]);
  });

  it("flags wildcard egress as policy-gated rather than pinned", () => {
    const rows = gatewayToolRows(parseContract({ network: { egress: "*" } }));
    const fetchRow = rows.find((r) => r.declaration === "network.egress")!;
    expect(fetchRow.tools).toEqual(["fetch"]);
    expect(fetchRow.note).toContain("refused at run time unless the operator's policy allows wildcard egress");
    expect(fetchRow.note).not.toContain("pinned");
  });
});

describe("embeddedAllowedTools", () => {
  it("returns the empty set for a pure-text contract", () => {
    expect(embeddedAllowedTools(parseContract(undefined))).toEqual([]);
  });

  it("mirrors the CLI HostToolGrants mapping, order and all", () => {
    // read → Read/Grep/Glob, write → Write/Edit, exec commands sorted →
    // Bash(cmd:*), egress hosts sorted → WebFetch(domain:host) — the exact
    // allowed-tools an `agentry install --provider claude` would write.
    const tools = embeddedAllowedTools(
      parseContract({
        network: { egress: ["b.example.com", "a.example.com"] },
        filesystem: { read: { paths: ["data/"] }, write: "workspace" },
        exec: { commands: ["jq", "git"] },
      }),
    );
    expect(tools).toEqual([
      "Read",
      "Grep",
      "Glob",
      "Write",
      "Edit",
      "Bash(git:*)",
      "Bash(jq:*)",
      "WebFetch(domain:a.example.com)",
      "WebFetch(domain:b.example.com)",
    ]);
  });

  it("maps wildcard egress to bare WebFetch", () => {
    expect(embeddedAllowedTools(parseContract({ network: { egress: "*" } }))).toEqual(["WebFetch"]);
  });
});

describe("parseContract mcpServers", () => {
  it("lists declared servers with ecosystem, exact version and tool filter", () => {
    const c = parseContract({
      mcpServers: [
        { npm: "@modelcontextprotocol/server-github", version: "2026.1.2", tools: ["list_issues"] },
        { pypi: "mcp-server-fetch", version: "0.6.2" },
        { npm: "no-version" },
      ],
    });
    expect(c.mcpServers).toEqual([
      { ecosystem: "npm", package: "@modelcontextprotocol/server-github", version: "2026.1.2", tools: ["list_issues"] },
      { ecosystem: "pypi", package: "mcp-server-fetch", version: "0.6.2", tools: [] },
    ]);
    expect(parseContract({}).mcpServers).toEqual([]);
  });
});
