// Manifest-capability → tool-surface mapping for the "MCP servers & tools"
// section of the BriefAgent page (RUNNER-PLAN-2 §P6, req 3).
//
// The wire shape is the manifest capability block exactly as the API returns
// it (schemas/openapi.yaml AgentVersion.capabilities): each member is a
// union — egress "none" | "*" | [hosts], filesystem none | workspace |
// {paths: […]}, exec none | {commands: […]} — so parsing lives here, pure
// and unit-tested, and the page only renders. The vocabulary mirrors
// docs/briefagents.md ("What a BriefAgent gets at run time") and the
// embedded mapping mirrors the CLI's pkg/export/hosttools.go HostToolGrants
// exactly: this page must not describe a tool set that differs from what
// `agentry run` / `agentry install` would actually do.

export type FSContract =
  | { kind: "none" }
  | { kind: "workspace" }
  | { kind: "paths"; paths: string[] };

export type EgressContract =
  | { kind: "none" }
  // wildcard is true when the declaration requests unrestricted egress
  // (scalar "*", or "*" among the listed hosts).
  | { kind: "hosts"; hosts: string[]; wildcard: boolean };

export type ExecContract = { kind: "none" } | { kind: "commands"; commands: string[] };

export interface McpContract {
  egress: EgressContract;
  fsRead: FSContract;
  fsWrite: FSContract;
  exec: ExecContract;
  secrets: string[];
  dataAccess: string[];
  // mcpServers are the declared servers (capabilities.mcpServers): exact
  // npm / PyPI package versions the runner installs per release and S7
  // checks for known vulnerabilities (agentry#177).
  mcpServers: DeclaredMcpServer[];
}

export interface DeclaredMcpServer {
  ecosystem: "npm" | "pypi";
  package: string;
  version: string;
  tools: string[];
}

function parseMcpServers(v: unknown): DeclaredMcpServer[] {
  if (!Array.isArray(v)) return [];
  const out: DeclaredMcpServer[] = [];
  for (const e of v) {
    if (typeof e !== "object" || e === null) continue;
    const o = e as { npm?: unknown; pypi?: unknown; version?: unknown; tools?: unknown };
    const version = typeof o.version === "string" ? o.version : "";
    if (!version) continue;
    if (typeof o.npm === "string" && o.npm) {
      out.push({ ecosystem: "npm", package: o.npm, version, tools: strList(o.tools) });
    } else if (typeof o.pypi === "string" && o.pypi) {
      out.push({ ecosystem: "pypi", package: o.pypi, version, tools: strList(o.tools) });
    }
  }
  return out;
}

// One row of the "Tools the runner grants" table. `declaration` is the
// manifest declaration (the docs table's left column), `tools` the gateway
// tool names it grants, `note` the scope in docs vocabulary.
export interface GatewayToolRow {
  declaration: string;
  tools: string[];
  note: string;
}

function strList(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  return v.filter((x): x is string => typeof x === "string" && x !== "");
}

function parseFS(v: unknown): FSContract {
  if (v === "workspace") return { kind: "workspace" };
  if (typeof v === "object" && v !== null && !Array.isArray(v) && "paths" in v) {
    const paths = strList((v as { paths?: unknown }).paths);
    if (paths.length > 0) return { kind: "paths", paths };
  }
  // "none", omitted, null, an empty paths list, or an unrecognized shape all
  // grant nothing: the tool is absent when undeclared, and a shape this page
  // cannot read must not render as a grant.
  return { kind: "none" };
}

function parseEgress(v: unknown): EgressContract {
  // The scalar "*" is accepted and normalized to the single-element list,
  // exactly as the manifest decoder does (pkg/manifest, Egress).
  const hosts = v === "*" ? ["*"] : strList(v).filter((h) => h !== "none");
  if (hosts.length === 0) return { kind: "none" };
  return { kind: "hosts", hosts, wildcard: hosts.includes("*") };
}

function parseExec(v: unknown): ExecContract {
  if (typeof v === "object" && v !== null && !Array.isArray(v) && "commands" in v) {
    const commands = strList((v as { commands?: unknown }).commands);
    if (commands.length > 0) return { kind: "commands", commands };
  }
  return { kind: "none" };
}

// parseContract normalizes a manifest capability block. Absent capabilities
// (undefined, or an empty object) are a pure-text contract.
export function parseContract(capabilities?: Record<string, unknown>): McpContract {
  const caps = (capabilities ?? {}) as {
    network?: { egress?: unknown };
    filesystem?: { read?: unknown; write?: unknown };
    exec?: unknown;
    secrets?: unknown;
    dataAccess?: unknown;
    mcpServers?: unknown;
  };
  return {
    egress: parseEgress(caps.network?.egress),
    fsRead: parseFS(caps.filesystem?.read),
    fsWrite: parseFS(caps.filesystem?.write),
    exec: parseExec(caps.exec),
    secrets: strList(caps.secrets),
    dataAccess: strList(caps.dataAccess),
    mcpServers: parseMcpServers(caps.mcpServers),
  };
}

function fsNote(fs: FSContract): string {
  if (fs.kind === "workspace") return "the whole task workspace";
  if (fs.kind === "paths") return `only ${fs.paths.join(", ")}`;
  return "";
}

// gatewayToolRows maps the contract to the tools the runner's gateway
// serves (docs/briefagents.md tool table + the always-on report/input
// channels of RUNNER-PLAN-2 §P4). Rows that do not apply are omitted, not
// shown empty: an undeclared capability is a tool that does not exist.
export function gatewayToolRows(c: McpContract): GatewayToolRow[] {
  const rows: GatewayToolRow[] = [
    {
      declaration: "(always)",
      tools: ["write_report"],
      note: "reports → the run's output folder",
    },
    {
      declaration: "(always)",
      tools: ["list_inputs", "read_input"],
      note: "operator-provided input files, read-only",
    },
  ];
  if (c.fsRead.kind !== "none") {
    rows.push({ declaration: "filesystem.read", tools: ["fs_read", "fs_list"], note: fsNote(c.fsRead) });
  }
  if (c.fsWrite.kind !== "none") {
    rows.push({ declaration: "filesystem.write", tools: ["fs_write"], note: fsNote(c.fsWrite) });
  }
  if (c.egress.kind === "hosts") {
    rows.push({
      declaration: "network.egress",
      tools: ["fetch"],
      note: c.egress.wildcard
        ? "unrestricted (\"*\") — refused at run time unless the operator's policy allows wildcard egress"
        : `pinned to ${c.egress.hosts.join(", ")}`,
    });
  }
  if (c.exec.kind === "commands") {
    rows.push({
      declaration: "exec.commands",
      tools: ["run_command"],
      note: `restricted to ${c.exec.commands.join(", ")}`,
    });
  }
  return rows;
}

// embeddedAllowedTools maps the same contract to the host built-ins an
// embedded install grants (`allowed-tools`). It must match the CLI's
// pkg/export/hosttools.go HostToolGrants element for element: read →
// Read/Grep/Glob, write → Write/Edit, each exec command (sorted) →
// Bash(cmd:*), each egress host (sorted) → WebFetch(domain:host), the
// wildcard host → bare WebFetch. Empty means pure text: nothing declared,
// host defaults apply.
export function embeddedAllowedTools(c: McpContract): string[] {
  const tools: string[] = [];
  if (c.fsRead.kind !== "none") tools.push("Read", "Grep", "Glob");
  if (c.fsWrite.kind !== "none") tools.push("Write", "Edit");
  if (c.exec.kind === "commands") {
    for (const cmd of [...c.exec.commands].sort()) tools.push(`Bash(${cmd}:*)`);
  }
  if (c.egress.kind === "hosts") {
    for (const h of [...c.egress.hosts].sort()) {
      tools.push(h === "*" ? "WebFetch" : `WebFetch(domain:${h})`);
    }
  }
  return tools;
}
