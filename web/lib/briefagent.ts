// The BriefAgent Builder's engine (DEV-059): render a builder form into a
// workspace (agent.yaml + instructions + README + LICENSE) and pack it as
// the tar.zst archive the cli-upload path accepts. Runs entirely in the
// web tier's route handler — the server re-validates and re-packs every
// upload (client packing is never trusted, §6.5), so this only has to be
// well-formed, not canonical. NOTE: the upload therefore sends NO digest
// field — the API's digest cross-check asserts byte-identity with the
// server's canonical re-pack, which only pkg/archive's own output can
// satisfy. packArchive still returns a digest of its bytes for tests and
// logging; it is not the release identity.
import "server-only";
import { createHash } from "node:crypto";
import { zstdCompressSync } from "node:zlib";

// BuilderMCPServer is one declared MCP server (RUNNER-PLAN-3): exactly one
// ecosystem, an EXACT version (the pin rides the release digest).
import type { AgentMode } from "./api";

export type BuilderMCPServer = {
  source: "npm" | "pypi";
  pkg: string;
  version: string;
  tools: string[];
  secrets: string[];
  egress: string[];
};

// One up-front question (manifest v2 `intake`, plan §3.5): asked before a
// run in either mode; the runner stages the answers read-only for the agent.
export type BuilderIntakeQuestion = {
  id: string;
  prompt: string;
  type: "text" | "secret" | "choice" | "file";
  required: boolean;
  choices: string[];
};

export type BuilderInput = {
  mcpServers: BuilderMCPServer[];
  name: string;
  namespace: string;
  // Run modes the release supports (DEV-088): one or both.
  modes: AgentMode[];
  // Up-front questions; empty is the common case.
  intake: BuilderIntakeQuestion[];
  // The assistant's first message in an interactive session when no task
  // text was given (manifest v2 `interactive.opening`); empty for none.
  opening: string;
  version: string;
  summary: string;
  license: string;
  tags: string[];
  instructions: string;
  egressMode: "none" | "hosts" | "all";
  egressHosts: string[];
  fsRead: "none" | "workspace" | "paths";
  fsReadPaths: string[];
  fsWrite: "none" | "workspace" | "paths";
  fsWritePaths: string[];
  execCommands: string[];
  secrets: string[];
  dataAccess: string[];
};

const NAME_RE = /^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$|^[a-z0-9]$/;
const SEMVER_RE = /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/;
const NPM_NAME_RE = /^(@[a-z0-9][a-z0-9-_.]*\/)?[a-z0-9][a-z0-9-_.]*$/;
const PYPI_NAME_RE = /^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$/;
const PEP440_EXACT_RE = /^\d+(\.\d+)*((a|b|rc)\d+)?(\.post\d+)?(\.dev\d+)?$/;
const ENV_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
const INTAKE_ID_RE = /^[a-z0-9_]{1,64}$/;
const INTAKE_TYPES = ["text", "secret", "choice", "file"] as const;
// The manifest's own limits (pkg/manifest V10).
export const MAX_INTAKE_QUESTIONS = 20;
export const MAX_OPENING_CHARS = 500;
// The single instruction file a v2 package names (plan §3.2).
export const INSTRUCTION_FILE = "AGENT.md";

// parseServerLines parses the Builder's line-based mcpServers field (one
// declared server per line; the plain-HTML form has no list controls,
// DEV-012):
//
//	npm:@scope/server-github@2026.1.2 tools=list_issues secrets=GITHUB_PAT egress=api.github.com
//	pypi:mcp-server-fetch@0.6.2 egress=*
//
// Blank lines and #-comments are skipped. Returns a message naming the
// first bad line, or null.
// serverLinesFromForm turns the Builder's structured MCP-server rows
// (mcp<i>Source/Pkg/Version/Tools/Secrets/Egress, i = 0..BUILDER_SERVER_ROWS-1)
// into the line syntax parseServerLines accepts, so both the rows and the
// advanced textarea feed one parser (agentry#52). Rows with no package are
// skipped.
export const BUILDER_SERVER_ROWS = 3;
export function serverLinesFromForm(form: { get(name: string): FormDataEntryValue | null }): string {
  const lines: string[] = [];
  for (let i = 0; i < BUILDER_SERVER_ROWS; i++) {
    const pkg = String(form.get(`mcp${i}Pkg`) ?? "").trim();
    if (!pkg) continue;
    const source = String(form.get(`mcp${i}Source`) ?? "npm") === "pypi" ? "pypi" : "npm";
    const version = String(form.get(`mcp${i}Version`) ?? "").trim();
    let line = `${source}:${pkg}@${version || "?"}`;
    for (const opt of ["tools", "secrets", "egress"] as const) {
      const v = String(form.get(`mcp${i}${opt[0].toUpperCase()}${opt.slice(1)}`) ?? "")
        .split(/[\s,]+/)
        .map((s) => s.trim())
        .filter(Boolean)
        .join(",");
      if (v) line += ` ${opt}=${v}`;
    }
    lines.push(line);
  }
  return lines.join("\n");
}

// intakeLinesFromForm turns the Builder's structured intake rows
// (intake<i>Id/Prompt/Type/Required/Choices, i = 0..BUILDER_INTAKE_ROWS-1)
// into the line syntax parseIntakeLines accepts, so the rows and the
// advanced textarea feed one parser. Rows with no id are skipped.
export const BUILDER_INTAKE_ROWS = 3;
export function intakeLinesFromForm(form: { get(name: string): FormDataEntryValue | null }): string {
  const lines: string[] = [];
  for (let i = 0; i < BUILDER_INTAKE_ROWS; i++) {
    const id = String(form.get(`intake${i}Id`) ?? "").trim();
    if (!id) continue;
    const prompt = String(form.get(`intake${i}Prompt`) ?? "").trim();
    const type = String(form.get(`intake${i}Type`) ?? "text").trim() || "text";
    const required = String(form.get(`intake${i}Required`) ?? "") !== "";
    const choices = String(form.get(`intake${i}Choices`) ?? "")
      .split(/[\s,]+/)
      .map((c) => c.trim())
      .filter(Boolean)
      .join(",");
    let line = `${id}: ${prompt} type=${type}`;
    if (choices) line += ` choices=${choices}`;
    if (required) line += " required";
    lines.push(line);
  }
  return lines.join("\n");
}

// parseIntakeLines parses one question per line:
//
//	topic: What should I look at? type=text required
//	region: Which region? type=choice choices=emea,apac,amer
//
// The prompt is everything between "id:" and the trailing options
// (type=, choices=, required). Blank lines and #-comments are skipped.
export function parseIntakeLines(text: string): { intake: BuilderIntakeQuestion[]; error: string | null } {
  const intake: BuilderIntakeQuestion[] = [];
  for (const rawLine of text.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const m = /^([^:\s]+):\s*(.*)$/.exec(line);
    if (!m) return { intake, error: `intake line "${line}": expected <id>: <prompt> [type=…] [choices=a,b] [required]` };
    const q: BuilderIntakeQuestion = { id: m[1], prompt: "", type: "text", required: false, choices: [] };
    const words = m[2].split(/\s+/).filter(Boolean);
    const promptWords: string[] = [];
    let inOptions = false;
    for (const w of words) {
      const om = /^(type|choices)=(.*)$/.exec(w);
      if (w === "required") { q.required = true; inOptions = true; continue; }
      if (om) {
        inOptions = true;
        if (om[1] === "type") {
          if (!(INTAKE_TYPES as readonly string[]).includes(om[2])) {
            return { intake, error: `intake "${q.id}": unknown type "${om[2]}" (text | secret | choice | file)` };
          }
          q.type = om[2] as BuilderIntakeQuestion["type"];
        } else {
          q.choices = om[2].split(",").map((c) => c.trim()).filter(Boolean);
        }
        continue;
      }
      if (inOptions) return { intake, error: `intake "${q.id}": "${w}" after the options — put the prompt before type=/choices=/required` };
      promptWords.push(w);
    }
    q.prompt = promptWords.join(" ");
    intake.push(q);
  }
  return { intake, error: null };
}

// validateIntake applies the V10 rules the API will re-check.
function validateIntake(intake: BuilderIntakeQuestion[]): string | null {
  if (intake.length > MAX_INTAKE_QUESTIONS) return `at most ${MAX_INTAKE_QUESTIONS} intake questions`;
  const seen = new Set<string>();
  for (const q of intake) {
    if (!INTAKE_ID_RE.test(q.id)) return `intake id "${q.id}" must be [a-z0-9_], 1–64 chars`;
    if (seen.has(q.id)) return `duplicate intake id "${q.id}"`;
    seen.add(q.id);
    if (!q.prompt.trim()) return `intake "${q.id}": the prompt is required`;
    if (q.type === "choice" && q.choices.length === 0) return `intake "${q.id}": type choice needs choices=`;
    if (q.type !== "choice" && q.choices.length > 0) return `intake "${q.id}": choices= only applies to type choice`;
  }
  return null;
}

export function parseServerLines(text: string): { servers: BuilderMCPServer[]; error: string | null } {
  const servers: BuilderMCPServer[] = [];
  for (const rawLine of text.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const [head, ...opts] = line.split(/\s+/);
    const m = /^(npm|pypi):(.+)@([^@]+)$/.exec(head);
    if (!m) {
      return { servers, error: `mcpServers line "${line}": expected npm:<package>@<version> or pypi:<package>@<version>` };
    }
    const srv: BuilderMCPServer = {
      source: m[1] as "npm" | "pypi",
      pkg: m[2],
      version: m[3],
      tools: [],
      secrets: [],
      egress: [],
    };
    for (const opt of opts) {
      const om = /^(tools|secrets|egress)=(.*)$/.exec(opt);
      if (!om) return { servers, error: `mcpServers line "${line}": unknown option "${opt}" (tools= secrets= egress=)` };
      const values = om[2].split(",").map((s) => s.trim()).filter(Boolean);
      if (om[1] === "tools") srv.tools = values;
      else if (om[1] === "secrets") srv.secrets = values;
      else srv.egress = values;
    }
    servers.push(srv);
  }
  return { servers, error: null };
}

// validateServers applies the V5 rules the API will re-check.
function validateServers(servers: BuilderMCPServer[]): string | null {
  if (servers.length > 8) return "at most 8 MCP servers may be declared";
  const seen = new Set<string>();
  for (const s of servers) {
    const id = `${s.source}:${s.pkg}`;
    if (seen.has(id)) return `duplicate MCP server ${id}`;
    seen.add(id);
    if (s.source === "npm" && !NPM_NAME_RE.test(s.pkg)) return `"${s.pkg}" is not a valid npm package name`;
    if (s.source === "pypi" && !PYPI_NAME_RE.test(s.pkg)) return `"${s.pkg}" is not a PEP-503 normalized PyPI name`;
    const exact = s.source === "npm" ? SEMVER_RE.test(s.version) : PEP440_EXACT_RE.test(s.version);
    if (!exact) return `MCP server ${id}: "${s.version}" is not an exact version (ranges are rejected — the pin is part of this release)`;
    for (const n of s.secrets) if (!ENV_NAME_RE.test(n)) return `MCP server ${id}: secret "${n}" is not an env-var name`;
    for (const t of s.tools) if (/\s/.test(t) || !t) return `MCP server ${id}: tool "${t}" must be a single token`;
  }
  return null;
}

// MAX_INSTRUCTIONS_BYTES caps the entrypoint file the Builder packs at the
// §19 "instruction-file total ≤ 1 MB" quota. The download route needs no
// account, so without a cap the only bound on the bytes it zstd-packs was
// the edge's request-body limit (agentry#18).
export const MAX_INSTRUCTIONS_BYTES = 1 << 20;

// validateInput applies the form-level rules; the API's V-rules are the
// real gate and re-check everything.
export function validateInput(i: BuilderInput): string | null {
  if (!NAME_RE.test(i.name)) return "name must be lowercase [a-z0-9-], 1–64 chars";
  if (!NAME_RE.test(i.namespace)) return "namespace must be lowercase [a-z0-9-]";
  if (!SEMVER_RE.test(i.version)) return "version must be strict semver (e.g. 0.1.0)";
  if (!i.summary.trim()) return "summary is required";
  if (i.summary.length > 140) return "summary must be at most 140 characters";
  if (!i.instructions.trim()) return "instructions are required";
  if (Buffer.byteLength(i.instructions, "utf8") > MAX_INSTRUCTIONS_BYTES) {
    return "instructions must be at most 1 MiB (the §19 instruction-file quota)";
  }
  if (i.egressMode === "hosts" && i.egressHosts.length === 0) return "egress is set to hosts but no hosts are listed";
  if (i.fsRead === "paths" && i.fsReadPaths.length === 0) return "fs read is set to paths but no paths are listed";
  if (i.fsWrite === "paths" && i.fsWritePaths.length === 0) return "fs write is set to paths but no paths are listed";
  if (i.modes.length === 0) return "pick at least one run mode (autonomous, interactive)";
  for (const m of i.modes) if (m !== "autonomous" && m !== "interactive") return `unknown run mode "${m}"`;
  if (i.opening.length > MAX_OPENING_CHARS) return `the interactive opening must be at most ${MAX_OPENING_CHARS} characters`;
  if (i.opening.trim() && !i.modes.includes("interactive")) return "an interactive opening is set but interactive is not among the run modes";
  const intakeErr = validateIntake(i.intake);
  if (intakeErr) return intakeErr;
  const serverErr = validateServers(i.mcpServers);
  if (serverErr) return serverErr;
  return null;
}

// yamlString double-quotes a scalar; JSON string escaping is valid YAML.
function yamlString(s: string): string {
  return JSON.stringify(s);
}

function fsValue(mode: string, paths: string[]): string {
  if (mode === "workspace") return "workspace";
  if (mode === "paths") return `{ paths: [${paths.join(", ")}] }`;
  return "none";
}

// renderManifest writes agent.yaml the way the template repo reads:
// stable key order, the capability contract last before publish.
export function renderManifest(i: BuilderInput): string {
  const entry = INSTRUCTION_FILE;
  const order: AgentMode[] = ["autonomous", "interactive"];
  const modes = order.filter((m) => i.modes.includes(m));
  const lines: string[] = [
    `schemaVersion: "2"`,
    `name: ${i.name}`,
    `namespace: ${i.namespace}`,
    `version: ${i.version}`,
    `summary: ${yamlString(i.summary)}`,
  ];
  if (i.license) lines.push(`license: ${i.license}`);
  if (i.tags.length > 0) lines.push(`tags: [${i.tags.join(", ")}]`);
  lines.push("", `modes: [${modes.join(", ")}]`, "", "entrypoints:", `  instruction: ${entry}`);
  if (i.intake.length > 0) {
    lines.push("", "intake:");
    for (const q of i.intake) {
      lines.push(`  - id: ${q.id}`, `    prompt: ${yamlString(q.prompt)}`);
      if (q.type !== "text") lines.push(`    type: ${q.type}`);
      if (q.required) lines.push("    required: true");
      if (q.choices.length > 0) lines.push(`    choices: [${q.choices.map(yamlString).join(", ")}]`);
    }
  }
  if (i.opening.trim()) lines.push("", "interactive:", `  opening: ${yamlString(i.opening.trim())}`);
  lines.push("", "capabilities:", "  network:");
  if (i.egressMode === "all") lines.push(`    egress: "*"`);
  else if (i.egressMode === "hosts") lines.push(`    egress: [${i.egressHosts.join(", ")}]`);
  else lines.push("    egress: none");
  lines.push(
    "  filesystem:",
    `    read: ${fsValue(i.fsRead, i.fsReadPaths)}`,
    `    write: ${fsValue(i.fsWrite, i.fsWritePaths)}`,
  );
  if (i.execCommands.length > 0) lines.push(`  exec: { commands: [${i.execCommands.join(", ")}] }`);
  else lines.push("  exec: none");
  if (i.secrets.length > 0) lines.push(`  secrets: [${i.secrets.join(", ")}]`);
  if (i.dataAccess.length > 0) lines.push(`  dataAccess: [${i.dataAccess.join(", ")}]`);
  if (i.mcpServers.length > 0) {
    lines.push("  mcpServers:");
    for (const s of i.mcpServers) {
      lines.push(`    - ${s.source}: ${yamlString(s.pkg)}`);
      lines.push(`      version: ${yamlString(s.version)}`);
      if (s.tools.length > 0) lines.push(`      tools: [${s.tools.join(", ")}]`);
      if (s.secrets.length > 0) lines.push(`      secrets: [${s.secrets.join(", ")}]`);
      if (s.egress.length > 0) lines.push(`      egress: [${s.egress.map((h) => (h === "*" ? `"*"` : h)).join(", ")}]`);
    }
  }
  lines.push(
    "",
    "publish:",
    `  include: [agent.yaml, ${entry}, README.md, LICENSE]`,
    "",
  );
  return lines.join("\n");
}

// workspaceFiles is the complete file set the archive will carry.
export function workspaceFiles(i: BuilderInput): { path: string; content: string }[] {
  const instructions = i.instructions.endsWith("\n") ? i.instructions : i.instructions + "\n";
  return [
    { path: "agent.yaml", content: renderManifest(i) },
    { path: INSTRUCTION_FILE, content: instructions },
    { path: "README.md", content: `# ${i.name}\n\n${i.summary}\n` },
    { path: "LICENSE", content: mitLicense(i.namespace) },
  ];
}

// packArchive builds a plain ustar tar (sorted paths, zeroed times and
// ownership — stable for identical input) and zstd-compresses it. The
// digest is sha256 over the compressed bytes, the identity the API
// cross-checks against what it received.
export function packArchive(files: { path: string; content: string }[]): {
  bytes: Buffer;
  digest: string;
} {
  const blocks: Buffer[] = [];
  for (const f of [...files].sort((a, b) => (a.path < b.path ? -1 : 1))) {
    const data = Buffer.from(f.content, "utf8");
    blocks.push(tarHeader(f.path, data.length), data, pad(data.length));
  }
  blocks.push(Buffer.alloc(1024)); // end-of-archive
  const tar = Buffer.concat(blocks);
  const bytes = zstdCompressSync(tar);
  const digest = "sha256:" + createHash("sha256").update(bytes).digest("hex");
  return { bytes, digest };
}

function pad(size: number): Buffer {
  const rem = size % 512;
  return rem === 0 ? Buffer.alloc(0) : Buffer.alloc(512 - rem);
}

function octal(n: number, width: number): string {
  return n.toString(8).padStart(width - 1, "0") + "\0";
}

function tarHeader(name: string, size: number): Buffer {
  const h = Buffer.alloc(512);
  h.write(name, 0, 100, "utf8"); // name (builder paths are short and flat)
  h.write(octal(0o644, 8), 100); // mode
  h.write(octal(0, 8), 108); // uid
  h.write(octal(0, 8), 116); // gid
  h.write(octal(size, 12), 124); // size
  h.write(octal(0, 12), 136); // mtime: epoch, deterministic
  h.write("        ", 148); // chksum placeholder (spaces)
  h.write("0", 156); // typeflag: regular file
  h.write("ustar\0", 257); // magic
  h.write("00", 263); // version
  let sum = 0;
  for (const b of h) sum += b;
  h.write(sum.toString(8).padStart(6, "0") + "\0 ", 148);
  return h;
}

function mitLicense(holder: string): string {
  return `MIT License

Copyright (c) ${new Date().getFullYear()} ${holder}

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
`;
}
