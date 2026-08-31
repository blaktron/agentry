// The BriefAgent Builder's engine (DEV-059): render a builder form into a
// workspace (agent.yaml + instructions + README + LICENSE) and pack it as
// the tar.zst archive the cli-upload path accepts. Runs entirely in the
// web tier's route handler — the server re-validates and re-packs every
// upload (client packing is never trusted, §6.5), so this only has to be
// well-formed, not canonical; the digest sent alongside is the digest of
// these exact uploaded bytes, which the API cross-checks on receipt.
import "server-only";
import { createHash } from "node:crypto";
import { zstdCompressSync } from "node:zlib";

export type BuilderInput = {
  name: string;
  namespace: string;
  kind: "skill" | "prompt-agent";
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

// validateInput applies the form-level rules; the API's V-rules are the
// real gate and re-check everything.
export function validateInput(i: BuilderInput): string | null {
  if (!NAME_RE.test(i.name)) return "name must be lowercase [a-z0-9-], 1–64 chars";
  if (!NAME_RE.test(i.namespace)) return "namespace must be lowercase [a-z0-9-]";
  if (!SEMVER_RE.test(i.version)) return "version must be strict semver (e.g. 0.1.0)";
  if (!i.summary.trim()) return "summary is required";
  if (i.summary.length > 140) return "summary must be at most 140 characters";
  if (!i.instructions.trim()) return "instructions are required";
  if (i.egressMode === "hosts" && i.egressHosts.length === 0) return "egress is set to hosts but no hosts are listed";
  if (i.fsRead === "paths" && i.fsReadPaths.length === 0) return "fs read is set to paths but no paths are listed";
  if (i.fsWrite === "paths" && i.fsWritePaths.length === 0) return "fs write is set to paths but no paths are listed";
  return null;
}

export function entrypointFile(kind: BuilderInput["kind"]): string {
  return kind === "skill" ? "SKILL.md" : "AGENT.md";
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
  const entry = entrypointFile(i.kind);
  const lines: string[] = [
    `schemaVersion: "1"`,
    `name: ${i.name}`,
    `namespace: ${i.namespace}`,
    `kind: ${i.kind}`,
    `version: ${i.version}`,
    `summary: ${yamlString(i.summary)}`,
  ];
  if (i.license) lines.push(`license: ${i.license}`);
  if (i.tags.length > 0) lines.push(`tags: [${i.tags.join(", ")}]`);
  lines.push(
    "",
    "entrypoints:",
    `  ${i.kind === "skill" ? "skill" : "prompt"}: ${entry}`,
    "",
    "capabilities:",
    "  network:",
  );
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
    { path: entrypointFile(i.kind), content: instructions },
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
