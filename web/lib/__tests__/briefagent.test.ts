import { describe, expect, it } from "vitest";
import { zstdDecompressSync } from "node:zlib";
import {
  BuilderInput, packArchive, renderManifest, validateInput, workspaceFiles,
} from "../briefagent";

function input(): BuilderInput {
  return {
    name: "hello-web-build",
    namespace: "acme",
    kind: "skill",
    version: "0.1.0",
    summary: "Builder round-trip fixture",
    license: "MIT",
    tags: ["fixture"],
    instructions: "# hello\n\nDo the one job.\n",
    egressMode: "hosts",
    egressHosts: ["api.example.com"],
    fsRead: "workspace",
    fsReadPaths: [],
    fsWrite: "paths",
    fsWritePaths: ["out"],
    execCommands: ["jq"],
    secrets: ["EXAMPLE_TOKEN"],
    dataAccess: ["code"],
  };
}

describe("validateInput", () => {
  it("accepts the fixture", () => {
    expect(validateInput(input())).toBeNull();
  });
  it("refuses hosts mode without hosts", () => {
    const i = input();
    i.egressHosts = [];
    expect(validateInput(i)).toMatch(/hosts/);
  });
  it("refuses a bad name", () => {
    const i = input();
    i.name = "Bad_Name";
    expect(validateInput(i)).toMatch(/name/);
  });
});

describe("renderManifest", () => {
  it("renders the closed-schema shapes", () => {
    const y = renderManifest(input());
    expect(y).toContain('schemaVersion: "1"');
    expect(y).toContain("egress: [api.example.com]");
    expect(y).toContain("write: { paths: [out] }");
    expect(y).toContain("exec: { commands: [jq] }");
    expect(y).toContain("secrets: [EXAMPLE_TOKEN]");
    expect(y).toContain("skill: SKILL.md");
    expect(y).toContain("include: [agent.yaml, SKILL.md, README.md, LICENSE]");
  });
  it("quotes the summary safely", () => {
    const i = input();
    i.summary = 'has "quotes": and #comment chars';
    expect(renderManifest(i)).toContain('summary: "has \\"quotes\\": and #comment chars"');
  });
});

describe("packArchive", () => {
  it("is a valid tar.zst whose names are sorted", () => {
    const { bytes, digest } = packArchive(workspaceFiles(input()));
    expect(digest).toMatch(/^sha256:[0-9a-f]{64}$/);

    const tar = zstdDecompressSync(bytes);
    const names: string[] = [];
    let off = 0;
    while (off < tar.length) {
      const name = tar.subarray(off, off + 100).toString("utf8").replace(/\0.*$/, "");
      if (!name) break;
      expect(tar.subarray(off + 257, off + 262).toString("utf8")).toBe("ustar");
      const size = parseInt(tar.subarray(off + 124, off + 136).toString("utf8"), 8);
      names.push(name);
      off += 512 + Math.ceil(size / 512) * 512;
    }
    expect(names).toEqual(["LICENSE", "README.md", "SKILL.md", "agent.yaml"]);
  });

  it("is deterministic for identical input", () => {
    const a = packArchive(workspaceFiles(input()));
    const b = packArchive(workspaceFiles(input()));
    expect(a.digest).toBe(b.digest);
  });
});
