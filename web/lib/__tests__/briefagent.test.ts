import { describe, expect, it } from "vitest";
import { zstdDecompressSync } from "node:zlib";
import {
  BuilderInput, MAX_INSTRUCTIONS_BYTES, packArchive, parseIntakeLines, parseServerLines, renderManifest,
  validateInput, workspaceFiles,
} from "../briefagent";

function input(): BuilderInput {
  return {
    name: "hello-web-build",
    namespace: "acme",
    modes: ["autonomous"],
    intake: [],
    opening: "",
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
    mcpServers: [],
  };
}

describe("validateInput", () => {
  it("accepts the fixture", () => {
    expect(validateInput(input())).toBeNull();
  });
  it("caps instructions at the §19 quota (agentry#18)", () => {
    const i = input();
    i.instructions = "x".repeat(MAX_INSTRUCTIONS_BYTES);
    expect(validateInput(i)).toBeNull();
    i.instructions = "x".repeat(MAX_INSTRUCTIONS_BYTES + 1);
    expect(validateInput(i)).toMatch(/1 MiB/);
    // Byte length, not character count: a multi-byte character counts fully.
    i.instructions = "é".repeat(MAX_INSTRUCTIONS_BYTES / 2 + 1);
    expect(validateInput(i)).toMatch(/1 MiB/);
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
    expect(y).toContain('schemaVersion: "2"');
    expect(y).toContain("modes: [autonomous]");
    expect(y).not.toContain("kind:");
    expect(y).toContain("egress: [api.example.com]");
    expect(y).toContain("write: { paths: [out] }");
    expect(y).toContain("exec: { commands: [jq] }");
    expect(y).toContain("secrets: [EXAMPLE_TOKEN]");
    expect(y).toContain("instruction: AGENT.md");
    expect(y).toContain("include: [agent.yaml, AGENT.md, README.md, LICENSE]");
  });
  it("quotes the summary safely", () => {
    const i = input();
    i.summary = 'has "quotes": and #comment chars';
    expect(renderManifest(i)).toContain('summary: "has \\"quotes\\": and #comment chars"');
  });
});

describe("modes, intake and the opening", () => {
  it("refuses an empty mode set and an opening without interactive", () => {
    const i = input();
    i.modes = [];
    expect(validateInput(i)).toMatch(/run mode/);
    i.modes = ["autonomous"];
    i.opening = "Hello";
    expect(validateInput(i)).toMatch(/interactive/);
    i.modes = ["interactive", "autonomous"];
    expect(validateInput(i)).toBeNull();
  });
  it("renders both modes in a fixed order with the intake and opening blocks", () => {
    const i = input();
    i.modes = ["interactive", "autonomous"];
    i.opening = "What should I look at?";
    i.intake = [
      { id: "topic", prompt: "What should I look at?", type: "text", required: true, choices: [] },
      { id: "region", prompt: "Which region?", type: "choice", required: false, choices: ["emea", "apac"] },
    ];
    const y = renderManifest(i);
    expect(y).toContain("modes: [autonomous, interactive]");
    expect(y).toContain('intake:\n  - id: topic\n    prompt: "What should I look at?"\n    required: true\n  - id: region\n    prompt: "Which region?"\n    type: choice\n    choices: ["emea", "apac"]');
    expect(y).toContain('interactive:\n  opening: "What should I look at?"');
  });
  it("parses the intake line syntax and names a bad line", () => {
    const ok = parseIntakeLines("topic: What should I look at? type=text required\n# comment\nregion: Which region? type=choice choices=emea,apac");
    expect(ok.error).toBeNull();
    expect(ok.intake).toEqual([
      { id: "topic", prompt: "What should I look at?", type: "text", required: true, choices: [] },
      { id: "region", prompt: "Which region?", type: "choice", required: false, choices: ["emea", "apac"] },
    ]);
    expect(parseIntakeLines("no colon here").error).toMatch(/expected <id>: <prompt>/);
    expect(parseIntakeLines("x: prompt type=date").error).toMatch(/unknown type/);
  });
  it("applies the V10 intake rules", () => {
    const i = input();
    i.intake = [{ id: "Bad Id", prompt: "p", type: "text", required: false, choices: [] }];
    expect(validateInput(i)).toMatch(/intake id/);
    i.intake = [{ id: "a", prompt: "p", type: "choice", required: false, choices: [] }];
    expect(validateInput(i)).toMatch(/needs choices/);
    i.intake = [{ id: "a", prompt: "p", type: "text", required: false, choices: ["x"] }];
    expect(validateInput(i)).toMatch(/only applies to type choice/);
    i.intake = [
      { id: "a", prompt: "p", type: "text", required: false, choices: [] },
      { id: "a", prompt: "q", type: "text", required: false, choices: [] },
    ];
    expect(validateInput(i)).toMatch(/duplicate/);
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
    expect(names).toEqual(["AGENT.md", "LICENSE", "README.md", "agent.yaml"]);
  });

  it("is deterministic for identical input", () => {
    const a = packArchive(workspaceFiles(input()));
    const b = packArchive(workspaceFiles(input()));
    expect(a.digest).toBe(b.digest);
  });
});

describe("mcpServers (RUNNER-PLAN-3)", () => {
  it("parses the line format and renders the manifest block", () => {
    const { servers, error } = parseServerLines(
      "npm:@scope/server-x@1.2.3 tools=list_issues secrets=GITHUB_PAT egress=api.github.com\n" +
      "# comment\npypi:mcp-server-fetch@0.6.2 egress=*\n",
    );
    expect(error).toBeNull();
    expect(servers).toHaveLength(2);
    const i = input();
    i.mcpServers = servers;
    expect(validateInput(i)).toBeNull();
    const y = renderManifest(i);
    expect(y).toContain('- npm: "@scope/server-x"');
    expect(y).toContain('version: "1.2.3"');
    expect(y).toContain("tools: [list_issues]");
    expect(y).toContain('egress: ["*"]');
  });
  it("refuses a range version — the pin is release content", () => {
    const { servers, error } = parseServerLines("npm:server-x@^1.2.0");
    expect(error).toBeNull();
    const i = input();
    i.mcpServers = servers;
    expect(validateInput(i)).toMatch(/exact version/);
  });
  it("refuses a malformed line with the line named", () => {
    const { error } = parseServerLines("docker:whatever@1.0.0");
    expect(error).toMatch(/expected npm:/);
  });
  it("refuses duplicates", () => {
    const { servers } = parseServerLines("npm:server-x@1.0.0\nnpm:server-x@1.0.1");
    const i = input();
    i.mcpServers = servers;
    expect(validateInput(i)).toMatch(/duplicate/);
  });
});
