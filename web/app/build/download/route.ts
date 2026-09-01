// POST /build/download — the Builder's local path. Renders the same
// workspace the submit route renders, packs the same canonical tar.zst, and
// hands it back as a download instead of a submission. No account needed:
// nothing here touches the registry, so there is nothing to authorize. The
// archive is exactly what `agentry publish` would pack from the same files
// — publish it later, or run it unsigned with `agentry run --local`.
import { NextRequest, NextResponse } from "next/server";
import { redirectBack, sameOrigin, readForm } from "@/lib/forms";
import {
  BuilderInput, packArchive, parseServerLines, validateInput, workspaceFiles,
} from "@/lib/briefagent";

function list(v: FormDataEntryValue | null): string[] {
  return String(v ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

export async function POST(req: NextRequest) {
  if (!sameOrigin(req)) return new NextResponse("cross-origin form post rejected", { status: 403 });
  const form = await readForm(req);

  const kind = String(form.get("kind") ?? "skill");
  const { servers, error: serverErr } = parseServerLines(String(form.get("mcpServers") ?? ""));
  if (serverErr) return redirectBack(req, "/build", { error: serverErr });
  const input: BuilderInput = {
    mcpServers: servers,
    name: String(form.get("name") ?? "").trim(),
    namespace: String(form.get("namespace") ?? "").trim(),
    kind: kind === "prompt-agent" ? "prompt-agent" : "skill",
    version: String(form.get("version") ?? "").trim(),
    summary: String(form.get("summary") ?? "").trim(),
    license: String(form.get("license") ?? "").trim(),
    tags: list(form.get("tags")),
    instructions: String(form.get("instructions") ?? ""),
    egressMode: (["none", "hosts", "all"].includes(String(form.get("egressMode")))
      ? String(form.get("egressMode"))
      : "none") as BuilderInput["egressMode"],
    egressHosts: list(form.get("egressHosts")),
    fsRead: (["none", "workspace", "paths"].includes(String(form.get("fsRead")))
      ? String(form.get("fsRead"))
      : "none") as BuilderInput["fsRead"],
    fsReadPaths: list(form.get("fsReadPaths")),
    fsWrite: (["none", "workspace", "paths"].includes(String(form.get("fsWrite")))
      ? String(form.get("fsWrite"))
      : "none") as BuilderInput["fsWrite"],
    fsWritePaths: list(form.get("fsWritePaths")),
    execCommands: list(form.get("execCommands")),
    secrets: list(form.get("secrets")),
    dataAccess: list(form.get("dataAccess")),
  };

  const invalid = validateInput(input);
  if (invalid) return redirectBack(req, "/build", { error: invalid });

  const { bytes, digest } = packArchive(workspaceFiles(input));
  const filename = `${input.namespace}-${input.name}-${input.version}.tar.zst`;
  return new NextResponse(new Uint8Array(bytes), {
    status: 200,
    headers: {
      "Content-Type": "application/octet-stream",
      "Content-Disposition": `attachment; filename="${filename}"`,
      "Content-Length": String(bytes.length),
      // The canonical digest of what was packed, for anyone who wants to
      // pin it before publishing.
      "X-Archive-Digest": digest,
      "Cache-Control": "no-store",
    },
  });
}
