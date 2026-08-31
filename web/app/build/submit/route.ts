// POST /build/submit — the Builder's engine (DEV-059): render the form
// into a workspace, pack the tar.zst, ensure the agent record exists, and
// upload the version over the cli-upload path. The API re-validates and
// re-packs; the pipeline decides. Nothing here can reach `published`
// without the gate.
import { NextRequest, NextResponse } from "next/server";
import { redirectBack, sameOrigin, readForm } from "@/lib/forms";
import { apiSend, apiUpload, problemDetail } from "@/lib/session";
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
  const visibility = String(form.get("visibility")) === "public" ? "public" : "private";

  const invalid = validateInput(input);
  if (invalid) return redirectBack(req, "/build", { error: invalid });

  // Ensure the agent record exists (idempotent from the user's view).
  const existing = await apiSend("GET", `/agents/${input.namespace}/${input.name}`);
  if (existing.status === 404) {
    const created = await apiSend("POST", "/agents", {
      namespace: input.namespace,
      name: input.name,
      kind: input.kind,
      visibility,
      summary: input.summary,
    });
    if (!created.ok) return redirectBack(req, "/build", { error: await problemDetail(created) });
  } else if (!existing.ok) {
    return redirectBack(req, "/build", { error: await problemDetail(existing) });
  }

  // No `digest` field: that cross-check asserts the CLIENT's packing
  // matches the server's canonical re-pack byte for byte (§6.5), which
  // only holds for pkg/archive's own output — a Node zstd stream is
  // well-formed but never byte-identical. This archive is built server-side
  // in this very request, so there is no client packing to distrust; the
  // server's canonical digest is the release identity either way.
  const { bytes } = packArchive(workspaceFiles(input));
  const upload = new FormData();
  upload.append("archive", new Blob([new Uint8Array(bytes)]), "agent.tar.zst");
  const res = await apiUpload(`/agents/${input.namespace}/${input.name}/versions`, upload);
  if (!res.ok) return redirectBack(req, "/build", { error: await problemDetail(res) });

  return redirectBack(req, `/${input.namespace}/${input.name}`, {
    ok: `version ${input.version} submitted — the security pipeline decides; this page shows the verdict.`,
  });
}
