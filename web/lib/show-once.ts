// showOnce renders a minimal HTML page for a secret that is displayed
// exactly once (SCIM tokens, webhook signing secrets, PATs). Secrets never
// ride URLs — a redirect-with-query would put them in history and logs.
// Values are HTML-escaped; the page inherits the app-wide CSP headers.
import "server-only";
import { NextResponse } from "next/server";

function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

export function showOnce(opts: {
  title: string;
  lines: [label: string, value: string][];
  backHref: string;
}): NextResponse {
  const rows = opts.lines
    .map(
      ([label, value]) =>
        `<p style="margin:0 0 4px"><strong>${esc(label)}</strong></p>` +
        `<pre style="margin:0 0 16px;padding:8px;border:1px solid #ccc;border-radius:6px;overflow-x:auto">${esc(value)}</pre>`,
    )
    .join("");
  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>${esc(opts.title)}</title></head>
<body style="font-family:system-ui,sans-serif;max-width:640px;margin:48px auto;padding:0 16px">
<main><header><h1 style="font-size:20px">${esc(opts.title)}</h1></header>
<nav aria-label="Back"><a href="${esc(opts.backHref)}">&larr; Back</a></nav>
<p>Copy the value below now — it is not stored and cannot be shown again.</p>
${rows}
</main></body></html>`;
  return new NextResponse(html, {
    status: 200,
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
  });
}
