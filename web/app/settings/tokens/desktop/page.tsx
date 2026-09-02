import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { Card } from "@/components/ui";
import { currentUser } from "@/lib/session";

export const metadata: Metadata = { title: "Authorize Agentry Desktop" };

// GET /settings/tokens/desktop?port=NNNNN&state=S — the desktop app's
// browser sign-in (DEV-058). The app starts a one-shot listener on
// 127.0.0.1:<port>, opens this page in the system browser, and waits.
// Signing in happens through the normal login path (the directory service
// under DEV-057); this page then asks ONE explicit question — authorize the
// desktop app? — and the approve route hands the loopback listener a
// single-use CODE, which the app exchanges for its PAT from its own process
// (agentry#19: the token never rides a URL). `state` is the app's CSRF
// nonce, bound to the grant server-side: the app rejects a callback whose
// state it did not itself generate, so a drive-by open of this page cannot
// plant a foreign grant in someone's desktop app.
const PORT_MIN = 1024;
const PORT_MAX = 65535;
const STATE_RE = /^[A-Za-z0-9_-]{8,128}$/;

export default async function DesktopAuthorizePage({
  searchParams,
}: {
  searchParams: Promise<{ port?: string; state?: string }>;
}) {
  const params = await searchParams;
  const port = Number.parseInt(params.port ?? "", 10);
  const state = params.state ?? "";
  const valid =
    Number.isInteger(port) && port >= PORT_MIN && port <= PORT_MAX && STATE_RE.test(state);

  const user = await currentUser();
  if (!user) {
    const next = `/settings/tokens/desktop?port=${encodeURIComponent(params.port ?? "")}&state=${encodeURIComponent(state)}`;
    redirect(`/login?next=${encodeURIComponent(next)}`);
  }

  if (!valid) {
    return (
      <div className="mx-auto max-w-md">
        <h1 className="mb-4 text-xl font-semibold">Authorize Agentry Desktop</h1>
        <Card>
          <p className="text-sm">
            This page is opened by the desktop app during sign-in, and this
            request is missing or malforms its callback parameters. Start the
            sign-in again from the app (Settings → Sign in via browser).
          </p>
        </Card>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-md">
      <h1 className="mb-4 text-xl font-semibold">Authorize Agentry Desktop</h1>
      <Card>
        <p className="text-sm">
          The Agentry Desktop app on <strong>this computer</strong> is asking
          for access as <strong>{user!.handle}</strong>. Approving hands the app
          listening on <code>127.0.0.1:{port}</code> a one-time code, which it
          exchanges for a personal access token within a minute — the token
          itself never appears in your browser, and nothing leaves this machine.
        </p>
        <p className="mt-2 text-xs" style={{ color: "var(--color-muted)" }}>
          Scopes: agent read/publish, repo read/write, profile. The token
          appears under Settings → Tokens and can be revoked there any time.
          If you did not just click “Sign in via browser” in the desktop app,
          close this tab.
        </p>
        <form method="post" action="/settings/tokens/desktop/approve" className="mt-4 flex gap-2">
          <input type="hidden" name="port" value={String(port)} />
          <input type="hidden" name="state" value={state} />
          <button
            type="submit"
            className="rounded-md px-3 py-1.5 text-sm font-medium"
            style={{ background: "var(--color-accent)", color: "var(--color-accent-fg)" }}
          >
            Authorize the desktop app
          </button>
        </form>
      </Card>
    </div>
  );
}
