// Cookie notice (§10 legal surface). The site sets only strictly necessary
// cookies — session, CSRF, the short-lived login state — so this is a
// notice with one acknowledgement, not a consent matrix with toggles.
// Dismissal is a cookie for everyone; for signed-in users it is also
// recorded on the account (User.cookieAckAt), so the banner stays dismissed
// on their other devices. Server component + plain form, like every other
// interaction on the site.
import Link from "next/link";
import { headers } from "next/headers";
import type { SessionUser } from "@/lib/session";

export const COOKIE_ACK_COOKIE = "agentry_cookie_ack";

export async function CookieBanner({
  user,
  acked,
}: {
  user: SessionUser | null;
  acked: boolean;
}) {
  if (acked || user?.cookieAckAt) return null;
  const pathname = (await headers()).get("x-pathname") ?? "/";
  return (
    <div
      role="region"
      aria-label="Cookie notice"
      className="fixed inset-x-0 bottom-0 z-40 border-t"
      style={{ background: "var(--color-surface)", borderColor: "var(--color-border)" }}
    >
      <form
        method="post"
        action="/cookies/ack"
        className="mx-auto flex max-w-6xl flex-wrap items-center gap-3 px-4 py-3 text-sm"
      >
        <p className="min-w-0 flex-1" style={{ color: "var(--color-muted)" }}>
          {"Agentry uses only strictly necessary cookies — they sign you in and keep the site secure. Nothing here tracks you, and there are no advertising or analytics cookies. "}
          <Link href="/privacy" className="underline">
            Privacy policy
          </Link>
        </p>
        <input type="hidden" name="next" value={pathname} />
        <button
          type="submit"
          className="rounded-md px-4 py-1.5 text-sm font-medium"
          style={{ background: "var(--color-accent)", color: "var(--color-accent-fg)" }}
        >
          OK
        </button>
      </form>
    </div>
  );
}
