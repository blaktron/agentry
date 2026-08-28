"use client";

// Refresher re-renders the server page on an interval while a pipeline run
// is in flight (§10.1 publish flow "watch pipeline live"). Self-hosted
// client bundle — allowed by the §10.3 CSP (script-src 'self'); the page
// remains fully functional without JS via manual reload.
import { useRouter } from "next/navigation";
import { useEffect } from "react";

export function Refresher({ everyMs = 2500 }: { everyMs?: number }) {
  const router = useRouter();
  useEffect(() => {
    const t = setInterval(() => router.refresh(), everyMs);
    return () => clearInterval(t);
  }, [router, everyMs]);
  return null;
}
