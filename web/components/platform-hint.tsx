"use client";

// PlatformHint marks the download card for the visitor's own platform.
// Progressive enhancement: the page is complete without it, and it only
// reads the navigator — nothing is sent anywhere. Cards carry
// data-platform="<os>-<arch>"; the one that matches gets data-yours="true",
// which the stylesheet styles, and its "Your platform" pill becomes visible.
import { useEffect } from "react";

function detect(): { os: string; arch: string } | null {
  if (typeof navigator === "undefined") return null;
  const ua = navigator.userAgent;
  const nav = navigator as Navigator & {
    userAgentData?: { platform?: string; architecture?: string };
  };
  const platform = (nav.userAgentData?.platform ?? navigator.platform ?? "").toLowerCase();
  let os = "";
  if (platform.includes("mac") || ua.includes("Mac OS")) os = "darwin";
  else if (platform.includes("win") || ua.includes("Windows")) os = "windows";
  else if (platform.includes("linux") || ua.includes("Linux")) os = "linux";
  if (!os) return null;
  // Apple silicon is not exposed to page script; Macs default to arm64
  // since that is what has shipped since 2020. Everyone else is x86-64
  // unless the UA says otherwise.
  let arch = os === "darwin" ? "arm64" : "amd64";
  if (/aarch64|arm64/i.test(ua)) arch = "arm64";
  return { os, arch };
}

export default function PlatformHint() {
  useEffect(() => {
    const d = detect();
    if (!d) return;
    const exact = document.querySelector<HTMLElement>(`[data-platform="${d.os}-${d.arch}"]`);
    const anyArch = document.querySelector<HTMLElement>(`[data-platform^="${d.os}-"]`);
    const el = exact ?? anyArch;
    if (el) el.dataset.yours = "true";
  }, []);
  return null;
}
