// The download manifest (scripts/release/build-downloads.sh) and the fixed
// matrix of targets the /download page shows. The manifest is read from
// disk at request time — AGENTRY_DOWNLOADS_DIR, the same directory the edge
// serves at AGENTRY_DOWNLOADS_URL — so publishing a new build is a file
// copy, not an image rebuild. A missing or unreadable manifest is not an
// error: every target then renders as "not yet available".
import "server-only";
import { readFile } from "node:fs/promises";
import path from "node:path";

export type Product = "cli" | "desktop";
export type OS = "linux" | "darwin" | "windows";
export type Arch = "amd64" | "arm64" | "universal";

export type Artifact = {
  product: Product;
  os: OS;
  arch: Arch;
  file: string;
  version: string;
  sizeBytes: number;
  sha256: string;
};

export type Manifest = {
  generatedAt: string;
  cli: { version: string };
  desktop: { version: string };
  artifacts: Artifact[];
};

// The matrix is the promise, the manifest is what has been kept. Order is
// display order.
export const CLI_TARGETS: { os: OS; arch: Arch; label: string; note: string }[] = [
  { os: "darwin", arch: "arm64", label: "macOS", note: "Apple silicon" },
  { os: "darwin", arch: "amd64", label: "macOS", note: "Intel" },
  { os: "linux", arch: "amd64", label: "Linux", note: "x86-64, static" },
  { os: "linux", arch: "arm64", label: "Linux", note: "arm64, static" },
  { os: "windows", arch: "amd64", label: "Windows", note: "x86-64" },
];

export const DESKTOP_TARGETS: { os: OS; arch: Arch; label: string; note: string }[] = [
  { os: "linux", arch: "amd64", label: "Linux", note: "x86-64, GTK/WebKit" },
  { os: "darwin", arch: "universal", label: "macOS", note: "universal, notarised" },
  { os: "windows", arch: "amd64", label: "Windows", note: "x86-64" },
];

export function downloadsBase(): string {
  return (process.env.AGENTRY_DOWNLOADS_URL ?? "/downloads").replace(/\/$/, "");
}

export async function readManifest(): Promise<Manifest | null> {
  const dir = process.env.AGENTRY_DOWNLOADS_DIR;
  if (!dir) return null;
  try {
    const raw = await readFile(path.join(dir, "manifest.json"), "utf8");
    const m = JSON.parse(raw) as Manifest;
    if (!Array.isArray(m.artifacts)) return null;
    return m;
  } catch {
    return null;
  }
}

export function findArtifact(m: Manifest | null, product: Product, os: OS, arch: Arch): Artifact | null {
  return m?.artifacts.find((a) => a.product === product && a.os === os && a.arch === arch) ?? null;
}

export function fmtBytes(n: number): string {
  if (n >= 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  if (n >= 1024) return `${Math.round(n / 1024)} kB`;
  return `${n} B`;
}
