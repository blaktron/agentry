import type { Metadata } from "next";
import { Card, CodeBlock } from "@/components/ui";
import { SITE } from "@/lib/site";

export const metadata: Metadata = {
  title: "Download",
  description: `Get the ${SITE.brand} CLI and desktop app.`,
};

// Download (§10.1 nav). The CLI is the working client today; the desktop app
// is a roadmap item, shown as "coming soon" rather than a dead link. Concrete
// artifact URLs are wired once releases are cut (the release workflow builds
// cross-platform binaries + a Homebrew tap).
const PLATFORMS = [
  { os: "macOS", note: "Apple silicon & Intel", hint: "arm64 · amd64" },
  { os: "Linux", note: "static binary", hint: "arm64 · amd64" },
  { os: "Windows", note: "static binary", hint: "amd64" },
];

export default function DownloadPage() {
  return (
    <div className="mx-auto flex max-w-3xl flex-col gap-8">
      <header>
        <h1 className="text-3xl font-semibold tracking-tight">Download {SITE.brand}</h1>
        <p className="mt-3 text-lg" style={{ color: "var(--color-muted)" }}>
          The command-line client publishes, installs, and verifies agents. Every install checks the
          archive digest and signature before anything lands on your machine.
        </p>
      </header>

      <section>
        <h2 className="text-xl font-semibold">Command-line interface</h2>
        <p className="mt-2 text-sm" style={{ color: "var(--color-muted)" }}>
          Install with Homebrew, or grab a static binary for your platform. Verify the release
          signature after downloading.
        </p>
        <div className="mt-4">
          <CodeBlock>{`brew install secureagentry/tap/agentry
# or download a binary below, then:
agentry version`}</CodeBlock>
        </div>
        <div className="mt-4 grid gap-3 sm:grid-cols-3">
          {PLATFORMS.map((p) => (
            <Card key={p.os}>
              <div className="font-medium">{p.os}</div>
              <div className="mt-1 text-sm" style={{ color: "var(--color-muted)" }}>
                {p.note}
              </div>
              <div className="mt-3 text-xs" style={{ color: "var(--color-muted)" }}>
                {p.hint}
              </div>
              <div
                className="mt-3 inline-block rounded-md border px-3 py-1.5 text-xs"
                style={{ borderColor: "var(--color-border)", color: "var(--color-muted)" }}
              >
                Binaries published with the first release
              </div>
            </Card>
          ))}
        </div>
      </section>

      <section>
        <h2 className="text-xl font-semibold">Desktop app</h2>
        <Card className="mt-3">
          <div className="flex items-center gap-3">
            <span className="font-medium">{SITE.brand} Desktop</span>
            <span
              className="rounded-full px-2 py-0.5 text-xs"
              style={{ background: "var(--color-surface)", color: "var(--color-muted)" }}
            >
              v0.1, early access
            </span>
          </div>
          <p className="mt-2 text-sm" style={{ color: "var(--color-muted)" }}>
            A desktop client for macOS, Windows, and Linux: browse the registry, read security
            report cards, install with on-device digest and signature verification, and validate
            local BriefAgent folders with the same scanners the registry runs.
          </p>
          <p className="mt-2 text-sm" style={{ color: "var(--color-muted)" }}>
            Builds are published on the{" "}
            <a href="https://github.com/blaktron/agentry-desktop/releases" className="underline">
              agentry-desktop releases page
            </a>{" "}
            while the project is in early access; public downloads will move here at launch.
          </p>
        </Card>
      </section>

      <section>
        <h2 className="text-xl font-semibold">Verify what you downloaded</h2>
        <p className="mt-2 text-sm" style={{ color: "var(--color-muted)" }}>
          The CLI verifies BriefAgents; you can also verify the CLI itself against the published release
          signatures and checksums. Full instructions live in the{" "}
          <a href={SITE.docsUrl} className="underline">
            documentation
          </a>
          .
        </p>
      </section>
    </div>
  );
}
