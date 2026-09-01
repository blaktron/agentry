import type { Metadata } from "next";
import { Card, CodeBlock } from "@/components/ui";
import PlatformHint from "@/components/platform-hint";
import {
  CLI_TARGETS,
  DESKTOP_TARGETS,
  downloadsBase,
  findArtifact,
  fmtBytes,
  readManifest,
  type Artifact,
  type Manifest,
  type Product,
} from "@/lib/downloads";
import { SITE } from "@/lib/site";

export const metadata: Metadata = {
  title: "Download",
  description: `Get the ${SITE.brand} CLI and desktop app.`,
};

// The manifest is read from disk per request (see lib/downloads.ts).
export const dynamic = "force-dynamic";

// Download (§10.1 nav). Binaries first — the page's job is to hand a
// visitor the right file — then the developer paths: package managers,
// per-provider installs, verification. Every target in the matrix is shown;
// the ones the manifest has are links, the rest say so honestly instead of
// pretending.
function DownloadCard({
  product,
  label,
  note,
  os,
  arch,
  artifact,
}: {
  product: Product;
  label: string;
  note: string;
  os: string;
  arch: string;
  artifact: Artifact | null;
}) {
  const base = downloadsBase();
  return (
    <Card
      tone={artifact ? "primary" : "secondary"}
      className="download-card flex flex-col gap-2"
      // data-platform is what components/platform-hint.tsx matches on.
      data-platform={`${os}-${arch}`}
    >
      <div className="flex items-baseline justify-between gap-2">
        <div className="font-medium">{label}</div>
        <span
          className="yours rounded-full border px-2 py-0.5 text-xs"
          style={{ borderColor: "var(--color-accent)", color: "var(--color-accent)" }}
          aria-hidden="true"
        >
          Your platform
        </span>
      </div>
      <div className="text-sm" style={{ color: "var(--color-muted)" }}>
        {note}
      </div>
      {artifact ? (
        <>
          <a
            href={`${base}/${artifact.file}`}
            className="mt-1 inline-flex items-center justify-center rounded-md px-3 py-2 text-sm font-medium"
            style={{ background: "var(--color-accent)", color: "var(--color-accent-fg)" }}
            download
          >
            Download {product === "cli" ? "CLI" : "Desktop"} · {artifact.version}
          </a>
          <dl
            className="mt-1 grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-0.5 font-mono text-xs"
            style={{ color: "var(--color-muted)" }}
          >
            <dt>size</dt>
            <dd>{fmtBytes(artifact.sizeBytes)}</dd>
            <dt>sha256</dt>
            <dd className="truncate" title={artifact.sha256}>
              {artifact.sha256}
            </dd>
          </dl>
        </>
      ) : (
        <div
          className="mt-1 rounded-md border border-dashed px-3 py-2 text-xs"
          style={{ borderColor: "var(--color-border)", color: "var(--color-muted)" }}
        >
          Not built yet — this target is on the release matrix and will appear here when it is.
        </div>
      )}
    </Card>
  );
}

function Grid({
  product,
  targets,
  manifest,
}: {
  product: Product;
  targets: typeof CLI_TARGETS;
  manifest: Manifest | null;
}) {
  return (
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
      {targets.map((t) => (
        <DownloadCard
          key={`${product}-${t.os}-${t.arch}`}
          product={product}
          label={t.label}
          note={t.note}
          os={t.os}
          arch={t.arch}
          artifact={findArtifact(manifest, product, t.os, t.arch)}
        />
      ))}
    </div>
  );
}

export default async function DownloadPage() {
  const manifest = await readManifest();
  const base = downloadsBase();
  const built = manifest?.artifacts.length ?? 0;

  return (
    <div className="space-y-12">
      <PlatformHint />

      <header className="max-w-3xl">
        <h1 className="text-3xl font-semibold tracking-tight">Download {SITE.brand}</h1>
        <p className="mt-3 text-lg" style={{ color: "var(--color-muted)" }}>
          The command-line client publishes, installs, runs, and verifies BriefAgents. Every install
          checks the archive digest and signature before anything lands on your machine.
        </p>
        {manifest ? (
          <p className="mt-2 text-sm" style={{ color: "var(--color-muted)" }}>
            Latest builds: CLI <code>{manifest.cli.version}</code>, desktop{" "}
            <code>{manifest.desktop.version}</code> · {built} of{" "}
            {CLI_TARGETS.length + DESKTOP_TARGETS.length} targets available ·{" "}
            <a href={`${base}/SHA256SUMS`} className="underline">
              SHA256SUMS
            </a>
          </p>
        ) : (
          <p className="mt-2 text-sm" style={{ color: "var(--color-muted)" }}>
            No builds are published on this registry yet; every target below shows as not yet
            available.
          </p>
        )}
      </header>

      <section>
        <h2 className="text-xl font-semibold">Command-line interface</h2>
        <p className="mt-2 max-w-3xl text-sm" style={{ color: "var(--color-muted)" }}>
          A single static binary. Put it on your <code>PATH</code>, run <code>agentry --version</code>,
          then <code>agentry setup</code> once to configure your LLM provider and the runner images.
        </p>
        <div className="mt-4">
          <Grid product="cli" targets={CLI_TARGETS} manifest={manifest} />
        </div>
      </section>

      <section>
        <div className="flex flex-wrap items-baseline gap-3">
          <h2 className="text-xl font-semibold">{SITE.brand} Desktop</h2>
          <span
            className="rounded-full px-2 py-0.5 text-xs"
            style={{ background: "var(--color-surface)", color: "var(--color-muted)" }}
          >
            early access
          </span>
        </div>
        <p className="mt-2 max-w-3xl text-sm" style={{ color: "var(--color-muted)" }}>
          A desktop client for macOS, Windows, and Linux: browse the registry, read security report
          cards, install with on-device digest and signature verification, build and submit
          BriefAgents, and run them with the same runner the CLI uses.
        </p>
        <div className="mt-4">
          <Grid product="desktop" targets={DESKTOP_TARGETS} manifest={manifest} />
        </div>
        <p className="mt-3 text-sm" style={{ color: "var(--color-muted)" }}>
          Builds are also published on the{" "}
          <a href="https://github.com/blaktron/agentry-desktop/releases" className="underline">
            agentry-desktop releases page
          </a>{" "}
          while the project is in early access.
        </p>
      </section>

      <section className="max-w-3xl">
        <h2 className="text-xl font-semibold">Verify what you downloaded</h2>
        <p className="mt-2 text-sm" style={{ color: "var(--color-muted)" }}>
          Every file above is listed in{" "}
          <a href={`${base}/SHA256SUMS`} className="underline">
            SHA256SUMS
          </a>
          , and each card shows its own digest. Check before you run:
        </p>
        <div className="mt-3">
          <CodeBlock>{`sha256sum -c --ignore-missing SHA256SUMS   # Linux
shasum -a 256 -c --ignore-missing SHA256SUMS # macOS
Get-FileHash .\\agentry-*.exe                 # Windows, compare by eye`}</CodeBlock>
        </div>
        <p className="mt-2 text-sm" style={{ color: "var(--color-muted)" }}>
          The CLI verifies BriefAgents the same way, with a signature on top. Full instructions live
          in the{" "}
          <a href={SITE.docsUrl} className="underline">
            documentation
          </a>
          .
        </p>
      </section>

      <section className="max-w-3xl">
        <h2 className="text-xl font-semibold">Install with a package manager</h2>
        <p className="mt-2 text-sm" style={{ color: "var(--color-muted)" }}>
          Homebrew is the supported path on macOS and Linux; the tap tracks the same releases as the
          binaries above.
        </p>
        <div className="mt-3">
          <CodeBlock>{`brew install secureagentry/tap/agentry
agentry --version`}</CodeBlock>
        </div>
      </section>

      {/* Per-provider installs (RUNNER-PLAN-2 §P5, req 6): BriefAgents that
          run on the host application's own tool plane. Provider flags are
          aliases for install targets, so the commands here must match what
          `agentry install --provider` actually does. */}
      <section>
        <h2 className="text-xl font-semibold">Run BriefAgents in your agent app</h2>
        <p className="mt-2 max-w-3xl text-sm" style={{ color: "var(--color-muted)" }}>
          These installs use the host application&apos;s own MCP servers and built-in tools instead
          of the docker gateway path — the declared capability contract maps onto the host&apos;s
          tool vocabulary, and enforcement is the host&apos;s.
        </p>
        <div className="mt-4 grid gap-3 md:grid-cols-3">
          <Card>
            <div className="font-medium">Claude Code</div>
            <div className="mt-3">
              <CodeBlock>{`agentry install ns/name --provider claude`}</CodeBlock>
            </div>
            <p className="mt-3 text-sm" style={{ color: "var(--color-muted)" }}>
              Installs as a Claude skill, with <code>allowed-tools</code> derived from the declared
              contract.
            </p>
          </Card>
          <Card>
            <div className="font-medium">Codex</div>
            <div className="mt-3">
              <CodeBlock>{`agentry install ns/name --provider codex`}</CodeBlock>
            </div>
            <p className="mt-3 text-sm" style={{ color: "var(--color-muted)" }}>
              Installs as an AGENTS.md section plus the BriefAgent&apos;s files.
            </p>
          </Card>
          <Card>
            <div className="font-medium">OpenClaw</div>
            <div className="mt-3">
              <CodeBlock>{`agentry install ns/name --provider openclaw`}</CodeBlock>
            </div>
            <p className="mt-3 text-sm" style={{ color: "var(--color-muted)" }}>
              Installs a Claude-format skill; OpenClaw consumes those today.
            </p>
          </Card>
        </div>
        <Card className="mt-3" tone="secondary">
          <div className="font-medium">Standalone (any machine with docker)</div>
          <div className="mt-3">
            <CodeBlock>{`agentry setup
agentry run ns/name`}</CodeBlock>
          </div>
          <p className="mt-3 text-sm" style={{ color: "var(--color-muted)" }}>
            The isolated-container path: each run executes in its own container with its tools
            served through a per-run MCP gateway.
          </p>
        </Card>
        <p className="mt-3 text-sm" style={{ color: "var(--color-muted)" }}>
          Distribution through each provider&apos;s plugin system is planned.
        </p>
      </section>
    </div>
  );
}
