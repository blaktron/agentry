import Link from "next/link";
import { apiGet, type Meta } from "@/lib/api";
import { Card, CodeBlock } from "@/components/ui";

// Home (§10.1): what Agentry is, how to install, and an honest statement of
// what scanning does and does not prove. SSR for SEO (D-08).
export default async function HomePage() {
  let meta: Meta | null = null;
  try {
    meta = await apiGet<Meta>("/meta", { revalidate: 60 });
  } catch {
    meta = null; // the marketing page must render even if the API is down
  }

  return (
    <div className="space-y-12">
      <section className="max-w-3xl">
        <h1 className="text-3xl font-semibold tracking-tight">
          A registry for single-purpose AI agents — with the scanning step built in
        </h1>
        <p className="mt-4 text-lg" style={{ color: "var(--color-muted)" }}>
          Agent instructions run with your credentials and your tool access. Agentry hosts them in
          git, and nothing becomes installable until it has passed a layered scan for prompt
          injection, hidden instructions, capability escalation, secrets, and supply-chain problems —
          then it is signed.
        </p>
        <div className="mt-6 flex flex-wrap gap-3">
          <Link
            href="/search"
            className="rounded-md px-4 py-2 text-sm font-medium"
            style={{ background: "var(--color-accent)", color: "var(--color-accent-fg)" }}
          >
            Browse agents
          </Link>
          <Link
            href="/trust"
            className="rounded-md border px-4 py-2 text-sm font-medium"
            style={{ borderColor: "var(--color-border)" }}
          >
            How scanning works
          </Link>
        </div>
      </section>

      <section className="grid gap-6 md:grid-cols-3">
        <Card>
          <h2 className="font-medium">Every version is scanned</h2>
          <p className="mt-2 text-sm" style={{ color: "var(--color-muted)" }}>
            Deterministic detectors for invisible Unicode, injection signatures, and undeclared
            capabilities, plus dependency and release-diff analysis. No flag, plan, or role skips it.
          </p>
        </Card>
        <Card>
          <h2 className="font-medium">Capabilities are declared up front</h2>
          <p className="mt-2 text-sm" style={{ color: "var(--color-muted)" }}>
            Network egress, filesystem access, subprocess execution, and expected secrets are part of
            the manifest — so your runtime can enforce least privilege, and you can see what changed
            between versions.
          </p>
        </Card>
        <Card>
          <h2 className="font-medium">Provenance you can check</h2>
          <p className="mt-2 text-sm" style={{ color: "var(--color-muted)" }}>
            Each published release is content-addressed and signed with an in-toto/DSSE attestation
            binding the archive digest to its scan report. The CLI verifies offline.
          </p>
        </Card>
      </section>

      <section className="max-w-3xl">
        <h2 className="text-xl font-semibold">Install an agent</h2>
        <div className="mt-3">
          <CodeBlock>{`agentry install acme/incident-summarizer --target=claude-skill`}</CodeBlock>
        </div>
        <p className="mt-3 text-sm" style={{ color: "var(--color-muted)" }}>
          The CLI verifies the digest and signature, shows you the declared capabilities, and asks
          before installing anything that can reach the network or run commands.
        </p>
      </section>

      <section className="max-w-3xl">
        <h2 className="text-xl font-semibold">What this does not claim</h2>
        <p className="mt-3 text-sm" style={{ color: "var(--color-muted)" }}>
          Static analysis cannot prove an agent safe, and we do not say it does. Agent pages show the
          findings, the ruleset version, and the scan date so you can judge for yourself. Novel
          injection techniques will get through; that is why versions are rescanned as the rulesets
          improve, and why advisories and quarantine exist.
        </p>
      </section>

      {meta && (
        <p className="text-xs" style={{ color: "var(--color-muted)" }}>
          Registry {meta.version} · API {meta.apiVersion}
        </p>
      )}
    </div>
  );
}
