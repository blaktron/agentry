import type { Metadata } from "next";
import { apiGetWellKnown } from "@/lib/api";
import { Card, CodeBlock } from "@/components/ui";

export const metadata: Metadata = {
  title: "Trust & security",
  description:
    "How SecureAgentry scans every published version, what the scanners look for, what signing proves, and what none of it guarantees.",
};

interface SigningKeys {
  keys: { keyId: string; algorithm: string; publicKeyPem: string }[];
}

const STAGES = [
  ["S1", "Inventory & hygiene", "Unpacks the exact bytes that will ship, sniffs file types, and rejects executables, nested archives, and structural anomalies."],
  ["S2", "Secrets", "Scans for credentials — provider key formats and high-entropy assignments — in the archive."],
  ["S3", "Hidden & obfuscated content", "Invisible Unicode, bidi overrides, the Unicode tag block, confusables, hidden HTML/CSS, data URIs, and encoded blobs in prose."],
  ["S4", "Injection signatures", "A versioned rule bundle for instruction-override frames, exfiltration directives, tool coercion, credential harvesting, persistence, and obfuscation markers."],
  ["S5", "LLM adjudication", "A model reviews the instructions against a fixed rubric with no tools and returns cited, structured scores. If it shows signs of having been manipulated, that is itself a finding."],
  ["S6", "Capability consistency", "For code-bearing BriefAgents, detects network, subprocess, filesystem, and dynamic-eval use and diffs it against the declared capabilities."],
  ["S7", "Dependencies & licenses", "Lockfile analysis, install-script detection, and typosquat heuristics."],
  ["S8", "Metadata & publisher signals", "Name confusability against popular BriefAgents, URL reputation, and publish-velocity anomalies from new accounts."],
  ["S9", "Release-diff risk", "Compares against the previous published version: new egress hosts, widened capabilities, new install scripts, first appearance of obfuscation."],
  ["S10", "Report assembly", "Produces the canonical report whose digest is signed into the attestation."],
];

// The trust page (§10.1): how scanning works, the signing keys, and an
// honest statement of limits (§1.6.3).
export default async function TrustPage() {
  const keys = await apiGetWellKnown<SigningKeys>("/.well-known/agentry/signing-keys.json", {
    revalidate: 300,
  }).catch(() => null);

  return (
    <div className="max-w-3xl space-y-10">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Trust &amp; security</h1>
        <p className="mt-3" style={{ color: "var(--color-muted)" }}>
          BriefAgent instructions are executed with your credentials and your tool access, but they are
          usually distributed with no signing, no scanning, and no review. SecureAgentry exists to close
          that gap — and to be precise about how far it closes.
        </p>
      </header>

      <section>
        <h2 className="text-xl font-semibold">What we do before anything is installable</h2>
        <p className="mt-2 text-sm" style={{ color: "var(--color-muted)" }}>
          Publication is a gate, not a formality. A version is scanned on the exact bytes that will
          ship. Findings decide the outcome: clean and low-severity versions publish automatically,
          medium and high findings go to human review, and critical findings are rejected. There is no
          flag, plan, or role that skips it — and if a scanner errors or times out, the version fails
          toward review rather than through.
        </p>
        <ul className="mt-4 space-y-3">
          {STAGES.map(([id, title, body]) => (
            <li key={id}>
              <Card>
                <p className="font-medium">
                  <span className="font-mono text-sm" style={{ color: "var(--color-accent)" }}>
                    {id}
                  </span>{" "}
                  {title}
                </p>
                <p className="mt-1 text-sm" style={{ color: "var(--color-muted)" }}>
                  {body}
                </p>
              </Card>
            </li>
          ))}
        </ul>
      </section>

      <section>
        <h2 className="text-xl font-semibold">What signing proves</h2>
        <p className="mt-2 text-sm" style={{ color: "var(--color-muted)" }}>
          Each published release is content-addressed, and we sign an in-toto statement binding that
          archive digest to the scan report that produced the decision, the ruleset version, and the
          policy in force. A verified signature means: these exact bytes are the ones this registry
          scanned and published. It does not mean the contents are benign.
        </p>
        <div className="mt-3">
          <CodeBlock>{`agentry verify acme/incident-summarizer@1.4.2`}</CodeBlock>
        </div>
        {keys && keys.keys.length > 0 && (
          <div className="mt-4">
            <h3 className="text-sm font-semibold">Current signing keys</h3>
            <ul className="mt-2 space-y-1 text-xs">
              {keys.keys.map((k) => (
                <li key={k.keyId} className="font-mono">
                  {k.keyId} · {k.algorithm}
                </li>
              ))}
            </ul>
            <p className="mt-2 text-xs" style={{ color: "var(--color-muted)" }}>
              The CLI pins these on first use and warns if they change. Rotation happens with
              overlapping validity windows.
            </p>
          </div>
        )}
      </section>

      <section>
        <h2 className="text-xl font-semibold">What this does not guarantee</h2>
        <div className="mt-3 space-y-3 text-sm" style={{ color: "var(--color-muted)" }}>
          <p>
            Static analysis cannot prove a BriefAgent safe. A sufficiently novel injection technique will
            pass a scan that was written before it existed. We publish finding counts, the ruleset
            version, and the scan date precisely so you can judge the freshness of the check rather
            than trust a badge.
          </p>
          <p>
            Declared capabilities are a contract from the author and the input to policy and scanning
            — the registry cannot enforce them while your BriefAgent runs. Your runtime should use the
            manifest to sandbox accordingly.
          </p>
          <p>
            Because detection improves after publication, we rescan published versions when rulesets
            ship. A new high-severity finding quarantines the version, notifies the author, and
            raises an advisory.
          </p>
        </div>
      </section>

      <section>
        <h2 className="text-xl font-semibold">Reporting a problem</h2>
        <p className="mt-2 text-sm" style={{ color: "var(--color-muted)" }}>
          Malicious content: use the report link on the BriefAgent page, or email abuse@ the registry
          domain. A vulnerability in SecureAgentry itself: see SECURITY.md in the open-source repository for
          the coordinated-disclosure process. The scanners and rulesets are open source, so the claims
          on this page are auditable rather than promised.
        </p>
      </section>
    </div>
  );
}
