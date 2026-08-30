import type { Metadata } from "next";
import Link from "next/link";
import { SITE } from "@/lib/site";

export const metadata: Metadata = {
  title: "About",
  description: `About ${SITE.brand}: trust infrastructure for AI agents.`,
};

export default function AboutPage() {
  return (
    <div className="mx-auto flex max-w-2xl flex-col gap-6">
      <header>
        <h1 className="text-3xl font-semibold tracking-tight">About {SITE.brand}</h1>
      </header>
      <div className="flex flex-col gap-4 text-sm leading-relaxed" style={{ color: "var(--color-fg)" }}>
        <p>
          {SITE.brand} is trust infrastructure for BriefAgents, single-purpose AI agents. BriefAgent
          instructions (skills, system prompts, small MCP servers) run with your credentials and your
          tool access, yet they are usually distributed with no signing, no scanning, and no review.{" "}
          {SITE.brand} treats that gap as the problem worth solving.
        </p>
        <p>
          Every BriefAgent lives in git, and every published version is an immutable, content-addressed
          release that has passed a layered security pipeline: deterministic detectors for hidden and
          obfuscated instructions, injection-signature rules, capability-consistency checks,
          dependency and supply-chain analysis, and release-diff review. Nothing becomes installable
          until the gate decides, and every release carries a signature you can verify offline.
        </p>
        <p>
          We are deliberate about what this does and does not prove. Static scanning reduces risk; it
          cannot prove a BriefAgent safe, and our language never says it does. Published versions are
          rescanned as detection improves, with advisories and quarantine when something new
          surfaces. Read the{" "}
          <Link href="/trust" className="underline">
            security model
          </Link>{" "}
          for the full picture.
        </p>
        <p>
          The framework is open source; the hosted service is built on top of it. This page is a
          placeholder for the company story, team, and mission. More soon.
        </p>
      </div>
    </div>
  );
}
