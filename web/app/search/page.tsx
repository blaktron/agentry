import Link from "next/link";
import type { Metadata } from "next";
import { apiGet, type AgentKind } from "@/lib/api";
import { AgentRow, Card } from "@/components/ui";

export const metadata: Metadata = { title: "Browse agents" };

interface SearchHit {
  namespace: string;
  name: string;
  kind: AgentKind;
  summary: string;
  installs30d?: number;
  quarantineState?: string;
}

interface SearchResults {
  results: SearchHit[];
  facets?: Record<string, Record<string, number>>;
}

const KINDS: AgentKind[] = ["skill", "prompt-agent", "mcp-server"];

// Search / browse (§10.1, §10.4). A plain GET form — no client JS — so the
// page works with a strict CSP and is crawlable (D-08).
export default async function SearchPage({
  searchParams,
}: {
  searchParams: Promise<{ q?: string; kind?: string }>;
}) {
  const sp = await searchParams;
  const q = (sp.q ?? "").trim();
  const kind = KINDS.includes(sp.kind as AgentKind) ? (sp.kind as AgentKind) : undefined;

  const params = new URLSearchParams();
  if (q) params.set("q", q);
  if (kind) params.set("kind", kind);
  params.set("limit", "50");

  let data: SearchResults | null = null;
  let error: string | null = null;
  try {
    data = await apiGet<SearchResults>(`/search?${params.toString()}`, { revalidate: 15 });
  } catch (e) {
    error = e instanceof Error ? e.message : "search unavailable";
  }

  const results = data?.results ?? [];
  const kindFacets = data?.facets?.kind ?? {};

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Browse agents</h1>
        <p className="mt-1 text-sm" style={{ color: "var(--color-muted)" }}>
          Every listed version has been scanned and signed. Open an agent to read its security report
          before installing.
        </p>
      </div>

      <form action="/search" className="flex flex-wrap items-center gap-3">
        <input
          type="search"
          name="q"
          defaultValue={q}
          placeholder="Search names, summaries, and READMEs…"
          aria-label="Search query"
          className="min-w-64 flex-1 rounded-md border px-3 py-2 text-sm"
          style={{ borderColor: "var(--color-border)", background: "var(--color-surface)" }}
        />
        <label className="text-sm" style={{ color: "var(--color-muted)" }}>
          <span className="mr-2">Kind</span>
          <select
            name="kind"
            defaultValue={kind ?? ""}
            className="rounded-md border px-2 py-2 text-sm"
            style={{ borderColor: "var(--color-border)", background: "var(--color-surface)" }}
          >
            <option value="">any</option>
            {KINDS.map((k) => (
              <option key={k} value={k}>
                {k}
                {kindFacets[k] !== undefined ? ` (${kindFacets[k]})` : ""}
              </option>
            ))}
          </select>
        </label>
        <button
          type="submit"
          className="rounded-md px-4 py-2 text-sm font-medium"
          style={{ background: "var(--color-accent)", color: "var(--color-accent-fg)" }}
        >
          Search
        </button>
      </form>

      {error && (
        <Card>
          <p className="text-sm">The registry search API is unavailable right now.</p>
          <p className="mt-1 text-xs" style={{ color: "var(--color-muted)" }}>
            {error}
          </p>
        </Card>
      )}

      {!error && results.length === 0 && (
        <Card>
          <p className="text-sm">
            {q ? `No public agents match “${q}”.` : "No public agents have been published yet."}
          </p>
        </Card>
      )}

      {results.length > 0 && (
        <>
          <p className="text-sm" style={{ color: "var(--color-muted)" }}>
            {results.length} result{results.length === 1 ? "" : "s"}
            {q ? ` for “${q}”` : ""}
          </p>
          <ul>
            {results.map((hit) => (
              <AgentRow
                key={`${hit.namespace}/${hit.name}`}
                namespace={hit.namespace}
                name={hit.name}
                summary={hit.summary}
                kind={hit.kind}
              />
            ))}
          </ul>
        </>
      )}

      <p className="text-sm" style={{ color: "var(--color-muted)" }}>
        Looking for the API? See the{" "}
        <Link href="/docs" className="underline">
          docs
        </Link>
        .
      </p>
    </div>
  );
}
