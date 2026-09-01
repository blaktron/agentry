import Link from "next/link";
import type { Metadata } from "next";
import { apiGet, type AgentKind, type SearchResults } from "@/lib/api";
import { AgentRow, Card } from "@/components/ui";
import { BrowsePane } from "@/components/browse-pane";

export const metadata: Metadata = { title: "Browse BriefAgents" };

const KINDS: AgentKind[] = ["skill", "prompt-agent", "mcp-server"];

// §5.4 capability groups, which is what `capability=` filters on. A
// capability declared as `none`/null/empty does not match (DEV-021): the
// filter answers "asks for this", not "mentions this".
const CAPABILITIES = ["network", "filesystem", "exec", "secrets", "dataAccess"];

const SORTS = [
  { id: "relevance", label: "best match" },
  { id: "installs", label: "most installed" },
  { id: "newest", label: "newest" },
];

function inputStyle() {
  return { borderColor: "var(--color-border)", background: "var(--color-surface)" } as const;
}

// Search / browse (§10.1, §10.4). A plain GET form with no client JS, so the
// page works with a strict CSP and is crawlable (D-08).
export default async function SearchPage({
  searchParams,
}: {
  searchParams: Promise<{
    q?: string;
    kind?: string;
    capability?: string;
    license?: string;
    verified?: string;
    sort?: string;
    selected?: string;
  }>;
}) {
  const sp = await searchParams;
  // The detail pane's subject: "ns/name", validated to the manifest's own
  // identifier shape so the value can never be anything but a lookup key.
  const selMatch = /^([a-z0-9][a-z0-9-]*)\/([a-z0-9][a-z0-9-]*)$/.exec((sp.selected ?? "").trim());
  const selected = selMatch ? { namespace: selMatch[1], name: selMatch[2] } : null;
  const q = (sp.q ?? "").trim();
  const kind = KINDS.includes(sp.kind as AgentKind) ? (sp.kind as AgentKind) : undefined;
  const capability = CAPABILITIES.includes(sp.capability ?? "") ? sp.capability : undefined;
  const license = (sp.license ?? "").trim().slice(0, 64);
  const verified = sp.verified === "1";
  const sort = SORTS.some((s) => s.id === sp.sort) ? sp.sort! : "relevance";

  const params = new URLSearchParams();
  if (q) params.set("q", q);
  if (kind) params.set("kind", kind);
  if (capability) params.set("capability", capability);
  if (license) params.set("license", license);
  if (verified) params.set("verified", "true");
  if (sort !== "relevance") params.set("sort", sort);
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
  // License facet counts come back from the same query; they are the honest
  // way to offer the filter, since the set of licences in a registry is
  // whatever has actually been published to it.
  const licenseFacets = Object.entries(data?.facets?.license ?? {}).sort((a, b) => b[1] - a[1]);
  const filtered = Boolean(q || kind || capability || license || verified);

  // Row links point back at this page with the same filters plus
  // `selected`; the close link is the same URL without it.
  const listParams = new URLSearchParams();
  if (q) listParams.set("q", q);
  if (kind) listParams.set("kind", kind);
  if (capability) listParams.set("capability", capability);
  if (license) listParams.set("license", license);
  if (verified) listParams.set("verified", "1");
  if (sort !== "relevance") listParams.set("sort", sort);
  const hrefFor = (sel: string | null) => {
    const p = new URLSearchParams(listParams);
    if (sel) p.set("selected", sel);
    const qs = p.toString();
    return qs ? `/search?${qs}` : "/search";
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Browse BriefAgents</h1>
        <p className="mt-1 text-sm" style={{ color: "var(--color-muted)" }}>
          Every listed version has been scanned and signed. Open a BriefAgent to read its security report
          before installing.
        </p>
      </div>

      <form action="/search" className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-3">
          <input
            type="search"
            name="q"
            defaultValue={q}
            placeholder="Search names, summaries, and READMEs…"
            aria-label="Search query"
            className="min-w-64 flex-1 rounded-md border px-3 py-2 text-sm"
            style={inputStyle()}
          />
          <button
            type="submit"
            className="rounded-md px-4 py-2 text-sm font-medium"
            style={{ background: "var(--color-accent)", color: "var(--color-accent-fg)" }}
          >
            Search
          </button>
        </div>
        <div className="flex flex-wrap items-center gap-4 text-sm" style={{ color: "var(--color-muted)" }}>
          <label>
            <span className="mr-2">Kind</span>
            <select name="kind" defaultValue={kind ?? ""} className="rounded-md border px-2 py-1.5 text-sm" style={inputStyle()}>
              <option value="">any</option>
              {KINDS.map((k) => (
                <option key={k} value={k}>
                  {k}
                  {kindFacets[k] !== undefined ? ` (${kindFacets[k]})` : ""}
                </option>
              ))}
            </select>
          </label>
          <label>
            <span className="mr-2">Capability</span>
            <select
              name="capability"
              defaultValue={capability ?? ""}
              className="rounded-md border px-2 py-1.5 text-sm"
              style={inputStyle()}
            >
              <option value="">any</option>
              {CAPABILITIES.map((c) => (
                <option key={c} value={c}>
                  asks for {c}
                </option>
              ))}
            </select>
          </label>
          <label>
            <span className="mr-2">License</span>
            <select name="license" defaultValue={license} className="rounded-md border px-2 py-1.5 text-sm" style={inputStyle()}>
              <option value="">any</option>
              {licenseFacets.map(([id, count]) => (
                <option key={id} value={id}>
                  {id} ({count})
                </option>
              ))}
              {license && !licenseFacets.some(([id]) => id === license) && (
                <option value={license}>{license}</option>
              )}
            </select>
          </label>
          <label>
            <span className="mr-2">Sort</span>
            <select name="sort" defaultValue={sort} className="rounded-md border px-2 py-1.5 text-sm" style={inputStyle()}>
              {SORTS.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.label}
                </option>
              ))}
            </select>
          </label>
          <label className="flex items-center gap-2">
            <input type="checkbox" name="verified" value="1" defaultChecked={verified} />
            <span title="Only BriefAgents in an organization namespace whose domain has been verified by DNS.">
              verified organizations only
            </span>
          </label>
        </div>
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
            {filtered
              ? `No public BriefAgents match${q ? ` “${q}”` : ""} with these filters.`
              : "No public BriefAgents have been published yet."}
          </p>
          {filtered && (
            <p className="mt-1 text-sm">
              <Link href="/search" className="underline">
                Clear the filters
              </Link>
            </p>
          )}
        </Card>
      )}

      {results.length > 0 && (
        <div className={selected ? "grid gap-6 lg:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]" : ""}>
          <div>
            <p className="text-sm" style={{ color: "var(--color-muted)" }}>
              {data?.total !== undefined && data.total > results.length
                ? `${results.length} of ${data.total} results`
                : `${results.length} result${results.length === 1 ? "" : "s"}`}
              {q ? ` for “${q}”` : ""}
              {!selected && (
                <span className="ml-2 hidden lg:inline">· select one to see its report and install it</span>
              )}
            </p>
            <ul>
              {results.map((hit) => (
                <AgentRow
                  key={`${hit.namespace}/${hit.name}`}
                  namespace={hit.namespace}
                  name={hit.name}
                  summary={hit.summary}
                  kind={hit.kind}
                  href={hrefFor(`${hit.namespace}/${hit.name}`)}
                  selected={selected?.namespace === hit.namespace && selected?.name === hit.name}
                />
              ))}
            </ul>
          </div>
          {selected && (
            // First in reading order on small screens (it is what was just
            // asked for); beside the list, sticky, from lg up.
            <aside className="order-first lg:order-none lg:sticky lg:top-4 lg:self-start" aria-label="Selected BriefAgent">
              <BrowsePane namespace={selected.namespace} name={selected.name} closeHref={hrefFor(null)} />
            </aside>
          )}
        </div>
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
