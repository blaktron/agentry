import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { apiGet, type TagPage as TagPageResult } from "@/lib/api";
import { AgentRow, Card } from "@/components/ui";

type Params = { tag: string };

// The tag pattern the API accepts (schemas/openapi.yaml). Checked here too so
// a junk path is a 404 page rather than a round trip and a problem document.
const TAG_RE = /^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$/;

export async function generateMetadata({ params }: { params: Promise<Params> }): Promise<Metadata> {
  const { tag } = await params;
  return { title: `#${tag}`, description: `Public BriefAgents tagged ${tag} on Agentry.` };
}

// Tag listing (§9.2): the agents whose latest published manifest carries this
// tag. Cursor-paged: the API returns nextCursor (and a Link header) rather
// than an offset, so "more" is a link, never a page number.
export default async function TagPage({
  params,
  searchParams,
}: {
  params: Promise<Params>;
  searchParams: Promise<{ cursor?: string }>;
}) {
  const { tag } = await params;
  if (!TAG_RE.test(tag)) notFound();
  const { cursor } = await searchParams;

  const query = new URLSearchParams({ limit: "50" });
  if (cursor) query.set("cursor", cursor);
  const page = await apiGet<TagPageResult>(
    `/tags/${encodeURIComponent(tag)}?${query.toString()}`,
    { revalidate: 30 },
  );
  if (!page) notFound();

  const results = page.results ?? [];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">#{page.tag}</h1>
        <p className="mt-1 text-sm" style={{ color: "var(--color-muted)" }}>
          Public BriefAgents whose latest published manifest declares this tag. Blocked BriefAgents never
          appear here.
        </p>
      </div>

      {results.length === 0 ? (
        <Card>
          <p className="text-sm">
            {cursor ? "No further BriefAgents on this page." : `No public BriefAgents are tagged #${page.tag}.`}
          </p>
        </Card>
      ) : (
        <ul>
          {results.map((hit) => (
            <AgentRow
              key={`${hit.namespace}/${hit.name}`}
              namespace={hit.namespace}
              name={hit.name}
              summary={hit.summary}
              modes={hit.modes}
            />
          ))}
        </ul>
      )}

      <div className="flex gap-4 text-sm">
        {page.nextCursor && (
          <Link
            href={`/tags/${encodeURIComponent(page.tag)}?cursor=${encodeURIComponent(page.nextCursor)}`}
            className="underline"
          >
            More BriefAgents →
          </Link>
        )}
        <Link href="/search" className="underline" style={{ color: "var(--color-muted)" }}>
          Browse everything
        </Link>
      </div>
    </div>
  );
}
