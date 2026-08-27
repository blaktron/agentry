import { notFound } from "next/navigation";
import type { Metadata } from "next";
import { apiGet, type Agent } from "@/lib/api";
import { AgentRow, Card } from "@/components/ui";

type Params = { ns: string };

export async function generateMetadata({ params }: { params: Promise<Params> }): Promise<Metadata> {
  const { ns } = await params;
  return { title: ns };
}

// Namespace page (§10.1): the public agents owned by a user or org.
export default async function NamespacePage({ params }: { params: Promise<Params> }) {
  const { ns } = await params;

  const agents = await apiGet<Agent[]>(`/agents?namespace=${encodeURIComponent(ns)}`, {
    revalidate: 30,
  });
  if (agents === null) notFound();

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold tracking-tight">{ns}</h1>
      {agents.length === 0 ? (
        <Card>
          <p className="text-sm">This namespace has no public agents.</p>
        </Card>
      ) : (
        <ul>
          {agents.map((a) => (
            <AgentRow key={a.id} namespace={a.namespace} name={a.name} summary={a.summary} kind={a.kind} />
          ))}
        </ul>
      )}
    </div>
  );
}
