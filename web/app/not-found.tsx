import Link from "next/link";

export default function NotFound() {
  return (
    <div className="max-w-xl space-y-4">
      <h1 className="text-2xl font-semibold tracking-tight">Not found</h1>
      <p style={{ color: "var(--color-muted)" }}>
        That page does not exist, or the agent is private and you are not signed in with access to it.
      </p>
      <p>
        <Link href="/search" className="underline" style={{ color: "var(--color-accent)" }}>
          Browse public agents
        </Link>
      </p>
    </div>
  );
}
