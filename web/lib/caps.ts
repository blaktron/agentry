// Capability-contract diffing for the reviewer surface (§10.1, §8.4).
//
// Extracted from app/review/[id]/page.tsx so it can be unit-tested: this is
// the panel a reviewer reads to answer "what new power is this version
// asking for", and an added-capability row that silently renders as "same"
// is the failure mode that matters.

export type CapChange = "added" | "removed" | "changed" | "same";

export interface CapDiffRow {
  key: string;
  before?: string;
  after?: string;
  change: CapChange;
}

// capLeaves flattens a capability object to dotted-path leaves. Arrays are
// leaves, not containers: `egress: ["a","b"]` reads better as one row than
// as two rows whose keys are array indices.
export function capLeaves(v: unknown, prefix: string, out: Map<string, string>) {
  if (v === null || v === undefined) return;
  if (typeof v !== "object" || Array.isArray(v)) {
    out.set(prefix, JSON.stringify(v));
    return;
  }
  for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
    capLeaves(val, prefix ? `${prefix}.${k}` : k, out);
  }
}

// diffCaps flattens two capability objects and marks each leaf.
export function diffCaps(
  prev: Record<string, unknown> | undefined,
  curr: Record<string, unknown> | undefined,
): CapDiffRow[] {
  const a = new Map<string, string>();
  const b = new Map<string, string>();
  capLeaves(prev ?? {}, "", a);
  capLeaves(curr ?? {}, "", b);
  const keys = [...new Set([...a.keys(), ...b.keys()])].sort();
  return keys.map((k) => ({
    key: k,
    before: a.get(k),
    after: b.get(k),
    change: !a.has(k) ? "added" : !b.has(k) ? "removed" : a.get(k) !== b.get(k) ? "changed" : "same",
  }));
}

// egressHosts flattens the manifest's egress union — `none`, `"*"`, or a
// list of hosts — into the host list a badge can show: `none` and an
// absent block are no hosts; `"*"` is the single wildcard entry.
export function egressHosts(value: unknown): string[] {
  if (Array.isArray(value)) return value.filter((h): h is string => typeof h === "string" && h !== "" && h !== "none");
  if (typeof value === "string" && value !== "" && value !== "none") return [value];
  return [];
}
