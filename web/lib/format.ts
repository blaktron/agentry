// Presentation helpers with no server dependency (so the unit tests can
// import them directly).

function pad(n: number): string {
  return String(n).padStart(2, "0");
}

// fmtUTC renders an ISO-8601 instant in UTC with the zone spelled out.
//
// These pages are server-rendered, so `toLocaleString()` formats in the
// SERVER's locale and timezone and then ships that string to every reader —
// an audit row that says "8/29/2026, 6:21:55 PM" is ambiguous to everyone
// who is not sitting in the datacentre. Audit logs, scan dates and publish
// times are evidence; they get one unambiguous rendering.
export function fmtUTC(iso?: string | null): string {
  if (!iso) return "none";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return (
    `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ` +
    `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())} UTC`
  );
}

// fmtUTCDate is fmtUTC without the clock, for places where the day is the
// whole of the information (token last-used, claim dates).
export function fmtUTCDate(iso?: string | null): string {
  if (!iso) return "none";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} UTC`;
}

// fmtCount renders a counter compactly (12, 1.2k, 3.4M) for stat panels.
export function fmtCount(n?: number): string {
  if (n === undefined || n === null || Number.isNaN(n)) return "0";
  if (n < 1000) return String(n);
  if (n < 1_000_000) return `${(n / 1000).toFixed(n < 10_000 ? 1 : 0)}k`;
  return `${(n / 1_000_000).toFixed(1)}M`;
}

// fmtBytes renders a byte count compactly for file listings (B, kB, MB).
// Decimal units on purpose: these are archive sizes, not memory.
export function fmtBytes(n?: number): string {
  if (n === undefined || n === null || Number.isNaN(n) || n < 0) return "none";
  if (n < 1000) return `${n} B`;
  if (n < 1_000_000) return `${(n / 1000).toFixed(1)} kB`;
  return `${(n / 1_000_000).toFixed(1)} MB`;
}
