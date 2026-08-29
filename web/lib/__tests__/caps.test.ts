import { describe, expect, it } from "vitest";
import { diffCaps } from "../caps";

// The capability diff is what a reviewer reads to answer "what new power is
// this version asking for" (§8.4). The failure that matters is an added or
// widened capability rendering as unchanged, so that is what these pin.

function row(rows: ReturnType<typeof diffCaps>, key: string) {
  const r = rows.find((x) => x.key === key);
  expect(r, `expected a row for ${key}`).toBeDefined();
  return r!;
}

describe("diffCaps", () => {
  it("marks a newly declared capability as added", () => {
    const rows = diffCaps({}, { network: { egress: ["api.example.com"] } });
    expect(row(rows, "network.egress").change).toBe("added");
    expect(row(rows, "network.egress").before).toBeUndefined();
    expect(row(rows, "network.egress").after).toBe('["api.example.com"]');
  });

  it("marks a widened egress list as changed, not same", () => {
    const rows = diffCaps(
      { network: { egress: ["api.example.com"] } },
      { network: { egress: ["api.example.com", "evil.example"] } },
    );
    expect(row(rows, "network.egress").change).toBe("changed");
  });

  it("treats an array as one leaf so reordering is still a change", () => {
    const rows = diffCaps({ network: { egress: ["a", "b"] } }, { network: { egress: ["b", "a"] } });
    expect(rows).toHaveLength(1);
    expect(rows[0].key).toBe("network.egress");
    expect(rows[0].change).toBe("changed");
  });

  it("marks a dropped capability as removed", () => {
    const rows = diffCaps({ exec: { commands: ["git"] } }, {});
    expect(row(rows, "exec.commands").change).toBe("removed");
    expect(row(rows, "exec.commands").after).toBeUndefined();
  });

  it("marks identical declarations as same", () => {
    const caps = { filesystem: { read: { paths: ["./data"] } }, secrets: ["TOKEN"] };
    const rows = diffCaps(caps, structuredClone(caps));
    expect(rows.every((r) => r.change === "same")).toBe(true);
  });

  it("reports every leaf of a nested object, sorted by key", () => {
    const rows = diffCaps(undefined, {
      network: { egress: ["h"] },
      exec: { commands: ["sh"] },
      secrets: ["A"],
    });
    expect(rows.map((r) => r.key)).toEqual(["exec.commands", "network.egress", "secrets"]);
    expect(rows.every((r) => r.change === "added")).toBe(true);
  });

  it("distinguishes an explicit none from an absent capability", () => {
    // `network: {egress: "none"}` is a declaration that says "no network".
    // Dropping the key entirely is a different statement, and the diff must
    // not flatten the two into each other.
    const rows = diffCaps({ network: { egress: "none" } }, {});
    expect(row(rows, "network.egress").change).toBe("removed");
    expect(row(rows, "network.egress").before).toBe('"none"');
  });

  it("treats undefined and empty capabilities as no rows at all", () => {
    expect(diffCaps(undefined, undefined)).toEqual([]);
    expect(diffCaps({}, {})).toEqual([]);
  });

  it("does not lose a leaf whose value is null", () => {
    // capLeaves skips null, so a null-valued key on one side must still show
    // up as a difference from a real value on the other.
    const rows = diffCaps({ exec: null }, { exec: { commands: ["sh"] } });
    expect(row(rows, "exec.commands").change).toBe("added");
  });
});
