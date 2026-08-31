import { describe, expect, it } from "vitest";
import { fmtBytes, fmtCount, fmtUTC, fmtUTCDate } from "../format";

// These pages are server-rendered, so a locale-dependent formatter would
// stamp the SERVER's timezone onto a string every reader sees. Audit rows,
// scan dates and publish times are evidence; they get one rendering, and it
// says which zone it is in.
describe("fmtUTC", () => {
  it("renders in UTC regardless of the offset in the input", () => {
    expect(fmtUTC("2026-08-29T18:42:07Z")).toBe("2026-08-29 18:42 UTC");
    // Same instant, written with an offset: the output must not move.
    expect(fmtUTC("2026-08-29T14:42:07-04:00")).toBe("2026-08-29 18:42 UTC");
    expect(fmtUTC("2026-08-29T20:42:07+02:00")).toBe("2026-08-29 18:42 UTC");
  });

  it("pads every field to a fixed width so columns line up", () => {
    expect(fmtUTC("2026-01-02T03:04:05Z")).toBe("2026-01-02 03:04 UTC");
  });

  it("crosses the date line correctly rather than showing the local day", () => {
    expect(fmtUTC("2026-08-29T23:30:00-04:00")).toBe("2026-08-30 03:30 UTC");
  });

  it("shows a plain 'none' for a missing timestamp", () => {
    expect(fmtUTC(undefined)).toBe("none");
    expect(fmtUTC(null)).toBe("none");
    expect(fmtUTC("")).toBe("none");
  });

  it("passes an unparseable value through instead of printing Invalid Date", () => {
    expect(fmtUTC("not a date")).toBe("not a date");
  });

  it("fmtUTCDate drops the clock but keeps the zone label", () => {
    expect(fmtUTCDate("2026-08-29T23:30:00-04:00")).toBe("2026-08-30 UTC");
    expect(fmtUTCDate(undefined)).toBe("none");
  });
});

describe("fmtCount", () => {
  it("shows small counts exactly", () => {
    expect(fmtCount(0)).toBe("0");
    expect(fmtCount(1)).toBe("1");
    expect(fmtCount(999)).toBe("999");
  });

  it("abbreviates thousands and millions", () => {
    expect(fmtCount(1000)).toBe("1.0k");
    expect(fmtCount(1234)).toBe("1.2k");
    expect(fmtCount(12_345)).toBe("12k");
    expect(fmtCount(3_400_000)).toBe("3.4M");
  });

  it("treats missing counters as zero rather than blank", () => {
    expect(fmtCount(undefined)).toBe("0");
    expect(fmtCount(NaN)).toBe("0");
  });
});

describe("fmtBytes", () => {
  it("shows small sizes in bytes", () => {
    expect(fmtBytes(0)).toBe("0 B");
    expect(fmtBytes(999)).toBe("999 B");
  });

  it("abbreviates kB and MB with one decimal", () => {
    expect(fmtBytes(1000)).toBe("1.0 kB");
    expect(fmtBytes(12_345)).toBe("12.3 kB");
    expect(fmtBytes(3_400_000)).toBe("3.4 MB");
  });

  it("treats missing and negative sizes as 'none'", () => {
    expect(fmtBytes(undefined)).toBe("none");
    expect(fmtBytes(-1)).toBe("none");
    expect(fmtBytes(NaN)).toBe("none");
  });
});
