// §17.6 baseline: search p95 < 300 ms at the 10k-agent seed dataset.
//
//   BASE_URL=https://staging.agentry.invalid k6 run scripts/perf/search.js
//
// Not run by CI (see README.md) — staging only.
import http from "k6/http";
import { check } from "k6";
import { Trend } from "k6/metrics";

const BASE_URL = __ENV.BASE_URL || "http://localhost:8080";
const VUS = Number(__ENV.VUS || 50);
const DURATION = __ENV.DURATION || "3m";

const searchTrend = new Trend("search_duration", true);
const facetTrend = new Trend("search_faceted_duration", true);

export const options = {
  scenarios: {
    search: { executor: "constant-vus", vus: VUS, duration: DURATION },
  },
  thresholds: {
    http_req_failed: ["rate<0.001"],
    // The §17.6 number. Faceted search gets the same budget: a facet that
    // costs 3x is a facet nobody will use.
    search_duration: ["p(95)<300"],
    search_faceted_duration: ["p(95)<300"],
  },
};

// Query mix: single common terms, two-term queries, a rare term, a prefix
// fragment for the trigram fallback, and an empty query (the browse path).
// A benchmark that only sends one query measures one query plan.
const TERMS = ["incident", "changelog", "invoice", "schema", "release",
  "dependency", "runbook", "dashboard", "migration", "digest", "postmortem"];
const MODIFIERS = ["summarizer", "auditor", "linter", "reporter", "triager"];
const FACETS = [
  "kind=skill",
  "kind=mcp-server",
  "capability=network",
  "license=Apache-2.0",
  "sort=installs",
  "verified=true",
];

function pick(xs) {
  return xs[Math.floor(Math.random() * xs.length)];
}

function query() {
  switch (Math.floor(Math.random() * 5)) {
    case 0:
      return pick(TERMS);
    case 1:
      return `${pick(TERMS)} ${pick(MODIFIERS)}`;
    case 2:
      return pick(TERMS).slice(0, 4); // trigram fallback path
    case 3:
      return "zzzznotarealterm"; // empty result set
    default:
      return ""; // browse
  }
}

export default function () {
  const q = encodeURIComponent(query());

  const plain = http.get(`${BASE_URL}/api/v1/search?q=${q}`, { tags: { mode: "plain" } });
  searchTrend.add(plain.timings.duration);
  check(plain, { "search 200": (r) => r.status === 200 });

  const faceted = http.get(`${BASE_URL}/api/v1/search?q=${q}&${pick(FACETS)}`, {
    tags: { mode: "faceted" },
  });
  facetTrend.add(faceted.timings.duration);
  check(faceted, { "faceted search 200": (r) => r.status === 200 });
}
