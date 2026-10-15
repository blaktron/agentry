// Baseline: resolve + download, 500 rps sustained.
//
// The pair is measured together because that is the shape of a real install:
// the CLI resolves `ns/name@range` to a version, then follows the download
// redirect. Measuring resolve alone would flatter the system by leaving out
// the redirect handoff.
//
//   BASE_URL=https://staging.agentry.invalid k6 run scripts/perf/resolve-download.js
//
// Not run by CI (see README.md) — staging only.
import http from "k6/http";
import { check } from "k6";
import { Trend } from "k6/metrics";

const BASE_URL = __ENV.BASE_URL || "http://localhost:8080";
const RATE = Number(__ENV.RATE || 500); // target
const DURATION = __ENV.DURATION || "5m";
const SEED_PREFIX = __ENV.SEED_PREFIX || "seed";
const SEED_COUNT = Number(__ENV.SEED_COUNT || 10000);
const SEED_NAMESPACES = Number(__ENV.SEED_NAMESPACES || 200);

const resolveTrend = new Trend("resolve_duration", true);
const downloadTrend = new Trend("download_redirect_duration", true);

export const options = {
  scenarios: {
    resolve_download: {
      executor: "constant-arrival-rate",
      rate: RATE,
      timeUnit: "1s",
      duration: DURATION,
      // Headroom so the scenario reports "insufficient VUs" rather than
      // silently degrading the arrival rate when the system slows down.
      preAllocatedVUs: Math.ceil(RATE / 4),
      maxVUs: RATE * 2,
    },
  },
  thresholds: {
    // The baseline itself. A run that misses these exits non-zero.
    http_req_failed: ["rate<0.001"],
    resolve_duration: ["p(95)<300"],
    download_redirect_duration: ["p(95)<300"],
    dropped_iterations: ["count<1"],
  },
};

// pickAgent reproduces a seedgen name deterministically enough to address it.
// The seed corpus is generated with a fixed PRNG, so the middle word varies;
// resolve takes ns/name, and the listing endpoint is how we discover both
// without embedding generator internals here.
const NOUNS = ["incident", "changelog", "invoice", "schema", "release", "dependency",
  "ticket", "runbook", "dashboard", "migration", "digest", "review",
  "transcript", "roadmap", "postmortem", "contract", "inventory"];
const VERBS = ["summarizer", "auditor", "linter", "reporter", "planner", "triager",
  "formatter", "explainer", "reviewer", "tracker", "generator"];

function randomAgentRef() {
  const idx = Math.floor(Math.random() * SEED_COUNT);
  const ns = `${SEED_PREFIX}-pub-${String(idx % SEED_NAMESPACES).padStart(4, "0")}`;
  const noun = NOUNS[Math.floor(Math.random() * NOUNS.length)];
  const verb = VERBS[Math.floor(Math.random() * VERBS.length)];
  const name = `${SEED_PREFIX}-${noun}-${verb}-${String(idx).padStart(5, "0")}`;
  return { ns, name };
}

// setup discovers real refs from the listing endpoint. Guessing names would
// measure the 404 path, which is fast and meaningless.
export function setup() {
  const res = http.get(`${BASE_URL}/api/v1/agents?limit=100`);
  if (res.status !== 200) {
    throw new Error(`listing failed: ${res.status} — is the seed dataset loaded?`);
  }
  const body = res.json();
  const items = (body && (body.items || body)) || [];
  const refs = items
    .filter((a) => a && a.name && a.namespace)
    .map((a) => ({ ns: a.namespace, name: a.name }));
  if (refs.length === 0) {
    throw new Error("no agents returned — run scripts/seed first");
  }
  return { refs };
}

export default function (data) {
  const refs = (data && data.refs) || [];
  const ref = refs.length ? refs[Math.floor(Math.random() * refs.length)] : randomAgentRef();

  const resolve = http.get(
    `${BASE_URL}/api/v1/resolve?ref=${encodeURIComponent(`${ref.ns}/${ref.name}`)}`,
    { tags: { endpoint: "resolve" } },
  );
  resolveTrend.add(resolve.timings.duration);
  const resolved = check(resolve, {
    "resolve 200": (r) => r.status === 200,
    "resolve returns a version": (r) => !!(r.json() || {}).version,
  });
  if (!resolved) return;

  const version = resolve.json().version;
  // redirects: 0 — the 302 to the CDN is the registry's work; following it
  // would measure the CDN instead.
  const download = http.get(
    `${BASE_URL}/api/v1/agents/${ref.ns}/${ref.name}/versions/${version}/download`,
    { redirects: 0, tags: { endpoint: "download" } },
  );
  downloadTrend.add(download.timings.duration);
  check(download, {
    "download redirects or streams": (r) => r.status === 302 || r.status === 200,
  });
}
