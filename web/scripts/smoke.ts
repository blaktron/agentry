// M0 acceptance: hit the live API through the generated TS client.
// Usage: AGENTRY_BASE_URL=http://localhost:8080 node scripts/smoke.ts
import { apiClient } from "../lib/client.ts";

const base = process.env.AGENTRY_BASE_URL ?? "http://localhost:8080";
const client = apiClient(base + "/api/v1");

const { data, error, response } = await client.GET("/meta");
if (error !== undefined || data === undefined) {
  console.error("TS smoke FAILED:", response.status, error);
  process.exit(1);
}
if (!data.version || data.apiVersion !== "v1") {
  console.error("TS smoke FAILED: unexpected meta payload", data);
  process.exit(1);
}
console.log(`TS smoke OK: agentryd ${data.version} api ${data.apiVersion} features ${JSON.stringify(data.features)}`);
