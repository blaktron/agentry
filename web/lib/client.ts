// Typed API client over the generated OpenAPI schema (M0). The Next.js app
// (M5) and smoke tests share this module.
import createClient from "openapi-fetch";
import type { paths } from "./api/schema.d.ts";

export function apiClient(baseUrl: string) {
  return createClient<paths>({ baseUrl });
}
