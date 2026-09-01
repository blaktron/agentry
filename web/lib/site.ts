// Central brand + external-site configuration for the Agentry web app.
//
// The product is "Agentry" — the same word as the CLI, the runner, and the
// `AGENTRY_` config prefix, so what people type is what they say. (It shipped
// briefly as "SecureAgentry"; that was retired 2026-09-01 for exactly this
// reason. The hosted domains kept their names.) Only user-visible copy is
// branded here.
//
// The docs and developers sites are SEPARATE deployments. Their URLs are
// configurable so the same web image runs in dev (pointing at local
// containers) and in production (docs.secureagentry.net / developers…).
export const BRAND = "Agentry";
export const TAGLINE =
  "A registry and git host for single-purpose AI agents, with mandatory pre-publication security scanning and signed provenance.";

// Production defaults; overridden per-deployment by env. Trailing slashes are
// trimmed so callers can concatenate paths safely.
const trim = (v: string) => v.replace(/\/$/, "");

export const SITE = {
  brand: BRAND,
  tagline: TAGLINE,
  // The public origin of THIS site (used for canonical links / copy).
  url: trim(process.env.AGENTRY_SITE_URL ?? "https://secureagentry.net"),
  // The separate wiki-style documentation site.
  docsUrl: trim(process.env.AGENTRY_DOCS_URL ?? "https://docs.secureagentry.net"),
  // The separate developers / API-reference site (OpenAPI, specs).
  developersUrl: trim(process.env.AGENTRY_DEVELOPERS_URL ?? "https://developers.secureagentry.net"),
  // Support / contact address surfaced on the contact page.
  contactEmail: process.env.AGENTRY_CONTACT_EMAIL ?? "hello@secureagentry.net",
  securityEmail: process.env.AGENTRY_SECURITY_EMAIL ?? "security@secureagentry.net",
  copyrightYear: 2026,
} as const;
