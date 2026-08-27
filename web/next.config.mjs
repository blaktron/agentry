/** @type {import('next').NextConfig} */

// Agentry web app (§10). Public pages are server-rendered (SSR) for SEO
// (D-08). CSP per §10.3: no inline script.
//
// AGENTRY_API_BASE is deliberately NOT declared in `env` below: values there
// are inlined at build time, which would freeze the API address into the
// image. lib/api.ts reads process.env at request time instead, so one image
// runs in dev, staging, and prod.

const csp = [
  "default-src 'self'",
  "script-src 'self'",
  // Tailwind v4 injects a style tag; allow self + nonce-less styles are
  // avoided by using a stylesheet. 'unsafe-inline' for styles only is the
  // documented §10.3 compromise (no inline SCRIPT, which is the XSS vector).
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
].join("; ");

const nextConfig = {
  reactStrictMode: true,
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "Content-Security-Policy", value: csp },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "no-referrer" },
          { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
        ],
      },
    ];
  },
};

export default nextConfig;
