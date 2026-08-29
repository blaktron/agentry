/** @type {import('next').NextConfig} */

// Agentry web app (§10). Public pages are server-rendered (SSR) for SEO
// (D-08).
//
// AGENTRY_API_BASE is deliberately NOT declared in `env` below: values there
// are inlined at build time, which would freeze the API address into the
// image. lib/api.ts reads process.env at request time instead, so one image
// runs in dev, staging, and prod.
//
// The Content-Security-Policy is NOT here. It carries a per-request script
// nonce and therefore lives in proxy.ts — see the comment there. Everything
// below is static by nature and applies to every path, including the asset
// routes proxy.ts skips.

const nextConfig = {
  // standalone output keeps Dockerfile.web to the traced server bundle
  // instead of the full node_modules tree.
  output: "standalone",
  reactStrictMode: true,
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
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
