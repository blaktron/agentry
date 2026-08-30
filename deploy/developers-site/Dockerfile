# SecureAgentry developers site (developers.secureagentry.net) — a SEPARATE
# deployment hosting the API reference and the OpenAPI specification. Redoc
# renders the spec as a full API reference; the raw file stays downloadable at
# /openapi.yaml. The Redoc bundle is served from the same origin (no CDN), so
# this works offline and under a strict CSP. Build context is the repo root.
FROM redocly/redoc:latest
# The spec is served from this origin; SPEC_URL is therefore a relative path.
COPY schemas/openapi.yaml /usr/share/nginx/html/openapi.yaml
ENV SPEC_URL=openapi.yaml
ENV PAGE_TITLE="SecureAgentry API Reference"
EXPOSE 80
