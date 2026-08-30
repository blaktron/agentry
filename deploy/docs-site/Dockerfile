# SecureAgentry docs site: build the Markdown docs into a static MkDocs
# Material site, then serve them with nginx. Separate deployment from the web
# app and the API. Build context is the repository root.
#
#   docker build -f deploy/docs-site/Dockerfile --build-arg SITE_URL=… .
FROM python:3.12-slim AS build
WORKDIR /build
RUN pip install --no-cache-dir "mkdocs-material==9.5.44"
# SITE_URL is baked into canonical links / sitemap at build time; configurable.
ARG SITE_URL=https://docs.secureagentry.net
ENV SITE_URL=${SITE_URL}
COPY docs/ ./docs/
COPY deploy/docs-site/mkdocs.yml ./mkdocs.yml
RUN mkdocs build --strict --site-dir /site

FROM nginx:1.27-alpine
COPY --from=build /site /usr/share/nginx/html
# The docs are fully static; nginx defaults serve them fine on :80.
EXPOSE 80
