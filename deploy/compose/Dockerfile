# agentryd container image (self-host + hosted, every role). Non-root.
#
# ONE image for all four roles, and it contains git.
#
# The git role needs a git binary, and `agentryd all` (the self-host default,
# which mounts the git routes in-process) needs it too. A separate image for
# the git role would leave `all` without git, or require the `all` deployment
# to pull the "git" image, which is a naming trap; it would also mean two tags
# per commit to keep in step, two signatures, and two SBOMs.
#
# The cost is the base: git needs a real userland, so distroless/static is out.
# debian-slim keeps the same Debian lineage the distroless images track, gets
# security updates, and ships git with its helpers intact rather than a binary
# hand-copied out of a builder and missing half its shared libraries.

# The builder is go.mod's Go, to the patch: a floating golang:1.27 is whatever
# the host cached, and with the image's GOTOOLCHAIN=local a stale one either
# refuses a newer go line or builds with the older Go. CI fails
# when this tag and go.mod's go line differ, so a bump moves both.
FROM golang:1.27.3 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/blaktron/agentry/internal/version.Version=${VERSION}" \
      -o /out/agentryd ./cmd/agentryd

# gitleaks (the S2 external tool): a static binary lifted from
# the upstream image, pinned by digest. The server execs it only when
# AGENTRY_SCAN_GITLEAKS_BIN points at it (compose does; see docker-compose).
FROM ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f AS gitleaks

FROM debian:trixie-slim
# git: required by the git and all roles (bare-repo hosting).
# ca-certificates: outbound TLS — OIDC discovery, webhook delivery, S3, KMS.
RUN apt-get update \
 && apt-get install --no-install-recommends -y git ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --gid 65532 nonroot \
 && useradd --uid 65532 --gid 65532 --home-dir /home/nonroot --create-home nonroot \
 # /data/git (bare repos) and /data/storage (local blob store fallback) exist
 # in the image owned by nonroot so a fresh named volume mounted there
 # inherits that ownership — a volume materialized at an absent path is
 # root-owned and uid 65532 could never init a repo into it.
 && install -d -o 65532 -g 65532 /data/git /data/storage

COPY --from=build /out/agentryd /usr/bin/agentryd
# The golden attack corpus rides along for the red-team job;
# report-only, read by a worker, never by the publish path.
COPY --from=build /src/testdata/attack-corpus /srv/agentry/attack-corpus
COPY --from=gitleaks /usr/bin/gitleaks /usr/bin/gitleaks

# The licences the binaries above are redistributed under. The Go modules'
# texts and NOTICE files are generated into THIRD_PARTY_NOTICES (scripts/notices;
# `make notices-check` fails when it is stale). The upstream gitleaks image
# carries no licence file, so its MIT text is fetched at the tag of the image
# above and verified against its checksum.
COPY THIRD_PARTY_NOTICES /usr/share/licenses/agentryd/THIRD_PARTY_NOTICES
ADD --chmod=0644 --checksum=sha256:e3884b252b3bfc045e55be43a34d1e80da070bc6f804ac95bf4660e97d62ebc6 \
    https://raw.githubusercontent.com/gitleaks/gitleaks/v8.30.1/LICENSE /usr/share/licenses/gitleaks/LICENSE

# uid 65532 matches the helm chart's podSecurityContext.runAsUser and the
# distroless "nonroot" convention the rest of the deployment assumes.
USER 65532:65532
ENTRYPOINT ["/usr/bin/agentryd"]
CMD ["all"]
