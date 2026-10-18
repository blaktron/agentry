# Self-hosting Agentry

The whole registry is open source: the scanners, the review queue, SSO and
SCIM, signing with your own key, and the server's own browser pages. There
is no "community edition" with the security features removed; a registry you
cannot audit is one you have to take on faith. What is *not* in this
repository is SecureAgentry's site — a closed front end that runs in
front of this same server; a registry does not need one, and
[the last section](#fronting-it-with-a-site) says how one plugs in.

**Target: a working private registry in under 15 minutes.**

## What you need

- PostgreSQL 16 (the only hard dependency)
- Somewhere to put files. A local disk is fine to start; S3 for production
- The `git` binary on the host running the git role
- Optionally: a model for AI Review, the pipeline's automated adjudication
  (TypeSafe AI's Jev with a key, or an Anthropic-, OpenAI-compatible or
  Bedrock model). Without one, the pipeline does **not** skip that step. It
  routes every version to human review instead (fail toward review, never
  toward skip).

## Quickstart with Docker Compose

```bash
git clone https://github.com/blaktron/agentry.git
cd agentry/deploy/compose
printf 'AGENTRY_AUTH_SEALING_KEY=%s\n' "$(openssl rand -base64 32)" >> .env   # encrypts webhook secrets and sign-in state at rest
printf 'AGENTRY_KNOWLEDGE_SEALING_KEY=%s\n' "$(openssl rand -base64 32)" >> .env   # optional: wraps knowledge packs' keys; a key of its own
mkdir -p keys && openssl ecparam -name prime256v1 -genkey -noout -out keys/signing-key.pem
chmod 600 keys/signing-key.pem && sudo chown 65532 keys/signing-key.pem  # the server's uid inside the container
printf 'AGENTRY_SIGNING_KEY_FILE=/etc/agentry/signing-key.pem\nAGENTRY_SIGNING_KEY_DIR=%s/keys\n' "$PWD" >> .env
mkdir -p edge/certs                # edge.crt + edge.key for the edge (self-signed is fine locally),
                                   # or point AGENTRY_EDGE_CERT_DIR at yours
docker compose up -d               # postgres, minio, mailpit
docker compose --profile server up -d
```

The stack refuses to start without the sealing key and the signing key in
`.env`, and the edge needs its certificate pair; all are one-time. **Back up the two keys**: the sealing key is the
only way to read the webhook secrets it encrypted, and every
attestation the signing key signed verifies only against it. Dev mode
(`AGENTRY_DEV_MODE=true` in `.env`) does without both — a constant from the
public source stands in for the sealing key, a signing key is minted at
every start, 2FA before a public publish is skipped — and is for a
throwaway stack only; the server refuses it outside `env: dev`.

The registry keeps no passwords: people sign in through an OpenID provider
you run (Keycloak, Entra ID, Okta, Google Workspace, authentik, Dex, or any
other). Configure it before the first sign-in, in `.env`:

```bash
cat >> .env <<'ENV'
AGENTRY_AUTH_OIDC_ISSUER=https://idp.example.com/realms/agentry
AGENTRY_AUTH_OIDC_CLIENT_ID=agentry
AGENTRY_AUTH_OIDC_CLIENT_SECRET=…
AGENTRY_AUTH_OIDC_DISPLAY_NAME=Example SSO
ENV
docker compose --profile server up -d
```

Register the registry with the provider as a confidential client, redirect
URI `{baseURL}/api/v1/auth/oidc/oidc/callback` ("Sign in with your OpenID
provider", below, has the details). The first sign-in creates your account.

The server's own pages are at http://localhost:8080/ui/: the sign-in
hand-off to that provider, sign-out, the page an activation link opens, and
`/ui/authorize`, which `agentry login` and the desktop app open. Everything
else, tokens, SSH keys, organizations and the review queue, is the API's,
through the CLI, the desktop app or a site in front of the registry.

An account whose provider did not vouch for its address is unactivated until
it confirms it: it reads but does not write. Ask for a link with
`POST /api/v1/user/email-verification`; in a dev setup mailpit
(http://localhost:8025) catches the message, and in production configure
real SMTP.

## Quickstart from source

```bash
brew install go postgresql@16       # or your platform's equivalent
make db-up                          # private Postgres cluster on :5477
make build
./bin/agentryd migrate
./bin/agentryd all                  # every role in one process
```

Point the CLI at it (the CLI lives in its own repo,
[blaktron/agentry-cli](https://github.com/blaktron/agentry-cli); the helper
clones and builds it, using a sibling checkout when one exists):

```bash
CLI=$(./scripts/dev/cli-bin.sh)
$CLI login --registry http://localhost:8080
$CLI init my-first-agent
cd my-first-agent && $CLI validate
```

`validate` runs the same manifest rules and the same hidden-content and
injection-signature scanners the server runs at publish time, offline.

A script or CI job that cannot sign in through a browser can give the CLI
a personal access token in the environment instead. For your own
registry, name it and set the token:

```bash
export AGENTRY_REGISTRY=https://agentry.example.com
export AGENTRY_TOKEN=agy_…   # a personal access token minted on that registry
$CLI whoami
```

`AGENTRY_TOKEN` is sent only to the self-hosted registry the CLI is
configured for: `AGENTRY_REGISTRY`, or, when that is unset, the
`defaultRegistry` in the CLI's config file (the first registry you signed
in to). A command aimed at any other registry, with `--registry` or
otherwise, does not send it and says so; it uses that registry's own
sign-in if there is one. It is never sent to SecureAgentry
(`secureagentry.net` and its subdomains), and the CLI refuses it outright
when no self-hosted registry is configured, so a token meant for one place
never reaches another. The token for SecureAgentry is a separate
variable, `SECUREAGENTRY_TOKEN`, which a release build sends only to the
SecureAgentry registry it was built for ([accounts and
tokens](https://docs.secureagentry.net/agentry/accounts/)).
`agentry --help` lists all three variables.

## Deployment shapes

| Shape | What runs | Who it is for |
|---|---|---|
| **Single process** | `agentryd all` + Postgres | evaluation, small teams |
| **HA** | Helm chart: `api`×N, `git`×N (shared RWX volume), `worker`×N; a site in front is its own deployment | production self-host |
| **AWS reference** | an ECS layout in Terraform, kept with the site (not in this repository) | a worked AWS shape to adapt |

The same binary serves every role; `agentryd api|git|worker|all` selects it.
The `git` role is the only one that needs repo storage mounted, and the
`worker` role is the only one that needs to reach the LLM provider. That is
what lets you give the scanning workers a no-egress security group.

Whatever `api` replicas must see alike lives in the database, not in any one
process: sessions, the job queue, and the SAML sets, so
an assertion consumed by one replica is refused by every other and a login
started on one completes on another. Nothing has to be enabled for that;
Redis (`AGENTRY_REDIS_URL`) remains optional and unused by these. What is
still per process is the rate-limit buckets, which an N-replica
deployment multiplies by N (the edge's limits are the ones that hold).

### The Helm chart

The chart in `deploy/helm/agentry` is published beside the image as an OCI
chart, signed with cosign like the image. The heads of `dev` and `main` are
published shortly after they move: the image as `agentryd:<branch>` and
`agentryd:sha-<sha>`, and the chart
`oci://ghcr.io/blaktron/agentry/charts/agentry` at a prerelease version,
`0.1.0-<branch>.<n>.g<sha>`, where `n` counts the publishing runs and the
default image is that `agentryd:sha-<sha>`.
A release publishes the tagged version: a `main` release as chart `0.6.15`
with image `v0.6.15`, a `dev` prerelease as chart `0.6.16-dev.1` with image
`v0.6.16-dev.1`. Only the newest `main` release moves the image's `latest`.
The package is private while the repository is, so pulling it needs a
`read:packages` token, the same one the image needs.

Every signature is keyless, issued to a GitHub Actions workflow
(`--certificate-oidc-issuer https://token.actions.githubusercontent.com`),
and its certificate identity names the workflow that signed it. Pin the
identity of what you mean to accept:

| What | `--certificate-identity` |
| --- | --- |
| a `vX.Y.Z` release, from v0.6.15 | `https://github.com/blaktron/agentry-release/.github/workflows/core.yaml@refs/heads/main` |
| a `vX.Y.Z-dev.N` prerelease, from v0.6.15-dev.112 | `https://github.com/blaktron/agentry-release/.github/workflows/core-dev.yaml@refs/heads/main` |
| a branch head's image and chart (`agentryd:<branch>`, `:sha-<sha>`, chart `0.1.0-<branch>.<n>.g<sha>` with `n` of 1001 or more) | `https://github.com/blaktron/agentry-release/.github/workflows/core-images.yaml@refs/heads/main` |

The release identities tell a `main` release from a prerelease: each
signature is refused under the other channel's identity. A branch head's
identity is the same for `dev` and `main`, so the tag or the chart version
is what says which branch it is. Earlier releases (v0.6.14 and before,
v0.6.15-dev.111 and before) were signed as
`https://github.com/blaktron/agentry/.github/workflows/release.yaml@refs/heads/main`
(`@refs/heads/dev` for a prerelease), and their sums file is
`SHA256SUMS.txt` with `SHA256SUMS.txt.sig` and `SHA256SUMS.txt.pem` beside
it; each one's notes give its command. Earlier branch builds, with `n` below
1001, were signed by a workflow in `blaktron/agentry` on their own branch;
`--certificate-identity-regexp '^https://github.com/blaktron/agentry/'`
accepts them.

A release's binaries are covered by its `SHA256SUMS`, which is signed the
same way; its notes give the commands for that release:

```bash
cosign verify-blob --certificate SHA256SUMS.pem --signature SHA256SUMS.sig \
  --certificate-identity https://github.com/blaktron/agentry-release/.github/workflows/core.yaml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
```

A chart (or an image) is checked before it is installed:

```bash
echo "$GHCR_TOKEN" | helm registry login ghcr.io -u <user> --password-stdin
cosign verify --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity https://github.com/blaktron/agentry-release/.github/workflows/core.yaml@refs/heads/main \
  ghcr.io/blaktron/agentry/charts/agentry:0.6.15
helm install agentry oci://ghcr.io/blaktron/agentry/charts/agentry \
  --version 0.6.15 -n agentry -f values.yaml
```

The values that make it installable on a cluster that is not the AWS
reference:

- `image.pullSecrets` — the Secrets that pull a private image.
- `config.git.sshAddr` (off by default) and `config.git.sshPublicUrl` — the
  git role's SSH listener, exposed as port 22 of the `<release>-git` Service
  when set. The Ingress covers HTTP only; SSH needs a TCP route or a
  LoadBalancer of its own.
- `config.signing.kind: file` with `signingKey.existingSecret` and
  `signingKey.key` — the PEM projected read-only to `config.signing.keyFile`
  (default `/etc/agentry-signing/signing-key.pem`; the directory must not be
  under the read-only `/etc/agentry` config mount, and the chart refuses one
  that is) in the worker pods only. The `api` and `git` roles start without
  the key: they serve the key set and the ruleset attestation from what the
  worker recorded, and a reviewer's approval is published and signed by the
  worker (a version stays in `needs_review` for the moment in between). The chart refuses to render `kind: file` without the Secret.
- `objectStoreCredentials.existingSecret` — object-store credentials
  (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`), injected into the api and
  worker pods only; the git role never touches the store. A `v*` tag
  pushed there is recorded by the git role and its archive is stored by a
  worker, which rebuilds it from the recorded commit and stores it only if
  the digest matches. So the worker needs the git volume
  (`worker.mountGitData`, the default). A tag submission whose archive is
  not stored within two hours is rejected, and the publisher pushes a new
  version tag.
- `secret.existingSecret` (or the chart's own Secret) — each role gets only
  the keys it uses. The git role, which takes untrusted
  pushes, gets `AGENTRY_DATABASE_URL` and `AGENTRY_AUTH_SEALING_KEY`. The
  worker also gets `AGENTRY_KNOWLEDGE_SEALING_KEY` and `AGENTRY_SMTP_PASS`:
  it sends the digest and billing mail and scans knowledge packs. The api
  gets every key, including the sign-in provider's
  `AGENTRY_AUTH_OIDC_CLIENT_SECRET`. A key passed through the chart-wide
  `extraEnv` still reaches every role, so pass a secret through the role's
  own `extraEnv` instead.
- `databaseCA.existingSecret` and `databaseCA.key` — the database's CA,
  projected to `/etc/agentry-db-ca/ca.crt`, so the DSN can carry
  `sslmode=verify-full&sslrootcert=/etc/agentry-db-ca/ca.crt`.
- `worker.networkPolicy` and `worker.proxy` — default-deny egress for the
  worker pods with allows for DNS, this namespace and the listed addresses,
  and an egress proxy in the worker's environment only (`NO_PROXY` keeps
  in-cluster names direct).
- `git.updateStrategy` with `git.replicaCount: 1` and `{type: Recreate}` —
  the shape for a ReadWriteOnce volume when no RWX class exists.
- `git.persistence.initOwnership` — for an RWX class whose driver leaves the
  volume's root owned by root (the kubelet applies `fsGroup` only to
  ReadWriteOnce volumes under a CSI driver's default `fsGroupPolicy`: Vultr
  VFS, EFS without an access point, Filestore). `true` adds an init
  container, the agentryd image run as root with `CAP_CHOWN` alone, that
  chowns `config.git.dataDir` to the pod's user and group so the non-root
  git role can write its SSH host key and the repositories.
- `AGENTRY_GIT_HOOKS_DIR` (through `git.extraEnv`; `git.hooksDir` in
  `agentry.yaml`) — where the git role makes the private directory it runs
  the pre-receive policy hook from; unset means the system temp directory,
  the chart's `/tmp` `emptyDir`. The hook never runs from the repository
  volume, because an RWX volume may not allow exec (Vultr VFS refuses with
  "Bad address"). The git role runs the hook once at startup
  and before every push, and refuses to start, or refuses the push, when it
  will not run; point it elsewhere only at a directory the server owns on a
  file system that allows exec.
- `api.extraEnv`, `git.extraEnv`, `worker.extraEnv` — environment for one
  role; `extraEnv` reaches every role.
- `podAnnotations` and `api.podAnnotations`, `git.podAnnotations`,
  `worker.podAnnotations` — annotations on the pods; a role's own win on a
  clash. A cluster autoscaler will not evict a pod with an
  `emptyDir` volume (every role has a scratch one), so it cannot drain their
  nodes unless the pods carry the annotation
  `cluster-autoscaler.kubernetes.io/safe-to-evict: "true"`. Set it on a role
  only where losing a pod is acceptable: the git role's repository volume
  may take minutes to attach on another node.
- `api.podDisruptionBudget`, `git.podDisruptionBudget`,
  `worker.podDisruptionBudget` — `{enabled, maxUnavailable}`, off by default:
  a PodDisruptionBudget for that role's pods alone, so a node drain evicts at
  most `maxUnavailable` of them at a time. `0` stops every drain of the
  role's nodes, the autoscaler's included.
- `serviceAccount` — each role runs under a ServiceAccount of its own,
  `<release>-agentry-api`, `<release>-agentry-worker` and
  `<release>-agentry-git`, so a pod's service-account token
  names the role presenting it: a service that authenticates pods by that
  token (the enterprise build's key service for hosted-run secrets binds
  encryption to the api's account and decryption to the worker's) can tell
  them apart. `serviceAccount.annotations` (an EKS IRSA role, say) goes on
  all three; an IAM trust policy written for the single account
  `<release>-agentry` that earlier chart versions made must name the three
  (or `<release>-agentry-*`) before the upgrade, or the roles lose their S3
  and KMS access. `serviceAccount.create: false` with `serviceAccount.name` runs
  every role under one existing account instead; `name` with `create: true`
  fails the render. The chart grants the accounts no Kubernetes RBAC: no
  role calls the Kubernetes API.

`scripts/acceptance/helm.sh` asserts that shape on every render: the git
Service, where each Secret lands and that nothing lands under `/etc/agentry`,
the policy, a ServiceAccount per role, the refusals.

## Configuration

`agentry.yaml` (copy `agentry.yaml.example`) plus `AGENTRY_*` environment
overrides; environment always wins. The authoritative list is
`internal/config/config.go`. The settings that matter most:

```yaml
env: prod
devMode: false          # the default; allowed only with env: dev, and one boolean switches five controls off

database:
  url: postgres://…

storage:
  kind: s3              # or local
  s3Bucket: my-agentry-releases
  s3Region: us-east-1

auth:
  sealingKey: "<base64 32 bytes>"   # required outside dev; encrypts webhook secrets
  cookieSecure: true

knowledge:
  sealingKey: "<base64 32 bytes>"   # optional; wraps knowledge packs' data keys (docs/knowledge.md); never auth.sealingKey

signing:
  kind: file            # file | kms, 'none' is refused in prod
  keyFile: /etc/agentry/signing-key.pem

# How the server presents itself and where browsers land.
web:
  url: ""               # a site fronting this server; unset = the server's own /ui/ pages
ui:
  mode: full            # full | authorize | off — the server's own browser surface
brand:
  name: ""              # emails and /ui/ call it this (default: the public host)
  logoURL: ""           # optional; the /ui/ pages show it
  cssURL: ""            # optional stylesheet the /ui/ pages load
  supportEmail: ""      # shown where people need help
  securityEmail: ""     # shown on the security notes

judge:
  provider: none        # none | static | openai | anthropic | bedrock | typesafe | classifier
  # typesafe is TypeSafe AI's Jev, the model Agentry's hosted registry uses
  # for AI Review: a hosted API with no self-hosted build, answering the six
  # rubric axes with probabilities over the manifest and every text file.
  # The key is required. The model id is pinned (default jev-1.13.0); an
  # alias such as jev-latest is refused at startup, because thresholds are
  # calibrated per version. A clean review lets the release through the
  # same gate as any other model provider; an error routes it to human
  # review.
  # apiKey: ...                       # AGENTRY_JUDGE_API_KEY (required)
  # model: jev-1.13.0                 # AGENTRY_JUDGE_MODEL (pinned; default shown)
  # baseUrl: https://api.typesafe.ai  # AGENTRY_JUDGE_BASE_URL (default shown)
  # For openai/anthropic, point at any endpoint speaking that protocol:
  # baseUrl: https://api.openai.com   # AGENTRY_JUDGE_BASE_URL
  # apiKey: sk-...                    # AGENTRY_JUDGE_API_KEY
  # model: gpt-4o                     # AGENTRY_JUDGE_MODEL (optional)
  # bedrock uses the AWS default credential chain (task role, profile, env):
  # region: us-east-1                 # AGENTRY_JUDGE_REGION (or AWS_REGION)
  # model: anthropic.claude-3-5-sonnet-20241022-v2:0   # Bedrock model id
  # classifier is a PromptGuard-class text classifier (Hugging Face
  # text-classification wire shape: {"inputs": text} → [[{label, score}]]).
  # It scores ONLY the injection axis, so it always routes to human review —
  # a cheap pre-screen that adds evidence, not a substitute for the rubric.
  # baseUrl: http://prompt-guard:8080/classify   # AGENTRY_JUDGE_BASE_URL
  # apiKey: ...                       # optional bearer token
  # With typesafe, the registry also serves the model-input scan
  # (POST /model-input/scan, docs/model-input.md) to platform staff and to
  # hosted jobs an extension admits, with this same key and model.

webSearch:
  # The web search the registry brokers for POST /model-input/search
  # (docs/model-input.md): none, youcom (You.com's Web Search API), brave
  # (Brave's LLM Context API), or tavily, exa or perplexity (their search
  # APIs, with a person's own key). The key stays
  # in the registry and never reaches a sandbox host.
  provider: none                      # AGENTRY_WEB_SEARCH_PROVIDER: none | youcom | brave | tavily | exa | perplexity
  # apiKey: ...                       # AGENTRY_WEB_SEARCH_API_KEY (required with a provider)
  # baseUrl: ...                      # AGENTRY_WEB_SEARCH_BASE_URL (empty is the provider's own:
  #                                   #   https://ydc-index.io for youcom, https://api.search.brave.com for brave,
  #                                   #   https://api.tavily.com, https://api.exa.ai, https://api.perplexity.ai)

scan:
  # The one external scanner tool behind the secret scanner's seam. Optional: unset,
  # the native Go secret detectors run alone.
  gitleaksBin: /usr/bin/gitleaks      # AGENTRY_SCAN_GITLEAKS_BIN ("auto" = PATH lookup); shipped in the image
  # gitleaks runs with the registry's own rule configuration (its built-in
  # default rules, passed as --config on every scan); a .gitleaks.toml inside
  # a submitted archive is scanned as a file and never read as configuration.
  # toolTimeout: 2m                   # AGENTRY_SCAN_TOOL_TIMEOUT per invocation
  # The vulnerability database S7 asks about the MCP servers a manifest
  # declares. Default api.osv.dev; point it at a mirror, or set "none" to
  # switch the lookup off (S7 then reports "not checked" and routes nothing).
  # osvUrl: https://api.osv.dev       # AGENTRY_SCAN_OSV_URL
  # Where S7 first asks whether each declared server's pinned version is
  # published at all: a version its registry does not have
  # rejects the submission. Defaults below; "none" in npmRegistryUrl stops
  # the check, and S7 then says it did not check.
  # npmRegistryUrl: https://registry.npmjs.org   # AGENTRY_SCAN_NPM_REGISTRY
  # pypiUrl: https://pypi.org                    # AGENTRY_SCAN_PYPI_URL
```

The scanning role needs egress to that database and to the two package
registries (three hosts: `api.osv.dev`, `registry.npmjs.org`, `pypi.org`). A
worker that cannot reach a registry leaves an `S7/version-not-checked`
finding, medium, which publishes. A worker that
cannot reach the database leaves an `S7/osv-no-data` finding naming every declared
server version the registry holds no answer for, on every submission until
a lookup succeeds. The finding is medium, so at the baseline the version
publishes with it on its report (an organization at threshold `low` holds
it), and the daily sweep looks the server up again. A server
version with an earlier answer is judged on that answer, however old. The
answers are kept per package version in
the `mcp_server_scans` table, so a server version is looked up live the
first time any manifest declares it and served from that table for the
next 24 hours.

**The daily sweep.** The worker re-checks every row of that table once
a day (the `scan.mcp_sweep` job, enqueued a minute after start-up and every
24 hours after). A server version that was clean and now carries a high or
critical advisory opens a **dependency alert** on every published version
that declares it; the author is told by email (`AGENTRY_NOTIFY_KIND=smtp`),
the audit trail records `agent.dependency_alert`, and an org's webhooks
receive `agent.dependency_alert`. The alert closes on its own when the
version is yanked, quarantined or blocked, or when the advisory is
withdrawn; publishing a fixed version does not close the old version's
alert, because the old version stays installable until it is yanked.

Git-tag publishes also have their **git history** scanned for secrets:
S2 walks the added lines of every commit reachable from the tag, so a key
committed and later removed still surfaces as `S2/history-<rule>`. That needs
the scanning role to see the repository data directory — the compose stack's
single `all` role does; a separate worker without shared git storage reports
`S2/history-not-scanned` instead of implying a clean history.

A configured tool that cannot be found is a startup error, never a silent
fallback. A tool that fails mid-scan leaves an `S2/tool-error` finding on
the report, so "gitleaks did not run" is distinguishable from "no
secrets". QuickAgents carry no tool code, so there is no code-analysis
stage; the MCP servers one declares are resolved and pinned by the runner.
S6 is the support-scripts stage that reads a package's shell, Python and
JavaScript files against the manifest, and the runner tools its instruction
calls for against the grants that give them; S7 is the MCP server lookup
above.

Generate a signing key:

```bash
openssl ecparam -name prime256v1 -genkey -noout -out signing-key.pem
chmod 600 signing-key.pem
```

Your public key is served at `/.well-known/agentry/signing-keys.json`, and
clients pin it on first use. **Back this key up.** Losing it forces a
rotation, and a rotation is visible to every client: the registry records the
public part of each key it signs with, keeps the old one listed as `retired`,
and at the next start queues a sweep that countersigns every attestation the
new key has not signed (the log says how many were pending and how many it
signed; a start on a key that some attestation still lacks queues it again),
so nothing already published stays unverifiable — but a client that pinned
the old key is told the advertised key ids changed and has to re-pin
deliberately before it verifies anything published afterwards. Rotate on
purpose, not by accident; the rotation runbook in `docs/ops/runbooks.md`
has the steps.

With the compose stack, two lines in `.env` wire the key in (the quickstart
above writes them; `AGENTRY_SIGNING_KIND` is `file` by default):
`AGENTRY_SIGNING_KEY_FILE=/etc/agentry/signing-key.pem` and
`AGENTRY_SIGNING_KEY_DIR=/path/to/the/directory/holding/signing-key.pem` (the
host directory, mounted read-only at `/etc/agentry`). The server runs as uid
65532 inside the container, so a `0600` key has to be owned by that uid
(`chown 65532 signing-key.pem`) or the server refuses to start. In dev mode
(`AGENTRY_DEV_MODE=true`, opt-in) `AGENTRY_SIGNING_KIND=none` is accepted and
the server mints a key at every start, so every restart is a rotation: the
previous key is retired, the whole catalogue is queued for countersigning,
and every client that pinned the stack warns about a changed key set until
it re-pins — fine for a throwaway stack, not for one anyone installs from;
and `kind: file` with no `keyFile` in dev mode is the same ephemeral key,
not an error.

Generate a sealing key:

```bash
openssl rand -base64 32
```

### Object storage and KMS signing

`storage.kind: local` keeps release archives on disk under `storage.localDir`.
The source quickstart uses it (the compose stack uses `s3` against its
MinIO), and a single-node deployment can keep using it indefinitely;
archives are content-addressed and write-once.

For S3, and for signing with a KMS key instead of a file:

```yaml
storage:
  kind: s3
  s3Bucket: my-agentry-releases
  s3Region: us-east-1

signing:
  kind: kms
  kmsKeyARN: arn:aws:kms:us-east-1:111122223333:key/…
```

Env equivalents: `AGENTRY_STORAGE_KIND`, `AGENTRY_STORAGE_S3_BUCKET`,
`AGENTRY_STORAGE_S3_REGION`, `AGENTRY_SIGNING_KIND`,
`AGENTRY_SIGNING_KMS_KEY_ARN`. Credentials come from the ambient AWS chain:
an instance or task role, not keys in this file. Restrict the key's
`kms:Sign` permission to the worker task role; the AWS reference's Terraform
does.

An S3-compatible store that is not AWS takes its endpoint and path-style
addressing: `s3Endpoint` (for example `https://ewr1.vultrobjects.com`) and
`s3UsePathStyle: true`, which MinIO and Ceph RGW both need, with any region
name (`us-east-1`). `s3Prefix` puts every key under a prefix, so one bucket
can hold several stores. The restore drill uses it to read the backup copy's
`store/` in place.

**Supported stores.** The `s3` backend runs against two S3
implementations:
- MinIO, in the compose stack.
- Ceph RGW, as Vultr Object Storage. A publish stores the archive byte for
  byte, the write-once conditional PUT answers `412` on a second write, and
  the attestation verifies against the served key. A copy of the store in a
  second region can be served through `s3Prefix`.

Signing with `kind: file` is what a production deployment can run: a P-256
key in a Secret mounted by the worker pods only.

**Caveat:** AWS S3 and KMS signing have **not been exercised against a live
AWS account**. The first deployment on AWS is therefore also the first
integration test of the `kms` signer and of S3's own behaviour, such as its
conditional-write semantics. If you are standing up production on S3 and
KMS, publish a throwaway version first and confirm that the archive
round-trips and `agentry verify` passes before you trust it with anything.

### Sign in with your OpenID provider

The registry can hand sign-in to any OpenID Connect provider you already
run (Keycloak, Entra ID, Okta, Google Workspace, authentik, Dex): people
sign in there, and the registry keeps its own sessions, tokens and
permissions. One provider at a time:

```yaml
auth:
  oidc:
    issuer: "https://idp.example.com/realms/agentry"   # has /.well-known/openid-configuration
    clientId: "agentry"
    clientSecret: "…"
    scopes: [openid, email, profile]   # the default
    displayName: "Example SSO"         # the sign-in button: "Continue with Example SSO"
```

Env: `AGENTRY_AUTH_OIDC_ISSUER`, `_CLIENT_ID`, `_CLIENT_SECRET`, `_SCOPES`
(comma-separated), `_DISPLAY_NAME` and `_ID`.

Register the client with your provider as a confidential client using the
authorization code flow with PKCE, and the redirect URI
`{baseURL}/api/v1/auth/oidc/oidc/callback`. `GET /api/v1/meta` then lists
`oidc` among `signInProviders`.

What the registry takes from the ID token, after checking its signature,
issuer, audience, expiry and nonce: `sub`, which links the account (as
`oidc:<sub>`), and `email` with `email_verified`. A first sign-in creates
the account, its handle seeded from `preferred_username` when the name is
free. A first sign-in whose address an existing account already holds links
to that account only when both the token and the account have the address
verified; otherwise it is refused with `409 sso-link-required`, never linked.
`amr` naming a second factor (`mfa`, `otp`, `hwk`, …) is recorded as
evidence for `auth.requireIdpMFA`.

`auth.oidc.id` names the provider in its routes and in every account it
links, and is `oidc` unless you set it. The one other id it takes is
`authentik`, for a deployment whose accounts are already linked as
`authentik:<sub>`. Never change the id of a provider whose accounts exist:
each would be signed in as somebody new.

Sign-in from a browser runs in the API's browser mode: the server's
`/ui/login` (or a site's own sign-in page) forwards to
`/api/v1/auth/oidc/<id>/start?next=<path>` and the callback answers a 303
back to that path (or to the sign-in page with `?error=…`) once the session
cookie is set; without `next` the same callback returns the JSON result the
CLI and tests consume. `auth.idpLogoutURL` (`AGENTRY_IDP_LOGOUT_URL`, the
chart's `config.idp.logoutUrl`) is where sign-out sends the browser once the
session is revoked, normally the provider's end-session endpoint, so the next
sign-in asks again.

The registry keeps no credentials of its own: no password, no second factor
and no sign-up form. Every account is made by a first sign-in through this
provider, and its second factor, if any, is the provider's. Without a
provider configured the sign-in page says so, and nobody can sign in.

The Helm chart carries the same knobs: `config.auth.oidc`,
`secret.oidcClientSecret` (or the `existingSecret` key
`AGENTRY_AUTH_OIDC_CLIENT_SECRET`) and `config.idp.logoutUrl`.

Earlier releases also had native accounts (a password, TOTP and a
remembered browser of their own), the `auth.externalOnly` switch and the
`social.*` providers (Google, GitHub, Microsoft, OpenAI and Claude). From
v0.6.15 they are gone: a configuration file that still names
`auth.externalOnly` or `social` does not load, and the
`AGENTRY_AUTH_EXTERNAL_ONLY` and `AGENTRY_SOCIAL_*` variables are not read.
Point a social provider's accounts at your OpenID provider instead; an
account that only ever had a password keeps its personal access tokens but
cannot sign in again until it signs in through the provider with the same
verified address.

### Audit archive and retention

Every audit event is written to the `audit_events` table. It is partitioned
monthly and carries an append-only trigger: rows cannot be updated or
deleted, by anyone, including you. The registry can additionally write a
continuous NDJSON stream. It is **off by default**:

```yaml
audit:
  streamKind: file            # none (default) | file | log | s3
  streamDir: /var/lib/agentry/audit-stream
  streamFlush: 30s
  retentionDays: 400          # 0 disables pruning
```

Env: `AGENTRY_AUDIT_STREAM_KIND`, `AGENTRY_AUDIT_STREAM_DIR`,
`AGENTRY_AUDIT_STREAM_FLUSH`, `AGENTRY_AUDIT_STREAM_S3_BUCKET`,
`AGENTRY_AUDIT_RETENTION_DAYS`.

- `file` appends one `audit-YYYY-MM-DD.ndjson` per UTC day to `streamDir`.
  Rotate and ship those with whatever you already use.
- `log` mirrors every event as one line on the server's own log,
  `event=audit.<action>` ([the log contract](logging.md)), so it lands
  wherever the server's lines are shipped. It is a mirror: the row stays
  the record.
- `s3` is **not implemented**. The constructor refuses at startup and names
  the bucket it was asked for, rather than silently dropping records.
  Use `file` plus your log shipper.
- An unavailable sink degrades to a no-op plus an error log; it does not stop
  the server from booting.
- Two deliberate trade-offs: the stream is fed by the audit writer
  immediately after the insert, so a transaction that rolls back afterwards
  leaves an "attempted" line in the archive with no matching row; and when
  the buffer fills (a wedged disk) records are **dropped with an error log**
  rather than blocking the request path. An archive that can stall writes is
  a denial-of-service surface, and an extra line is auditable where a missing
  one is not.

**Retention is month-granular.** Pruning works by dropping whole monthly
partitions, the only way to prune a table whose trigger refuses `DELETE`,
and O(1) rather than a 400-day scan. A partition is dropped only once *all*
of its rows are outside the window, so effective retention rounds **up** to a
month boundary: with `retentionDays: 400` you will hold up to ~430 days.
Size your storage for the upper bound.

### Notification email

Verification emails, review notifications and advisory notices go out over
SMTP:

```yaml
smtp:
  host: smtp.example.com
  port: 587
  username: agentry
  password: "…"
  from: "Agentry <noreply@example.com>"
```

Env: `AGENTRY_SMTP_HOST`, `AGENTRY_SMTP_PORT`, `AGENTRY_SMTP_USER`,
`AGENTRY_SMTP_PASS`, `AGENTRY_SMTP_FROM`, `AGENTRY_SMTP_STARTTLS`
(plus `AGENTRY_NOTIFY_KIND=smtp` to switch the notifier on).

In dev the compose stack's **mailpit** (http://localhost:8025) is the default
target and catches everything, so nothing leaves the machine. The compose
file reads all of these from `.env`, so switching the sender to a real
provider is an `.env` edit plus recreating the `server` container. With
Postmark, the server token is both SMTP username and password, and until
the account is approved it only delivers to recipients on the sending
domain. With no SMTP configured at all, the server logs that a verification
mail would have gone and to which mailbox (the address masked) and never
the token — [the log contract](logging.md) keeps every token out of every
line — so an address cannot be verified without a sender: mailpit in the
compose stack, or a real provider.

Whatever the transport, the registry mails only addresses it has verified:
a user whose `email_verified_at` is unset (the verify-email link, an IdP's
`email_verified` claim, or SCIM sets it) receives none of the notification
mails, and the suppression is logged as `notify: suppressed, address not
verified` with the user id (a user row that cannot be read is logged as
`user row unreadable` at warn and treated the same way). The verification mail itself is the one
exception, since it is how an address becomes verified. An account seeded
by hand for automation or acceptance runs should either carry a real
mailbox or have every `email_*` flag off in `user_notification_settings`
(`PUT /user/notifications`): a verified stamp on an invented
address is how a registry bounces mail from its own test data.

### Limits and quotas

The quotas are configuration (`limits.*`; the rate limits also as
`AGENTRY_LIMITS_*` in the environment, the repository quotas in YAML only) and an organization on a larger plan can be raised above them
through the entitlements resolver. The defaults:

| Key | Default | What |
|---|---|---|
| `limits.repoQuotaBytes` | 100 MiB | a push that would take the repository past it is refused |
| `limits.repoWarnBytes` | 25 MiB | past it the push succeeds and the pusher sees `remote: agentry: warning: repository is N MB of the M MB quota` |
| `limits.repoMaxBlobBytes` | 25 MiB | no single object in a pushed tree may exceed it |
| `limits.archiveMaxBytes` | 10 MiB | the release archive, after `publish.include` |
| `limits.archiveMaxFiles` | 2000 | files in the archive |
| `limits.archiveMaxFileBytes` / `archiveMaxImageFileBytes` | 2 MiB / 5 MiB | any one file, images by extension |
| `limits.archiveMaxTextBytes` | 1 MiB | the text files in total — the prose the scanners read in full; a package cannot spread an oversized instruction set across many files (V8) |
| `limits.gitPushesPerHour` | 60 | per repository, spent at one admission point whichever transport the push arrives on — smart HTTP or SSH |
| `limits.gitConcurrentPerIP` | 20 | concurrent git operations (clone, fetch, push, over smart HTTP or SSH) from one client address; past it the operation is refused at once (HTTP 429, or a message over SSH) rather than queued. The address is the one resolved through the declared proxies: behind a proxy set `http.trustedProxyCIDRs` and, for SSH, `git.sshProxyProtocolCIDRs`, or every client shares the proxy's budget. Beside it stand fixed caps of 4 per repository and 32 per process |
| `limits.sshKeyOffersPerMin` | 60 | public keys one source address may offer the git SSH listener per minute, spent before the key is looked up; past it the offer is refused without a database lookup |
| `limits.agentsPerUserNamespace` / `agentsPerOrgNamespace` | 200 / 500 | |
| `limits.versionsPerDay` | 20 | per agent |
| `limits.webhookEndpointsPerOrg` / `webhookDeliveriesPerSecond` | 20 / 5 | |
| `limits.authedPerHour`, `authedBurstPerMin`, `anonymousPerMin`, `loginPerMin` | 5000, 100, 60, 10 | the API rate buckets (also enforced at the edge) |
| `limits.knowledgeBytesPerAccount` | 0 (no cap) | the bytes of knowledge packs one account keeps in the registry, and apart from its members' the bytes of one organization's shared packs (`AGENTRY_KNOWLEDGE_BYTES_PER_ACCOUNT`); past it no pack is added or grown, and none is deleted ([Knowledge packs](knowledge.md)) |
| `limits.modelInputPerMin` | 120 | model-input calls ([Model input](model-input.md)) per caller per minute, and the burst: a platform staff member, or one hosted job. An address presenting job credentials may spend ten times that (`AGENTRY_LIMITS_MODEL_INPUT_PER_MIN`) |
| `limits.scimPerMin` | 600 | SCIM requests per organization per minute, and the burst a directory may spend at once. An initial sync of a few hundred people fits; past it the IdP gets 429 with `Retry-After` and paces itself. Raise it for a directory of thousands, since a directory's size is a property of the deployment |

The archive quotas are checked by the manifest rules (V8) both on the server
at submission and by `agentry validate` offline, so a package learns it is
over before it is uploaded.

### The job queue

Async work (scans, webhook deliveries, audit exports, repository
bookkeeping, the watchdog and MCP sweeps) rides a queue in the same
Postgres database. The driver is [River](https://riverqueue.com)
(`queue.driver: river`, `AGENTRY_QUEUE_DRIVER`); its tables (`river_job`,
`river_queue`, `river_leader`, `river_notification`, `river_migration`) are
created by the migrator on start beside the core schema, so nothing extra
runs. `queue.workers` (`AGENTRY_QUEUE_WORKERS`, default 1) is how many jobs
one worker process runs at once per queue: 1 runs jobs serially; raise it on a worker with the memory for parallel scans.
A job that fails retries with exponential backoff up to five attempts, a
job a crashed worker held is rescued after 30 minutes, and every outcome is
counted (see Metrics). A job rescued at its last attempt is run once more
as that last attempt, within ten minutes (`queue.settle_rescued` on the core
queue), so what its handler does when it gives up still happens: a
knowledge pack is marked failed, an unfinished directory erasure is audited
as abandoned and raised. A last attempt that is itself rescued is logged and
not run again. River is the only driver: a configuration that
names `queue.driver: pg` is refused at start, and the migrator drops the
legacy `jobs` table.

### Metrics

The API exposes Prometheus metrics at **`/metrics`**: HTTP request counts and
latencies by route and status, queue depth and job outcomes, scan stage
durations, and the Go runtime collectors. Scrape it from your own Prometheus;
there is no push path and no external dependency.

`/metrics` is unauthenticated and carries route-level operational data. There
is no agent content and no user identifiers, but you should still keep it off
the public internet. Bind the API's metrics exposure behind your ingress, or
scrape over the cluster network only.

A build with an extension (see "Extending the server" below) may add series of
its own to `/metrics` and to the OTLP export. They carry the same resource
labels, are named after the extension, and hold the same rule: bounded label
values, never an identifier. A series whose name the core already uses is left
out of the scrape, and the core's is kept.

`/healthz` (liveness) and `/readyz` (readiness, checks the database) are
separate and are what your load balancer should use.

### Logs

The server writes one JSON object per line to stderr and nowhere else:
[the log contract](logging.md) says what a line carries (one request id on
every line and audit row of a request, and the same id on the edge once
`AGENTRY_PROXY_REQUEST_ID` is on; an `event` name on every signal; the
access line's fields), what is never in one (tokens, secrets, names,
addresses of people, values above 4 KB), and how the audit mirror
(`audit.streamKind: log`) works. The level is `log.level` /
`AGENTRY_LOG_LEVEL`.

The compose stack keeps every container's `json-file` log rotated (three
files of 10 MB per container), so its logs never grow without bound;
`docker logs` is the reader. The edge writes its access line
as JSON too — `event=http.access`, the `request_id` it minted and passed
upstream, the client address, method, path (never the query string),
status, bytes, timings, host, user agent — so with
`AGENTRY_PROXY_REQUEST_ID=true` one id names a request on the edge's line
and on every line and audit row the server writes for it.

**Shipping the lines** is the deployment's choice: the server needs no log
store and depends on none. Every service in `docker-compose.yaml` has the
same rotated `logging` block, and a compose override file that sets
`logging` on a service replaces it with another Docker logging driver
(`syslog`, `fluentd`, `gelf`, `journald`) pointed at whatever collector you
run. Use the driver's
`mode: non-blocking` so a collector that is slow or down never stalls a
container; the price is the lines sent while it was down. On Kubernetes the
chart's pods write to stdout and stderr, which any node-level collector
reads from the kubelet's files. The audit record does not depend on any of
it: `audit_events` keeps its rows for `audit.retentionDays`, and how long a
log store keeps the `audit.<action>` lines of the `log` stream is that
store's setting.

### What the stack exposes

`/ui/` is the server's own browser surface: the device authorize
page `agentry login` and the desktop app open, and, on a server without a
site in front, the sign-in hand-off, sign-out and the page an activation
link opens. The edge sends it to the API like `/api/`. The handle
`ui` (and the other root paths of the server and the site) cannot be
registered.

Docker publishes ports by inserting its own firewall rules ahead of the
host's (firewalld and ufw zones do not apply to a published port), so a
plain `"5432:5432"` on a machine with a public address is Postgres — with
the compose file's development password — on the internet. The stack
therefore publishes every service **except the edge** on `AGENTRY_BIND`,
default `127.0.0.1`: Postgres (5432), MinIO (9000/9001), mailpit
(1025/8025) and agentryd (8080) — and the git SSH port (2222) on its own
`AGENTRY_SSH_BIND`, default all interfaces, since that one is meant to be
reached. A site overlay publishes its own services
the same way. The acceptance
scripts, `agentry` on the host, and the quickstart above all use
`localhost`, so nothing changes for them.

```bash
# .env — reach the direct ports from another machine on a private network
AGENTRY_BIND=100.64.0.7        # e.g. this host's Tailscale address
# .env — the edge is public by default; bind it privately when a tunnel
# (below) is the only intended entry point
AGENTRY_EDGE_BIND=100.64.0.7
```

Whatever you bind, confirm it from outside: `ss -ltn` on the host lists
what is listening and on which address, and a request to each port from
a machine that should *not* reach it should fail. If a public address ever
served these ports, treat the compose defaults (`agentry` / `agentry`,
`agentry-dev-secret`) as disclosed and change them.

The Postgres and MinIO passwords come from `.env` — `AGENTRY_PG_PASSWORD`
and `AGENTRY_MINIO_SECRET`, defaulting to the development values — and
reach every place they are used (the services, agentryd's DSN, the bucket
bootstrap). Set both before the first `up` on any
stack that is not a throwaway; on a stack that already has data, change
the stored password first (`ALTER USER agentry PASSWORD …` in Postgres,
`mc admin user` for MinIO) and then `.env`, since the volumes keep what
they were initialised with.

MinIO runs with one drive, so a drive it takes offline fails every write
(a 503 `SlowDownWrite`) until it comes back. It takes a drive offline when
an operation, or its own periodic write-and-read check, takes longer than
`MINIO_DRIVE_MAX_TIMEOUT`. The compose file sets that to three minutes
instead of MinIO's thirty seconds (`AGENTRY_MINIO_DRIVE_TIMEOUT` in `.env`
changes it), because a disk shared with builds can stall a write past
thirty seconds under load, and a slow write is better than a refused one.

### Rate limits at the edge

agentryd applies per-IP limits to the API; the edge adds `limit_req`
zones (keyed on the resolved visitor address) for the routes that do work for
strangers: the sign-in page `/ui/login` and `/api/v1/auth/*` (30/min, burst
30), which share one budget by visitor address. The other API routes stay
outside it. The git endpoints have their own budget (120/min, burst 60). Over the limit is `429` with
`Retry-After: 6`: six seconds is one interval of the slowest headless zone
(10/min), a conservative pause before another request. Git also permits eight
active requests per visitor; a concurrency refusal is `429` with
`Retry-After: 1`, a polling hint while a slot depends on an active request ending.
Neither delay reserves a slot. Only edge-generated refusals receive these
headers; upstream `429` responses retain their own retry instructions and
successful responses receive none. Tune the zones in `edge/nginx.conf`;
a site's overlay adds
zones for its own forms; behind Cloudflare, mirror the same paths with a
rate-limiting rule so the edge is the second line, not the first.

### Running behind a proxy

Rate limiting buckets anonymous traffic per client IP. Behind a load
balancer, every request appears to come from the balancer unless you say
otherwise:

```yaml
http:
  trustedProxies: 2          # number of reverse-proxy hops in front of agentryd
  trustedProxyCIDRs:         # where the hop in front connects from (recommended)
    - 10.0.0.0/8
```

Env: `AGENTRY_TRUSTED_PROXIES` (an integer hop count) and
`AGENTRY_TRUSTED_PROXY_CIDRS` (comma-separated CIDRs or bare addresses).

The two knobs answer different questions. `trustedProxies` says **how many**
hops wrote the tail of `X-Forwarded-For`, so the server knows which entry is
the client's. `trustedProxyCIDRs` says **who** may speak for a client at all:
when it is set, the header is read only on a request whose TCP peer is inside
one of the ranges, and every other request resolves to its peer, whatever the
header says. Set both. With the hop count alone, the server
reads the last N entries from whoever connects, so a client that reaches
agentryd's port directly with N = 1 names its own address and picks its own
rate-limit bucket; the only defence is keeping that port off every network a
client can reach. The list makes that a property of the server rather than
of the deployment, the way nginx's `set_real_ip_from` does. A chain
*shorter* than N did not come from the hops in front either, and resolves to
the peer. The list is ignored while `trustedProxies` is 0. A prefix with host
bits set (`10.0.0.5/8`) fails the start.

What to list: the address range the hop in front connects from. The compose
stack defaults it to `172.16.0.0/12,192.168.0.0/16`, docker's own address
pools, which hold the stack's network the edge reaches agentryd over (and the
bridge address a published loopback port arrives from, so a process on the
host itself can still set the header). Behind an ingress controller, list the
controller's pod range; behind a cloud balancer, its subnets. The chart's
`config.http.trustedProxyCIDRs` is empty by default and should be set with
`trustedProxies`.

`http.proxyRequestID: true` (`AGENTRY_PROXY_REQUEST_ID=true`) additionally
says the hop in front **sets** `X-Request-Id` on every request it forwards
— the compose edge does (`proxy_set_header X-Request-Id $request_id`); an
ALB does not — so the server honours it and one id names a request on both
hops ([the log contract](logging.md)). It is honoured under the same peer
test as `X-Forwarded-For`: with `trustedProxyCIDRs` set, a request from an
unlisted peer gets a minted id. Off, the default, the server mints
its own and ignores the header. Never turn it on for a hop that merely
forwards the header: that would let a client choose the id stamped on its
lines and audit rows.

`X-Forwarded-For` is honoured **only** up to that many proxy hops: behind
CloudFront → ALB set `2`; behind a single load balancer set `1`. Leave it at
`0` (the default) if the server is directly exposed. The header is then
ignored entirely. Setting it higher than the real hop count lets any client
choose its own rate-limit bucket and forge audit IPs, which is worse than
having no per-IP limiting at all.

The compose stack ships its own proxy, the `edge` service
(`deploy/compose/edge/nginx.conf`): nginx on 80/443 that terminates TLS and
serves the server's own `/ui/` pages, `/api`, `/scim`, `/.well-known`,
`/downloads/` and `/<ns>/<name>.git` from one origin (the same split the
Helm ingress makes; a site in front replaces this config with its own, see
the last section). **Use it even in dev.** Browsers send no `Sec-Fetch-Site`
and — under a `Referrer-Policy: no-referrer` — an `Origin` of `null` to any
origin that is not https or localhost, so on a plain-http hostname every
form post to the `/ui/` pages (or a site's) is refused as cross-origin.
Point `AGENTRY_EDGE_CERT_DIR` at a directory holding `edge.crt` and
`edge.key`; on a Tailscale host

```bash
sudo tailscale cert --cert-file edge.crt --key-file edge.key <host>.<tailnet-name>.ts.net
```

issues a certificate browsers trust, and a self-signed pair works for a
first boot. Then in `deploy/compose/.env`: `AGENTRY_TRUSTED_PROXIES=1`,
`AGENTRY_PUBLIC_WEB_URL=https://<host>`, and once clients trust the
certificate, `AGENTRY_PUBLIC_URL=https://<host>` (clone, install and
download URLs render from it) and `AGENTRY_COOKIE_SECURE=true`.

### Cloudflare Tunnel

The compose stack can publish the edge through a Cloudflare Tunnel — an
outbound-only connector, so the host needs no inbound port at all. The
connector reaches the edge over the compose network, not through the
published ports, so with the tunnel as the only intended entry point set
`AGENTRY_EDGE_BIND` to a private address (or `127.0.0.1`) as well. A
Cloudflare-fronted site whose origin also answers on its public IP gets
none of the WAF, rate limiting, or Access rules configured at the edge,
and the address is only ever one stale DNS record away from being known.

```bash
# .env (git-ignored, mode 600)
CLOUDFLARE_TUNNEL_TOKEN=…          # Zero Trust → Networks → Tunnels → your tunnel → token
COMPOSE_PROFILES=server,tunnel     # so a plain `docker compose up -d` includes it
```

Visitors' addresses survive the tunnel: cloudflared forwards Cloudflare's
`CF-Connecting-IP`, the edge reads that header only when the peer is on
the `ingress` network the compose file gives cloudflared and the edge
alone (`AGENTRY_INGRESS_SUBNET`, default `172.16.255.240/28`, outside
docker's own address pool; if you change it, change
`set_real_ip_from` in `deploy/compose/edge/nginx.conf` to match), and it
writes the resolved address as the single `X-Forwarded-For` entry agentryd
reads. Keep `AGENTRY_TRUSTED_PROXIES=1`; a direct connection
to the edge — from the internet or from another container on the host —
cannot forge the header, because the edge replaces it rather than
appending to it and ignores `CF-Connecting-IP` from any other peer.

The `cloudflared` service is behind the `tunnel` profile so a stack without
a token still starts. The token reaches the connector only as the
`TUNNEL_TOKEN` environment variable — not as a command-line argument, so it
does not appear in `ps` or `docker inspect`'s command — and the container
runs read-only with every capability dropped. The tunnel is remotely
managed: configure the public hostnames in the dashboard, each with origin
`https://edge:443` and the **origin server name** set to that hostname so
TLS to the edge verifies. Running
`docker run … --token …` by hand holds the terminal because cloudflared runs
in the foreground; the service is the way to run it.

### Platform staff

Name the
deployment's staff organization and its domain with `AGENTRY_STAFF_ORG` and
`AGENTRY_STAFF_DOMAIN` (the chart's `config.auth.staffOrg` and
`config.auth.staffDomain`); set both or neither. An account is platform
staff exactly while three things hold:

- the account is active;
- its verified address is at exactly the staff domain;
- it is an active member of the staff organization, in any role.

The organization admits nobody else. An address outside its domain is
refused with `409 staff-org-domain` at every door: an invitation, the
invitation's accept, an admin's approval of a pending member, SCIM
provisioning, the domain fold-in and founding the organization.

What matches: `secureagentry.net` matches `chris@secureagentry.net`. It does
not match `ops.secureagentry.net`, `secureagentry.net.example`, or a domain
that is not plain ASCII (an internationalised look-alike).

Add and remove staff by adding and removing members, as an admin of the
staff organization. The flag is recomputed in the same transaction as every
membership change (an accept, an approval, a role change, a removal or a
member leaving, SCIM deprovisioning, account erasure, and erasing the
organization). It is also recomputed at every sign-in and once over every
flagged account and member when the server starts, so changing these keys
takes effect at the next start. Each change is audited as
`user.staff_sync` with `rule: staff-org` and the reason.

What staff can do in review: every item on the platform queue and on every
organization's queue, private QuickAgents included. They read it, decide it
and record a false-positive verdict on its findings; accepting risk on an
organization's QuickAgent stays that organization's reviewers'. Staff may
also decide versions they submitted themselves, and set verdicts on their
findings, which no one else may: such a decision or verdict is marked
`self_decision: true` in its `review.decision` or `finding.verdict` audit
event. Give the staff role to people you trust with both.

The rule rests on facts nobody sets about themselves:

- **Membership** is granted by the organization's admins.
- **The organization itself** can be founded only by platform staff.
- **A stored address** changes only at erasure (SCIM refuses a change). Use
  a sign-in provider that does not let people change their own address.

An address counts as verified when the registry's mailed link was
followed, the sign-in provider or a social provider asserted it at sign-in, an
invitation at an organization's verified domain was accepted, or an
organization's SCIM provisioned it. So an address at the staff domain in
the registry is not proof by itself that its holder controls the mailbox.
It is the membership an admin grants that makes staff.

A registry-side service account needs an address at the domain and a
membership like anyone else. With neither key set, nothing syncs and
existing flags stay as they are.

**Moving a deployment onto the rule, in this order.**

1. Make sure the staff organization exists, founded by an account that is
   staff before the rule is set.
2. Give every account meant to stay staff (operators, service accounts) a
   verified address at the domain and an active membership.
3. Set both keys and restart.

The first start recomputes every flagged account: anyone not yet a member
loses staff, audited. If nobody is a member, nobody is staff, and only an
operator writing to the database can seed the first one again.

### Account erasure

`POST /user/delete` pseudonymizes the registry account. Where an extension
of the server is the deployment's directory (the service that holds people's
sign-in accounts), the erasure also reaches it: the directory deletes the
person's sign-in account, retrying on its own where it can. The outcome is
recorded as a `user.directory_erase` audit event and carried on the
erasure's 204 in the `X-Agentry-Directory-Erasure` header: `deleted`,
`not-found`, `unresolved` (an account the directory could not tell apart as
this person's, left in place), `pending` (the directory retries it),
`failed` or `not-configured` (no directory: erasure is registry-only). An
erasure whose directory half does not complete is logged as
`failopen.directory_erasure` at ERROR and counted as
`FailOpenEvents{path="directory_erasure"}`: alert on either, then delete the
sign-in account by hand. With no directory, deleting the sign-in account at
your provider is yours to do, and the privacy policy's promise that deletion
removes personal information has to say so.

### Two-factor authentication and public publishing

The registry keeps no second factor of its own, so whether people sign in
with one is your provider's to enforce, where it also covers sign-in itself
rather than only publishing. By default the registry publishes to a public
namespace without asking for evidence of one.

To turn trust into evidence, set `AGENTRY_AUTH_REQUIRE_IDP_MFA=true`.
Outside dev mode the registry then refuses to publish to a public namespace
until the account has signed in at least once with an ID token whose `amr`
claim (RFC 8176) names a second factor — `mfa`, `otp`, `hwk`, `webauthn` and
the like, never `pwd` alone — which the registry records as
`users.idp_mfa_at`. Check one sign-in's token (or the `user.login` audit row)
before enabling the flag, because with it on and a provider that never
asserts a factor, nobody can publish publicly.

With the same flag set, an organization's own SSO connection is evidence
too. When a member signs in through the organization's SAML or OIDC
connection and the validated assertion says a second factor was used, the
registry stamps `users.idp_mfa_at` as it does for the sign-in provider. Only with
the flag, because the organization's IdP belongs to that organization's
admins, not to you, and the stamp is account-wide and kept. With the flag
off there is no gate, and an organization's claim is not recorded. For OIDC the evidence is the ID token's `amr`, by the list above. For SAML
it is the signed AuthnStatement's `AuthnContextClassRef`, or Entra ID's
`http://schemas.microsoft.com/claims/authnmethodsreferences` attribute,
naming one of:

| Value | Sent by |
|---|---|
| `https://refeds.org/profile/mfa` | IdPs that follow the REFEDS MFA profile |
| `http://schemas.microsoft.com/claims/multipleauthn` | AD FS, Entra ID |
| `urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract` | SAML 2.0 context class |
| `urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorUnregistered` | SAML 2.0 context class |
| `urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken` | SAML 2.0 context class |

A password context class (`Password`, `PasswordProtectedTransport`) is one
factor and stamps nothing. Some IdPs send the multi-factor class only when
the service provider asks for it. Check one member's assertion before relying
on it. The `sso.login` audit row records, for each sign-in, whether the
assertion named a second factor (`mfaAsserted`) and whether the registry
recorded it (`mfaRecorded`).

Whichever way it is set, `GET /api/v1/meta` reports the gate's state as
`features.publicPublish2FA`, which is what a front end reads before it
tells anyone that publishing needs a second factor.

### Remembered browsers

A directory in front of the registry (an extension built on the registry's
directory port) can let a browser that answered the second factor skip it
at later sign-ins. The registry keeps the record: the directory asks for one
from a sign-in whose own verified ID token names a second factor (`amr`)
answered within the last five minutes (`auth_time`), and later asks whether
the browser's token is still one of the account's live records. The
directory sets and reads the cookie; the registry sets none of its own.

The credential is narrow on purpose. It skips the second factor at the
directory and nothing else: it is not a session, it does not lengthen one,
and it carries no scope. Its lifetime is absolute — using it does not extend
it — so it expires `AGENTRY_AUTH_TRUSTED_DEVICE_TTL` after it was issued.
That defaults to 30 days, and 30 days is also the ceiling: a larger value is
refused at startup rather than honoured, because a deployment that raised it
would be issuing a credential the threat model never priced in. Only the
token's SHA-256 is stored, beside the issuing address and user agent; those
two are recorded so that a page listing remembered browsers can describe
them to their owner, and neither is consulted in the decision. A lookup that
cannot be answered — an outage, a revoked record, an expired one, somebody
else's — answers no, and the directory asks for the code.

A remembered browser is a second credential class, not a longer session:
the 24-hour session cap still binds every session, and a `trusted_devices`
record lengthens none of them.

**Withdrawing it.** `GET /api/v1/user/trusted-devices` answers how many live
remembered browsers the caller's account has, and `DELETE` on the same path
revokes all of them, this browser's included. Both are for a session: a
personal access token reads 0 and is refused the clear. There is no list
and no per-browser removal; the hosted site offers the clear as one "Clear
remembered devices" button. Account erasure deletes the account's records in
the erasure transaction, and SCIM deactivation revokes them. Every lookup
ignores a record past its expiry, and an hourly sweep on the worker role
(`trusted_device.sweep`) deletes those rows, with the address and user agent
they hold. A revoked record is kept until its own expiry, inert, and swept
then. Signing out, and "sign out everywhere else", leave remembered browsers
alone: surviving them is the point, and the clear above is the control that
ends them.

## Hosting the downloads

The edge serves whatever is in the downloads directory
(`AGENTRY_DOWNLOADS_DIR`; unset, an empty named volume `downloads`) at
`/downloads/`, so publishing a build for your users is a file copy. The
CLI and the desktop app build from their own repositories (`agentry-cli`,
`agentry-desktop`); the hosted site's repository has the script that
builds the whole matrix and writes the `manifest.json` its download page
renders. A registry without a site hosts the files and links to
them from wherever it tells its users about the clients:

```bash
scp agentry-*-linux-amd64 host:/srv/agentry/downloads/
```

`AGENTRY_DEFAULT_REGISTRY` bakes the registry these binaries talk to when
the user configures nothing — set it to the registry (or the site in front
of it) that serves them, so a downloaded client connects back there by
default (`--registry` and the config file still override). Left empty, the
source defaults apply.

The script cross-compiles the CLI for macOS (arm64, amd64), Linux (amd64,
arm64) and Windows (amd64) — it is pure Go — and builds the desktop app
for Linux when the GTK/WebKit dev headers are present and for Windows when
the Wails CLI is on `PATH`. The macOS desktop app cannot be built there:
a Mac builds it (`scripts/build-darwin.sh` in the desktop repository,
which produces a zip of the universal application bundle), and the script
brings that zip in with `--import DIR` — every artifact in `DIR` is copied
into the output before the checksums are written, so it is listed like the
rest; a `SHA256SUMS` beside it, written by the Mac, is checked before the
copy. It writes `SHA256SUMS` and `manifest.json`; the page renders from
the manifest, shows every target on the release matrix, and marks the ones
without an artifact as not yet available instead of linking to nothing.
The Windows artifacts are Authenticode-signed (desktop 0.5.0 or later):
the import re-verifies each signature with `osslsigncode` against the name
the bundle's `BUILD-INFO` states before the manifest marks it `signed`, and
refuses a mismatch. The macOS bundle is ad-hoc signed and the Linux packages
carry no OS signature; a card says "signed" only when the manifest does. Point `AGENTRY_DOWNLOADS_DIR` in `.env` at the directory — the
edge serves it at `/downloads/`, and a site's `web` container reads the
manifest from it — and re-create the `edge` service (and the site's `web`,
when one is in front) once so the mount exists. Versions come from
`git describe` in each repo, so tag releases
(`v0.1.0`) to get readable file names.

## Choosing your publication policy

The platform baseline lives in the `policies` table (`org_id IS NULL`) and is
readable at `/api/v1/platform/policy`. With no row, the defaults are the
ruleset's: findings up to `medium` auto-publish with the findings shown,
`high` goes to review, `critical` is rejected, wildcard network egress (and
a browser whose `scope` is `public`; `wildcardEgress`
decides both) goes to review, and content a stage could not read goes to review whatever the
threshold. The threshold is released with the rule bundle's version (`medium`
since ruleset 0.3.0, `low` before it), so upgrading the server can move it;
a stored row keeps whatever it says.

A stricter starting point for an internal registry, where everything gets a
human look:

```json
{
  "requireHumanReview": "always",
  "maxAutoPublishSeverity": "info",
  "wildcardEgress": "reject",
  "allowedLicenses": ["Apache-2.0", "MIT"]
}
```

Organizations can tighten this for their own namespace but never loosen it:
`blockedCapabilities` unions, `allowedLicenses` intersects, severity
thresholds only move down, and `requireHumanReview` conditions add up (a
baseline that reviews `exec` and an organization that reviews `network`
review both; `"always"` wins over any condition). When the baseline's and
the organization's `allowedLicenses` have no identifier in common, no
license is left, so the namespace refuses every public publish; the
effective policy says so with `"noPublicLicense": true`. A policy document
may set `noPublicLicense` itself to stop public publishes.

Three notes on the knobs:

- `blockedMcpServers` rejects a submission whose manifest declares one of the
  listed MCP servers (`npm:<package>` / `pypi:<package>`, or `url:<host>`
  for a remote server, `path.Match` globs such as `npm:@evil/*` or
  `url:*.example.com`); it unions across baseline and org like
  `blockedCapabilities`.
- `blockedCapabilities` rejects a submission that *declares* the capability;
  it is a gate on the manifest, not a runtime restriction. Combine it with
  `requireHumanReview: {"whenCapabilities": [...]}` if you want a look rather
  than a refusal.
- `allowedLicenses` lists SPDX identifiers; the registry validates against
  the full SPDX license list (embedded, refreshed with
  `scripts/dev/spdx-sync.sh`) and accepts expressions — `MIT OR Apache-2.0`,
  `GPL-2.0-or-later WITH Classpath-exception-2.0`. An expression passes the
  policy only when every identifier in it is allowed. Custom `LicenseRef-`
  identifiers are refused for public publish. The baseline's and the
  organization's lists are intersected without regard to case. An absent
  or empty list allows any license.

## Organizations

An organization is a namespace with members. Anyone with a verified
address creates one (`POST /api/v1/orgs`, or a site's organizations page)
and becomes its first **admin**; the other role is
**member**. Admins manage members, teams, settings, policy, SSO, SCIM,
domains and webhooks and publish to the organization's agents; members
create agents in its namespace and publish to them. Nobody joins
uninvited: an admin invites by email, or approves someone the
organization's IdP provisioned over SCIM. A person belongs to one
organization at a time and may leave it from the members list; the last
admin cannot leave, be removed or erase their account until another admin
is in place.

An organization is **keyed on its creator's email domain**: unless the
form asks for no domain, or the address is at a public mail provider,
the domain is recorded, a second organization cannot be created at it,
and a person who signs up with an address there is pointed to its admins
(`GET /api/v1/user/domain-org`; `POST …/request-access` mails them, once a
day). Further domains are claimed and verified over DNS from the
organization (`/api/v1/orgs/{org}/domain-claims`); a verified domain also belongs
to one organization.

An admin **decommissions** the organization by naming its handle
(`POST /api/v1/orgs/{org}/decommission`). It is then read-only for its members for the hold below, and
when the hold ends a sweep yanks its releases, deletes its archives and
repositories, ends every membership and releases its handle and domain.
Platform staff can **suspend** an organization
(`POST /api/v1/orgs/{org}/suspend`) — it and everything under it answer as
absent, over the API and over git and to staff too, until reinstated — and
**reinstate** one, which also cancels a hold that has not run. Both take the
organization's handle, since a suspended organization is absent even to
staff.

When an organization holds a domain, the accounts whose verified address
is at it **fold in**: at the person's next directory sign-in they become a
*pending* member of the organization — the same state a SCIM-provisioned
person is in — and a sweep folds in the accounts already known at the
domain the moment the organization is created there or verifies it. A
pending member holds nothing and keeps working on their own plan until an
admin approves them (where the seat is taken) or declines them; a decline
is remembered, and only an admin's invitation supersedes it. `GET
/api/v1/user` carries `pendingOrg` while they wait, and the server's own
pages show the notice. The admins are mailed the pending list in one
daily digest, each person named once, through the notifier under the
verified-address rule. The fold-in never fires for an unverified address,
a public mail domain, or a person who belongs to an organization already.

```yaml
orgs:
  decommissionHold: 720h      # 30 days; 0 erases at the next hourly sweep
  pendingDigestEvery: 24h     # the admins' pending-members digest; 0 keeps a day
```

Env: `AGENTRY_ORGS_DECOMMISSION_HOLD`, `AGENTRY_ORGS_PENDING_DIGEST_EVERY`.

## Operating it

- **Backups:** Postgres is the system of record. Back it up. Release archives
  are content-addressed and write-once; repos are recoverable from any clone.
  Losing the repo store breaks pushes, not published installs.
- **The worker matters.** With no worker running, versions sit in `scanning`
  and never publish. That is the fail-closed design working, but it looks like
  a hang. Check the worker first when publishes stall.
- **A new ruleset rescans the catalogue and redoes the review queue.**
  Registering a ruleset semver for the first time enqueues the rescan
  sweep automatically; the rescan sweep quarantines published versions that newly
  trip a high or critical finding no person has decided on. Beside it,
  `scan.redo_review_queue` judges every version in `needs_review` with a
  pending item again under the new ruleset and publishes the ones the gate
  now passes; their items close as `superseded`. Both log a summary when they
  finish. Every release is kept in `ruleset_releases`, and each version is
  tagged `ruleset/v<semver>` in the core repository
  ([pkg/ruleset/README.md](https://github.com/blaktron/agentry/blob/main/pkg/ruleset/README.md)).
- Runbooks for the failure modes above: [docs/ops/runbooks.md](ops/runbooks.md).

## What you are responsible for

Running your own registry means you own the trust decisions:

- the signing key and its backups;
- who has platform-staff rights (they can quarantine, block, and read
  everything on your instance);
- whether an AI Review model is configured (`judge.provider`), and therefore
  whether review is automated or entirely human. A configured model's token
  use is recorded per scan run and shown to platform staff on the report as
  `judgeUsage`;
- keeping the ruleset current; a scanner from a year ago is a scanner that
  has not seen this year's techniques.

None of that is different on SecureAgentry; self-hosting makes it
visible.

## Who reads an agent's repository over git

An agent's own people read and push its whole repository, over smart HTTP
or SSH: the owner, an organization's administrators and active members,
and anyone granted a role on the agent. Everyone else reads a public agent
only as far as review has passed it:

- A clone advertises only the tags that point at the commit of a reviewed
  version (published, or yanked, which still installs by exact pin), and
  HEAD at the newest of them. No branch, and no tag of a version that is
  awaiting review, rejected, quarantined or blocked.
- It is served from a separate repository that holds those tags and the
  objects they reach, history included, and nothing else, so no other
  object can be fetched by its id. The registry keeps one such copy per set
  of reviewed tags under `git.dataDir/views` and builds a new one when the
  set changes.
- A public agent with no reviewed tag, and every agent the platform has
  quarantined or blocked, answers as a path that is not there: the
  credential prompt (401) anonymously, 404 when signed in.

A pending member and a security reviewer hold no role on an organization's
agents and read none of its private ones.

Git sends credentials over HTTPS only when the server asks for them, and a
public agent does not ask, so an owner who clones their public agent with a
token in the URL reads it as anyone would. Send the token with the first
request, or use SSH, to read the whole repository:

```bash
git -c http.proactiveAuth=basic clone https://<handle>:<token>@registry.example.com/<ns>/<name>.git
```

`http.proactiveAuth` needs git 2.46 or later.

## SSH git transport

Besides smart HTTP, the `git` and `all` roles serve `ssh://git@<host>:<port>/<ns>/<name>.git`
when `AGENTRY_GIT_SSH_ADDR` is set (the compose stack sets `:2222` and publishes it on the
host as `${AGENTRY_SSH_PORT:-2222}`; unset it to switch the transport off). Only
`git-upload-pack` and `git-receive-pack` are served — no shell, no forwarding — through the
same authorization, hooks and quotas as HTTPS.

- **Credential:** a user's SSH public key, registered with
  `POST /user/ssh-keys` (or a site's settings page). A key is worth repository read/write and the release tag the
  user's role allows; it never reaches the API. There is no anonymous mode over SSH. Adding
  a key reads the entitlements switch `SSHKeys`: the core always includes it;
  a closed build's resolver may refuse it by subscription (`403 feature-not-included`), and a
  key already held keeps working.
- **Host key:** generated under the git data directory on first start
  (`ssh_host_ed25519_key`; `AGENTRY_GIT_SSH_HOST_KEY` points elsewhere). The SHA256
  fingerprint is logged at startup (`git ssh listening … hostkey_fingerprint=…`) — publish it so users
  can pin it in `known_hosts`.
- **Advertising:** set `AGENTRY_GIT_SSH_PUBLIC_URL` (for example
  `ssh://git@git.example.com:2222`) and agent pages show the SSH clone URL next to HTTPS.
- **Enforced SSO:** an organization that requires SSO takes pushes only over HTTPS with an
  org-bound token; over SSH the push is refused with that message.
- **Budgets:** a push over SSH spends the same per-repository hourly budget as a push over
  HTTPS (`limits.gitPushesPerHour`) and is refused with the same words when it is spent. The
  listener also bounds what one source address may make the registry do before it has a
  credential: `limits.sshKeyOffersPerMin` public-key offers a minute, refused past that
  without a lookup. The client sees the ordinary `Permission denied (publickey)`; the
  server's log carries the refusal (`http.rate_limited`, class `ssh-key-offer`, with the
  address). The port is the one service the compose stack publishes beyond loopback
  (`AGENTRY_SSH_BIND`), so the edge's rate limits do not cover it; this budget is what does.
  It is keyed by the peer address the listener sees, so a TCP proxy in front of it that
  does not preserve the source puts every client in one bucket.
- **Behind a TCP proxy:** set `git.sshProxyProtocolCIDRs` (env
  `AGENTRY_GIT_SSH_PROXY_PROTOCOL_CIDRS`, comma-separated; the chart's
  `config.git.sshProxyProtocolCIDRs`) to the addresses the proxy connects from, and have
  the proxy send a PROXY protocol header (nginx `stream`: `proxy_protocol on;` in the
  `server` block that forwards to the listener; HAProxy: `send-proxy` or `send-proxy-v2`).
  The listener then requires a v1 or v2 header on every connection and uses its source
  address for the key-offer budget and the log line, so the budget is per client again.
  A connection from any other address is refused, header or not, and so is a connection
  from a listed address that opens without one: a client can never name its own address.
  The proxy's own health checks (v1 `UNKNOWN`, v2 `LOCAL`) are served as the proxy's
  address. Refusals are logged as `git ssh connection refused` with the peer and the
  reason: at `info` when a listed proxy sends no usable header (a misconfiguration), at
  `debug` for any other address (scanners would otherwise flood the log). Entries are CIDRs or bare addresses; a prefix with host bits set
  (`10.0.0.5/8`) fails the start. Turn the proxy's header on and this setting on
  together: this setting without the header refuses every connection, and a header the
  listener does not expect is at best ignored (a v1 line is skipped as a pre-banner line
  and the budget stays the proxy's; a v2 header breaks the handshake).

## Fronting it with a site

Everything above is a complete registry. SecureAgentry puts a site in
front of the same server — a closed front end that renders the catalogue,
the report cards, the Builder and the account pages in its own brand — and
so can you. The contract between a front end and this server is small and
entirely configuration:

- **`web.url` / `AGENTRY_WEB_URL`** — the site's origin. When it is set,
  every browser destination the API writes (where a failed sign-in lands,
  where a signed-in browser goes, where an email link points, where sign-out
  ends) is a page of that site instead of the server's `/ui/` pages. The
  site's paths are fixed by convention (`/login`, `/dashboard`,
  `/settings/…`, `/verify-email`); `internal/api/webpaths.go` is the one
  table that knows them.
- **`ui.mode` / `AGENTRY_UI_MODE`** — `full` serves every `/ui/` page (the
  device-authorize page, the sign-in hand-off, sign-out and address
  confirmation), `authorize` keeps only the device-authorize page the CLI
  and the desktop app open (the site provides the rest), `off` serves none. A site in front
  normally runs `authorize`.
- **`brand.*` / `AGENTRY_BRAND_NAME`, `AGENTRY_BRAND_LOGO_URL`,
  `AGENTRY_BRAND_CSS_URL`, `AGENTRY_SUPPORT_EMAIL`, `AGENTRY_SECURITY_EMAIL`**
  — what the server calls the deployment in emails and on the `/ui/` pages; the
  stylesheet and logo the remaining pages load. `GET /api/v1/meta` reports
  `brand` and `ui` (with `authorizeUrl`) so clients need no other
  configuration.
- **Sign-out** — `AGENTRY_IDP_LOGOUT_URL` is the sign-in provider's
  end-session endpoint, where sign-out sends the browser.
- **The edge** — a site replaces `edge/nginx.conf` with one that sends
  `/api/`, git, `/ui/` and `/downloads/` to the server and everything else to
  the site, and adds rate-limit zones for its own forms.

In compose that is one overlay file: a second `-f` that adds the site's
services, replaces the edge config, and sets the variables above; the core
stack is untouched. The site talks to the same API as the CLI, with the
browser's session cookie, under the same authorization matrix — a front end
cannot do anything the API refuses.

A closed build can also extend the server itself: `pkg/extension` lets an
outside Go module mount routes under `/api/v1/x/<name>/`, run its own
migrations in its own schema, replace the entitlements resolver (limits and
the caps `Features` answers, such as a private-agent cap), subscribe to
committed events and add worker jobs, with `GET /api/v1/meta` listing what is
loaded. An extension may also admit or refuse a submission after every core
check and before anything is stored (`Admits`), name a route of its own
the anonymous rate class skips (`Unthrottles`: a payment provider's signed
webhook), receive the database pool, the logger, an audit writer and a meter
for its own metrics at start-up (`Binds`), delete the rows it keeps about a person inside the
account erasure's and the data clear's own transaction (`ErasesAccounts`),
run a job on a period, and register audit actions under its own name.

An extension can also be the deployment's directory, the service that holds
people's sign-in accounts. It supplies the directory the registry erases
accounts in and asks whether an account is still there (`ManagesDirectory`);
the directory's own work at sign-in (its claims, remembered browsers, the
checks its flows make, a mirror of platform staff) is the extension's. A
directory that also carries out an erasure's directory half itself, retries
included (`DirectoryErasure`), is handed the erased account once the
registry's erasure has committed, and the outcome it returns is what
`X-Agentry-Directory-Erasure` reports. It hears every
sign-in through an individual provider with all of the ID token's claims,
before the session is issued, and whether that sign-in created the account
(`HearsSignIn`), and the events
`account.erased` (with the identities the account signed in with and the
address it held) and `staff.changed`. It can read platform staff, mint a
remembered browser at a sign-in it hears, and check one, under the
registry's rules: minted only from that sign-in's own verified token, whose
`amr` names a second factor and whose `auth_time` is minutes old, stored as
a SHA-256 hash and bound to one account. It can say that a sign-in it
hears came through an organization's own single sign-on
(`SignIn.AssertSSO`), and the session that sign-in gets then satisfies the
organization's enforced SSO; the organization's audit log records it as
`sso.login`. It can seal a small value it must
keep at rest, such as a queued erasure's address, under the server's
sealing key (`Deps.Sealer`). It can serve calls
from a service of its own under `/internal/x/<name>/` (`ReceivesCallbacks`).
There the registry checks a shared secret of at least 32 characters, answers
404 to any request carrying `X-Forwarded-For` or `Forwarded`, applies the
rate class the extension declared, and resolves no caller. No edge shipped
with the registry routes `/internal/`, and an ingress you write must not
either. `pkg/handle` exports the handle grammar and the reserved names, for
a directory that lets people choose a username the registry seeds a handle
from.

The core carries no extension and behaves identically with none:
a self-hosted registry has no subscription tiers, caps nothing, and never
answers `402`.

## Sandbox hosts for hosted runs

A registry built from this repository needs none of this section either. It
concerns a deployment of the closed enterprise build that runs
[hosted runs](hosted-runs.md) on the push path, and it describes the hosts
([the execution plane](hosted-runs.md#the-execution-plane)) made by hand on
any provider.

**What the registry needs.** The CA and the runs store, both, or no run is
pushed:

- Make the CA with `secureagentry-ca init -dir DIR -name NAME` on a
  machine of your own, not a server. Give the server `DIR/master.key` as
  `AGENTRY_RUNS_CA_MASTER_KEY` and `DIR/bundle.b64` as
  `AGENTRY_RUNS_CA_BUNDLE`, from the files into its secret store. Back up
  `DIR/root.key` yourself and put it nowhere else: without it no
  intermediate can be signed again. The same CA's root is what the server
  checks [OpenBao's](#openbao-the-key-service-for-hosted-run-secrets)
  certificate against.
- Give the runs store two buckets of its own, separate from the registry's
  object store (`AGENTRY_RUNS_STORE_*`, in
  [the hosted runs' configuration](hosted-runs.md#the-deployments-configuration)).
  The hosts reach them only through presigned URLs, so they must be able to
  reach the endpoint; the registry needs the keys. Give the input bucket a
  lifecycle rule of a couple of days and the output bucket one past the
  runs' retention, as backstops: the registry deletes both itself.
- Set the hosts' settings on the server (`AGENTRY_RUNS_HOST_*`): the model
  the hosts call, with its key, and a registry token with `agent:read`.

**A host.** A Linux machine with a docker daemon on which gVisor's `runsc`
is registered twice: as `runsc`, and as a second registration that runs the
same binary with the same arguments plus `--host-uds=open` (`runsc-uds`),
under which the MCP gateway reaches its run's docker filter. runhost refuses
to start when either is missing, or the second runs anything else. Run
`secureagentry-runhost` there with `AGENTRY_RUNHOST_NAME` (the host's DNS
name), `AGENTRY_RUNHOST_TLS_DIR`, `AGENTRY_RUNHOST_HOME` (the same path in a
container and on the host), `AGENTRY_RUNHOST_REGISTRY` (your registry's
public origin, which the CLI resolves and verifies releases against),
`AGENTRY_RUNHOST_API` (the origin it enrols at),
`AGENTRY_RUNHOST_RUNTIME=runsc`, `AGENTRY_RUNHOST_GATEWAY_RUNTIME=runsc-uds`,
and `AGENTRY_RUNHOST_RESOLVERS` (the host's own name servers, at most three,
IPv4). Leave out the settings the registry pushes. Mint its enrolment token
as platform staff for that name and the address the registry will reach it
at, and give it to `secureagentry-runhost enrol` on stdin. One job at a time
is the default (`AGENTRY_RUNHOST_CAPACITY`). Give each host a machine of its
own: a daemon shared with anything else is a kernel shared with the runs'
sandbox.

**The network.** This is what keeps a run from reaching your registry:

- Put the hosts on a network that has no route to the registry's, its
  database or its object store.
- Inbound, admit runhost's port (`8443`) from the registry's egress address
  alone, and nothing else.
- Outbound, from the host and from every container on it, admit DNS to the
  resolvers you named and TCP 80 and 443 to public addresses, and refuse
  private ranges, CGNAT, link-local and loopback addresses; refuse the
  containers the cloud's metadata address too. Put the rules where the
  container runtime's own firewall rules cannot bypass them.
- The hosts must reach, on public addresses, your registry's origin, the
  runs store's endpoint, the model's endpoint and the image registries the
  runner pulls from. A registry or a store on a private address is refused
  by the rule above; open exactly that address and port if you must.

**Taking a host out.** Retire it as platform staff, unless it is the last
host taking runs (`409 last-host`): the registry calls it no more, closes
and refunds a run it held once the stale window passes, and never enrols its
name again. Then stop it. A machine rebuilt comes back under a new name. The enterprise
build's fleet, which makes and destroys hosts itself, speaks Vultr's API
alone ([its settings](https://docs.secureagentry.net/ops/deployment/#the-runs-fleets-settings));
without it, every host is made and taken down this way, by hand.

## OpenBao, the key service for hosted-run secrets

A registry built from this repository needs none of this section. It
concerns a deployment of the closed enterprise build that mounts its vault,
the extension that keeps an account's secrets for
[hosted runs](hosted-runs.md#a-runs-secrets). The vault is the first part
of the application that depends on a service besides the database and the
object store: [OpenBao](https://openbao.org/), whose Transit engine
encrypts and decrypts each secret, so the key never rests in the
registry's database. The vault is off while `AGENTRY_VAULT_ADDR` is unset.
A release that declares a secret is then refused for a hosted run
(`409 secrets-declared`), and a set is `503 vault-unavailable`.

### What OpenBao must carry

| Item | What |
|---|---|
| Transit | mounted at `transit/`, with four keys, each of type `aes256-gcm96` and **derived**, so that what is encrypted with an owner as the context (`user:<account id>`, or `org:<organization id>` for `hosted-keys`) is under a key of that owner's own: `hosted-vault` for the secrets; `hosted-connections` for the vault's OAuth connections; `hosted-runs` for the data keys of a hosted run's own data at rest; `hosted-keys` for each account's and organization's private key from the runs CA's `users` intermediate, which opens their knowledge packs, Writing Voice and run outputs |
| policy `encrypt` | `update` on `transit/encrypt/hosted-vault` and `transit/encrypt/hosted-connections`, nothing else: the api's |
| policy `decrypt` | `update` on `transit/decrypt/hosted-vault` and nothing else: the worker's |
| policy `connections` | `update` on encrypt and decrypt under `hosted-connections`: the worker's |
| policy `runs` | `update` on encrypt and decrypt under `hosted-runs`: both roles' |
| policy `keys` | `update` on encrypt and decrypt under `hosted-keys`: both roles' |
| an operator's policy | rotate the key, read its versions, rewrap, and set the version floors, never `exportable` or plaintext backup, which cannot be turned off once set. It never decrypts |
| two login roles | the api's bound to `encrypt`, `runs` and `keys`, the worker's to `decrypt`, `connections`, `runs` and `keys`, each **without the default policy**, so their tokens cannot renew themselves. The server logs in again at three quarters of the lease and once more on a `403` |

The roles log in by AppRole (`AGENTRY_VAULT_AUTH=approle`) or by the pod's
ServiceAccount token (`kubernetes`). On Kubernetes, bind the encrypt role to
the api's ServiceAccount and the decrypt role to the worker's, which the
chart gives each role ([the Helm chart](#the-helm-chart)). A compose stack
runs every role in one process, which then holds both roles' AppRole
credentials. That is weaker than a cluster, where each role holds only its
own.

The server talks to OpenBao over HTTPS alone and checks its certificate
against the runs CA's root and nothing else (`AGENTRY_RUNS_CA_*`, the CA that
signs the sandbox hosts' certificates). The name it checks must be a cluster
service's (`<service>.<namespace>.svc`), because the sandbox hosts'
certificates come from the same CA and none of them is named in that space.
Serve OpenBao a server-authentication certificate for such a name, and set
`AGENTRY_VAULT_TLS_SERVER_NAME` when the address's host is not that name.
The server refuses to start when the address is not `https://`, the checked
name is not a service's, or the runs CA is missing. A certificate OpenBao
does not serve correctly shows only at first use: a set is
`503 vault-unavailable` and a run with a secret fails, refunded.

| Variable | What |
|---|---|
| `AGENTRY_VAULT_ADDR` | OpenBao's `https://` address; unset, the vault is off |
| `AGENTRY_VAULT_AUTH` | `approle` or `kubernetes`; required with an address |
| `AGENTRY_VAULT_ENCRYPT_ROLE_ID`, `AGENTRY_VAULT_ENCRYPT_SECRET_ID` | the encrypt role's AppRole, both or neither |
| `AGENTRY_VAULT_DECRYPT_ROLE_ID`, `AGENTRY_VAULT_DECRYPT_SECRET_ID` | the decrypt role's AppRole, both or neither |
| `AGENTRY_VAULT_ENCRYPT_ROLE`, `AGENTRY_VAULT_DECRYPT_ROLE` | the Kubernetes auth roles; a process that names neither logs in as `api` to encrypt |
| `AGENTRY_VAULT_KUBERNETES_TOKEN_FILE` | the ServiceAccount token, read at every login; the pod's own by default |
| `AGENTRY_VAULT_TLS_SERVER_NAME` | the name OpenBao's certificate is checked for |

Give the api the encrypt role and the worker the decrypt role, each with the
policies above and nothing more. The api then writes secrets it cannot read,
and the worker opens them only at a run's hand-off. Run data (`hosted-runs`)
and account keys (`hosted-keys`) are the exceptions: both roles encrypt and
decrypt under them, because both serve the owner's own reads, and the code's
owner checks are the guard there.

**Without the vault**, an enterprise build with the runs CA configured
still issues each holder's encryption key, and seals it under the runs CA's
master key (`AGENTRY_RUNS_CA_MASTER_KEY`). The master key and the database
together then open the key that opens every holder's packs, voice and run
outputs. With the vault configured, new keys are sealed by `hosted-keys`,
and a seal pass moves the older ones within minutes.

### Its seal, its storage and its audit

- **Storage.** OpenBao's `postgresql` storage in a database and user of its
  own, beside the registry's. Both tables it creates have a primary key.
- **Seal.** OpenBao's static seal: a 32-byte key it reads at start-up and
  unseals with. A restart comes back unsealed with no one present, and a
  wrong key leaves it running and sealed, so health-check with
  `bao status`, not the port. Where OpenBao initialises itself from its
  configuration file (Transit, the key, the policies, the roles), as
  Agentry's own deployments do, it revokes the root token it made and,
  under a static seal, makes no recovery keys. Administration then
  needs a login of its own, such as a break-glass role that no pod uses.
- **Audit.** A `file` device on standard output puts one JSON line per
  request and response on the container's log. Each line names the path, the
  role and the policies, and replaces every value with a keyed hash.

### What to back up, and what it opens

- **The seal key.** Without it, OpenBao's storage cannot be unsealed and
  every account's secrets are lost. Keep a copy off the cluster.
- **OpenBao's database**, with the registry's own backups. The Transit key
  lives there, encrypted under the seal key.
- **The certificate's renewal date.** Its expiry stops every set and every
  hosted run with a secret.

The seal key and a copy of OpenBao's database together open the Transit
key. With the registry's database beside them, which holds the ciphertexts,
they open every secret. A static seal moves the key out of the registry's
database. It does not put it beyond the cluster: whoever can read the
cluster's Secrets and reach PostgreSQL has all three. Guard the seal key's
copies as you guard the database's backups, and do not store them together.

Each secret records the key version that encrypted it. After a rotation,
never raise the key's minimum decryption version past the oldest version
still in use, or those secrets stop opening.

What the vault does not protect, from the worker role to a leaked token, is
in [Hosted runs](hosted-runs.md#what-this-does-not-protect). Two more points
concern the operator:

- **On a compose stack the api can read a secret.** Its one process holds
  the decrypt role beside the encrypt role. Only where the api and the
  worker run apart does the api write secrets it cannot open.
- **OpenBao's operator policy** rotates and rewraps but cannot decrypt.
  Anyone who holds the break-glass role, or the seal key and the storage,
  can.
