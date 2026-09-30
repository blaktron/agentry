# Self-hosting Agentry

The whole registry is open source: the scanners, the review queue, SSO and
SCIM, signing with your own key, and the server's own browser pages. There
is no "community edition" with the security features removed; a registry you
cannot audit is one you have to take on faith. What is *not* in this
repository is the hosted service's site — a closed front end that runs in
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
printf 'AUTHENTIK_SECRET_KEY=%s\n' "$(openssl rand -base64 48)" >> .env
printf 'AGENTRY_AUTH_SEALING_KEY=%s\n' "$(openssl rand -base64 32)" >> .env   # encrypts TOTP seeds and webhook secrets at rest
printf 'AGENTRY_KNOWLEDGE_SEALING_KEY=%s\n' "$(openssl rand -base64 32)" >> .env   # optional: wraps knowledge packs' keys; a key of its own
mkdir -p keys && openssl ecparam -name prime256v1 -genkey -noout -out keys/signing-key.pem
chmod 600 keys/signing-key.pem && sudo chown 65532 keys/signing-key.pem  # the server's uid inside the container
printf 'AGENTRY_SIGNING_KEY_FILE=/etc/agentry/signing-key.pem\nAGENTRY_SIGNING_KEY_DIR=%s/keys\n' "$PWD" >> .env
mkdir -p edge/certs                # edge.crt + edge.key for the edge (self-signed is fine locally),
                                   # or point AGENTRY_EDGE_CERT_DIR at yours
docker compose up -d               # postgres, minio, mailpit, authentik
docker compose --profile server up -d
```

The stack refuses to start without `AUTHENTIK_SECRET_KEY`, the sealing
key and the signing key in `.env`, and the edge needs its certificate
pair; all are one-time. **Back up the two keys**: the sealing key is the
only way to read the TOTP seeds and webhook secrets it encrypted, and every
attestation the signing key signed verifies only against it. Dev mode
(`AGENTRY_DEV_MODE=true` in `.env`) does without both — a constant from the
public source stands in for the sealing key, a signing key is minted at
every start, 2FA before a public publish is skipped — and is for a
throwaway stack only; the server refuses it outside `env: dev`.

The server's own pages are at http://localhost:8080/ui/ — sign-in, your
account, tokens and SSH keys, the review queue, the staff console and
organization administration. `agentry login` opens `/ui/authorize` there.

Then create the first account:

```bash
curl -sX POST http://localhost:8080/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"handle":"you","email":"you@example.com","password":"a-long-passphrase"}'
```

Email verification is required before publishing. In a dev setup the token is
logged at debug level and mailpit (http://localhost:8025) catches the message;
in production configure real SMTP.

If you enable the directory service below with
`AGENTRY_AUTH_EXTERNAL_ONLY=true`, this curl answers `410 Gone` by design —
accounts are then created on the sign-up page the directory service serves,
not through the native register endpoint.

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

## Deployment shapes

| Shape | What runs | Who it is for |
|---|---|---|
| **Single process** | `agentryd all` + Postgres | evaluation, small teams |
| **HA** | Helm chart: `api`×N, `git`×N (shared RWX volume), `worker`×N; a site in front is its own deployment | production self-host |
| **AWS reference** | the hosted service's Terraform, kept with the site (not in this repository) | mirrors how the hosted service runs |

The same binary serves every role; `agentryd api|git|worker|all` selects it.
The `git` role is the only one that needs repo storage mounted, and the
`worker` role is the only one that needs to reach the LLM provider. That is
what lets you give the scanning workers a no-egress security group.

Whatever `api` replicas must see alike lives in the database, not in any one
process: sessions, the job queue, and — since agentry#414 — the SAML sets, so
an assertion consumed by one replica is refused by every other and a login
started on one completes on another. Nothing has to be enabled for that;
Redis (`AGENTRY_REDIS_URL`) remains optional and unused by these. What is
still per process is the §19 rate-limit buckets, which an N-replica
deployment multiplies by N (the edge's limits are the ones that hold).

### The Helm chart

The chart in `deploy/helm/agentry` is published beside the image as an OCI
chart, signed with cosign like the image. Every push to `dev` and `main`
publishes `oci://ghcr.io/blaktron/agentry/charts/agentry` at a prerelease
version, `0.1.0-<branch>.<run>.g<sha>`, whose default image is the
`agentryd:sha-<sha>` built by the same run. A release publishes the tagged
version: a `main` release as chart `0.6.0` with image `v0.6.0`, a `dev`
prerelease as chart `0.6.1-dev.1` with image `v0.6.1-dev.1`. Only the newest
`main` release moves the image's `latest`. A released chart or image is signed
by the release workflow on its branch: pin
`--certificate-identity https://github.com/blaktron/agentry/.github/workflows/release.yaml@refs/heads/main`
(with `--certificate-github-workflow-repository blaktron/agentry`) to accept
only `main` releases. The regexp below also accepts the per-branch builds. The package is private while the
repository is, so pulling it needs a `read:packages` token, the same one the
image needs.

```bash
echo "$GHCR_TOKEN" | helm registry login ghcr.io -u <user> --password-stdin
cosign verify --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/blaktron/agentry/' \
  ghcr.io/blaktron/agentry/charts/agentry:0.1.0-main.57.g8420dcb
helm install agentry oci://ghcr.io/blaktron/agentry/charts/agentry \
  --version 0.1.0-main.57.g8420dcb -n agentry -f values.yaml
```

The values that make it installable on a cluster that is not the AWS
reference (added for the Vultr production cluster, DEV-124):

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
  worker (a version stays in `needs_review` for the moment in between;
  agentry#479). The chart refuses to render `kind: file` without the Secret.
- `objectStoreCredentials.existingSecret` — object-store credentials
  (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`), injected into the api and
  worker pods only; the git role never touches the store. A `v*` tag
  pushed there is recorded by the git role and its archive is stored by a
  worker, which rebuilds it from the recorded commit and stores it only if
  the digest matches (agentry#508). So the worker needs the git volume
  (`worker.mountGitData`, the default). A tag submission whose archive is
  not stored within two hours is rejected, and the publisher pushes a new
  version tag.
- `secret.existingSecret` (or the chart's own Secret) — each role gets only
  the keys it uses (agentry#744). The git role, which takes untrusted
  pushes, gets `AGENTRY_DATABASE_URL` and `AGENTRY_AUTH_SEALING_KEY`. The
  worker also gets `AGENTRY_KNOWLEDGE_SEALING_KEY`, `AGENTRY_SMTP_PASS` and
  `AGENTRY_IDP_ADMIN_TOKEN`: it sends the digest and billing mail, retries
  account erasure and scans knowledge packs. The api gets every key,
  including the directory's `AGENTRY_SOCIAL_AUTHENTIK_CLIENT_SECRET` and
  `AGENTRY_IDP_TRUST_CHECK_TOKEN`. With `config.auth.idpStaffMirrorGroup`
  set, every role gets the admin token too, because config validation
  requires it wherever the mirror is named. A key passed through the
  chart-wide `extraEnv` still reaches every role, so pass a secret through
  the role's own `extraEnv` instead. Settings that validation ties to a key
  must go the same way: `AGENTRY_IDP_STAFF_MIRROR_GROUP` in the chart-wide
  `extraEnv` stops the git role from starting (set
  `config.auth.idpStaffMirrorGroup` instead), and so does
  `AGENTRY_IDP_TRUST_CHECK_TOKEN` anywhere but `api.extraEnv`.
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
  "Bad address", agentry#495). The git role runs the hook once at startup
  and before every push, and refuses to start, or refuses the push, when it
  will not run; point it elsewhere only at a directory the server owns on a
  file system that allows exec.
- `api.extraEnv`, `git.extraEnv`, `worker.extraEnv` — environment for one
  role; `extraEnv` reaches every role.
- `podAnnotations` and `api.podAnnotations`, `git.podAnnotations`,
  `worker.podAnnotations` — annotations on the pods; a role's own win on a
  clash (agentry#745). A cluster autoscaler will not evict a pod with an
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
  `<release>-agentry-git` (agentry#627), so a pod's service-account token
  names the role presenting it: a service that authenticates pods by that
  token (the enterprise build's key service for hosted-run secrets binds
  encryption to the api's account and decryption to the worker's) can tell
  them apart. `serviceAccount.annotations` (an EKS IRSA role, say) goes on
  all three; an IAM trust policy written for the single account
  `<release>-agentry` the chart made before agentry#627 must name the three
  (or `<release>-agentry-*`) before the upgrade, or the roles lose their S3
  and KMS access. `serviceAccount.create: false` with `serviceAccount.name` runs
  every role under one existing account instead; `name` with `create: true`
  fails the render. The chart grants the accounts no Kubernetes RBAC: no
  role calls the Kubernetes API.

`scripts/acceptance/m7.sh` asserts that shape on every render: the git
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
  sealingKey: "<base64 32 bytes>"   # required outside dev; encrypts TOTP seeds
  cookieSecure: true

knowledge:
  sealingKey: "<base64 32 bytes>"   # optional; wraps knowledge packs' data keys (docs/knowledge.md); never auth.sealingKey

signing:
  kind: file            # file | kms, 'none' is refused in prod
  keyFile: /etc/agentry/signing-key.pem

# How the server presents itself and where browsers land (DEV-091).
web:
  url: ""               # a site fronting this server; unset = the server's own /ui/ pages
ui:
  mode: full            # full | authorize | off — the server's own browser surface
brand:
  name: ""              # emails, authenticator apps and /ui/ call it this (default: the public host)
  logoURL: ""           # optional; the /ui/ pages and the directory show it
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
  # (Brave's LLM Context API), tavily, exa or perplexity (their search APIs). The key stays in the registry and never
  # reaches a sandbox host.
  provider: none                      # AGENTRY_WEB_SEARCH_PROVIDER: none | youcom | brave | tavily | exa | perplexity
  # apiKey: ...                       # AGENTRY_WEB_SEARCH_API_KEY (required with a provider)
  # baseUrl: ...                      # AGENTRY_WEB_SEARCH_BASE_URL (empty is the provider's own:
  #                                   #   https://ydc-index.io for youcom, https://api.search.brave.com for brave,
  #                                   #   https://api.tavily.com, https://api.exa.ai, https://api.perplexity.ai)

scan:
  # The one external scanner tool behind the §8.3 seam. Optional: unset,
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
```

The scanning role needs egress to that database (one host); a worker that
cannot reach it leaves an `S7/osv-error` finding naming every declared
server version the registry holds no answer for, which routes the version to review
rather than through, on every submission until a lookup succeeds. A server
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

Git-tag publishes also have their **git history** scanned for secrets (§8.3):
S2 walks the added lines of every commit reachable from the tag, so a key
committed and later removed still surfaces as `S2/history-<rule>`. That needs
the scanning role to see the repository data directory — the compose stack's
single `all` role does; a separate worker without shared git storage reports
`S2/history-not-scanned` instead of implying a clean history.

A configured tool that cannot be found is a startup error, never a silent
fallback. A tool that fails mid-scan leaves an `S2/tool-error` finding on
the report, so "gitleaks did not run" is distinguishable from "no
secrets". The code-analysis stages that once ran opengrep and an OSV
dependency check were retired with the package kinds they served:
QuickAgents carry no tool code, and the MCP servers one declares are
resolved and pinned by the runner instead. Both ids are in use again — S6
is the support-scripts stage that reads a package's shell, Python and
JavaScript files against the manifest, and S7 the MCP server lookup above.

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
an instance or task role, not keys in this file. The hosted service's
Terraform provisions both the bucket and a key whose `kms:Sign` permission
is restricted to the worker task role.

An S3-compatible store that is not AWS takes its endpoint and path-style
addressing: `s3Endpoint` (for example `https://ewr1.vultrobjects.com`) and
`s3UsePathStyle: true`, which MinIO and Ceph RGW both need, with any region
name (`us-east-1`). `s3Prefix` puts every key under a prefix, so one bucket
can hold several stores. The restore drill uses it to read the backup copy's
`store/` in place.

**What has been verified, and where.** The `s3` backend has run against two
S3 implementations:
- MinIO, in the compose stack, on every dev deployment since the first.
- Ceph RGW, as Vultr Object Storage, in production. The Vultr plan's M3
  (agentry#450, 2026-09-23) proved there:
  - a publish end to end, with the archive round-tripped byte for byte;
  - the write-once conditional PUT answered `412` on a second write;
  - the attestation verified against the served key.

  Its M7 (agentry-web#212, 2026-09-24) served and verified a version from a
  copy of the store in a second region, through `s3Prefix`.

Signing with `kind: file` is what production runs: a P-256 key in a Secret
mounted by the worker pods only (DEV-129).

**Honest caveat:** AWS S3 and KMS signing have **not been exercised against a
live AWS account**. The AWS Terraform is validated but never applied, and the
build environment has no AWS credentials. The first deployment on AWS is
therefore also the first integration test of the `kms` signer and of S3's own
behaviour, such as its conditional-write semantics. If you are standing up
production on S3 and KMS, publish a throwaway version first and confirm that
the archive round-trips and `agentry verify` passes before you trust it with
anything.

### Social login

Individual accounts can sign in with Google, GitHub, Microsoft, OpenAI, or
Claude (§12.1). All are optional and independent: **a provider with no
client id is not offered at all**. Its start endpoint returns 404, so
probing cannot distinguish "misconfigured" from "not enabled".

```yaml
social:
  google:
    clientId: "…apps.googleusercontent.com"
    clientSecret: "…"
  github:
    clientId: "Iv1.…"
    clientSecret: "…"
  microsoft:
    clientId: "…"
    clientSecret: "…"
  openai:
    clientId: "…"
    clientSecret: "…"
    issuer: "https://your-oidc-issuer.example"   # required for openai/claude
  claude:
    clientId: "…"
    clientSecret: "…"
    issuer: "https://your-oidc-issuer.example"
```

Env: `AGENTRY_SOCIAL_<PROVIDER>_CLIENT_ID` and `_CLIENT_SECRET` per provider
(`AGENTRY_SOCIAL_MICROSOFT_CLIENT_ID`, …), plus `_ISSUER` for the OIDC
providers.

Register the callback with each provider as
`{baseURL}/api/v1/auth/oidc/{provider}/callback`, so `baseURL` must be
set correctly for social login to work at all.

`GET /api/v1/meta` lists the configured providers as `signInProviders`
(an empty list when there are none), so a front end offers them without
calling `/auth/oidc/{provider}/start`, which begins a flow and is rate
limited like any anonymous request (agentry#694).

Two behaviours worth knowing before you enable this (DEV-019, DEV-055):

- **Google and Microsoft are real OIDC**: discovery, issuer pinning, PKCE,
  ID-token signature and nonce verification. Google uses
  `accounts.google.com`; Microsoft uses the multi-tenant `common` endpoint
  by default (override `issuer` for a single tenant). **GitHub is an
  OAuth 2.0 shim**: there is no ID token to verify, so the trust anchor is
  TLS to `api.github.com` plus your client secret. There is no PKCE; a
  sealed single-use state cookie is what binds a callback to the browser
  that started it. An email is recorded only when GitHub reports it both
  primary *and* verified. **OpenAI and Claude publish no fixed consumer
  sign-in endpoints**, so they need an `issuer` pointing at an
  OIDC-compatible endpoint you operate or trust; without one they stay
  unoffered.
- **Social login is not a way around 2FA.** A redirect callback has nowhere
  to carry a TOTP code, so an account with 2FA enrolled receives a sealed
  five-minute challenge instead of a session, completed at
  `POST /api/v1/auth/2fa/totp/challenge`.

### Audit archive and retention

Every audit event is written to the `audit_events` table. It is partitioned
monthly and carries an append-only trigger: rows cannot be updated or
deleted, by anyone, including you. §12.6 additionally wants a
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
  wherever the server's lines are shipped — the log stack's `agentry-audit`
  index, for one. It is a mirror: the row stays the record.
- `s3` is **not implemented**. The constructor refuses at startup and names
  the bucket it was asked for, rather than silently dropping records
  (DEV-020). Use `file` plus your log shipper.
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
file reads all of these (and the directory service's `AUTHENTIK_EMAIL_*`
set) from `.env`, so switching both senders to a real provider is an `.env`
edit plus recreating the `server` and `authentik-*` containers. With
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

The §19 quotas are configuration (`limits.*`; the rate limits also as
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
one worker process runs at once per queue: 1 keeps the serial behaviour of
earlier releases; raise it on a worker with the memory for parallel scans.
A job that fails retries with exponential backoff up to five attempts, a
job a crashed worker held is rescued after 30 minutes, and every outcome is
counted (see Metrics). `queue.driver: pg` selects the earlier `SELECT … FOR
UPDATE SKIP LOCKED` implementation on the `jobs` table; it stays for one
release as a fallback and is not for new installs.

### Metrics

The API exposes Prometheus metrics at **`/metrics`**: HTTP request counts and
latencies by route and status, queue depth and job outcomes, scan stage
durations, and the Go runtime collectors. Scrape it from your own Prometheus;
there is no push path and no external dependency.

`/metrics` is unauthenticated and carries route-level operational data. There
is no agent content and no user identifiers, but you should still keep it off
the public internet. Bind the API's metrics exposure behind your ingress, or
scrape over the cluster network only.

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
files of 10 MB per container), so a stack without a log stack does not keep
logs forever; `docker logs` is the reader. The edge writes its access line
as JSON too — `event=http.access`, the `request_id` it minted and passed
upstream, the client address, method, path (never the query string),
status, bytes, timings, host, user agent — so with
`AGENTRY_PROXY_REQUEST_ID=true` one id names a request on the edge's line
and on every line and audit row the server writes for it.

**The log stack** — the rsyslog collector, the OpenSearch store and
OpenSearch Dashboards, from the `agentry-logging` repository — is an
optional profile applied over this stack as two more compose files. Every
container then ships its lines through Docker's `syslog` driver, over UDP
to a loopback port, in non-blocking mode: shipping is best-effort by
design. A collector that is slow, down or not yet up never stalls the
registry and never stops a container from starting; the price, measured,
is the lines sent while the collector was down, and about three in a
hundred at ten thousand lines a second (nothing at the registry's own
rates). The audit record does not depend on it. Retention is the stack's
knobs — `AGENTRY_LOGS_RETENTION_DAYS` (30), `AGENTRY_ACCESS_RETENTION_DAYS`
(14), `AGENTRY_AUDIT_INDEX_RETENTION_DAYS` (90) — while `audit_events`
keeps its rows for `audit.retentionDays`: Postgres is the audit record and
the store is the search copy.
OpenSearch needs `vm.max_map_count` of at least 262144 on the host
(Fedora ships more; Debian and Ubuntu ship 65530 and it refuses to start)
and about 5.5 GB of disk for the images. The repository's README carries
the rest.

### What the stack exposes

`/ui/` is the server's own browser surface (DEV-091): the device authorize
page `agentry login` and the desktop app open, and, on a server without a
site in front, sign-in, the account pages and the review, staff and
organization pages. The edge sends it to the API like `/api/`. The handle
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
reach every place they are used (the services, agentryd's DSN, authentik's
database, the bucket bootstrap). Set both before the first `up` on any
stack that is not a throwaway; on a stack that already has data, change
the stored password first (`ALTER USER agentry PASSWORD …` in Postgres,
`mc admin user` for MinIO) and then `.env`, since the volumes keep what
they were initialised with.

### Rate limits at the edge

agentryd applies the §19 per-IP limits to the API; the edge adds `limit_req`
zones (keyed on the resolved visitor address) for the routes that do work for
strangers: the sign-in page `/ui/login` and `/api/v1/auth/*` (30/min, burst
30), and the git endpoints (120/min, burst 60). Over the limit is `429` with
`Retry-After`. Tune the zones in `edge/nginx.conf`; a site's overlay adds
zones for its own forms; behind Cloudflare, mirror the same paths with a
rate-limiting rule so the edge is the second line, not the first.

### Running behind a proxy

Rate limiting (§19) buckets anonymous traffic per client IP. Behind a load
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
header says (agentry#429). Set both. With the hop count alone, the server
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
sudo tailscale cert --cert-file edge.crt --key-file edge.key <host>.<tailnet>.ts.net
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
and authentik read. Keep `AGENTRY_TRUSTED_PROXIES=1`; a direct connection
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
TLS to the edge verifies (see the beta readiness notes for the full list of
hostnames and the caching, WAF, and Access settings that matter). Running
`docker run … --token …` by hand holds the terminal because cloudflared runs
in the foreground; the service is the way to run it.

### The directory service (DEV-057)

The compose stack ships Authentik as the account directory: passwords,
MFA, recovery, and sign-up live there, and the registry consumes it as
the `authentik` OIDC provider while keeping sessions, PATs, and RBAC
native. The edge serves it as `auth.<your-domain>` and, when no such DNS
name exists (dev), on `https://<host>:8443`.

First boot, in `deploy/compose/.env`:

```bash
AUTHENTIK_SECRET_KEY=…        # openssl rand -base64 48
AUTHENTIK_BOOTSTRAP_PASSWORD=…   # akadmin's password
AUTHENTIK_BOOTSTRAP_TOKEN=…      # API token for the bootstrap script
AUTHENTIK_BOOTSTRAP_EMAIL=akadmin@example.com
```

then bring the stack up and run `scripts/dev/authentik-bootstrap.sh`
(idempotent — creates the OAuth2 provider `agentry-registry` and the
`agentry` application), and point the registry at the result. The provider
allows one grant, the authorization code (with PKCE), the only one the
registry uses. authentik 2026.8 made a provider's grants explicit: one the
API creates gets none and refuses every sign-in with `invalid_request`,
and one migrated from an older release gets all of them, including
`password` and `client_credentials`, which hand out tokens to anyone
holding the client secret, with no browser flow. Re-running the script
after such an upgrade narrows the provider (agentry#494).

```bash
AGENTRY_AUTH_EXTERNAL_ONLY=true
AGENTRY_SOCIAL_AUTHENTIK_CLIENT_ID=agentry-registry
AGENTRY_SOCIAL_AUTHENTIK_CLIENT_SECRET=…   # what you gave the bootstrap script
AGENTRY_SOCIAL_AUTHENTIK_ISSUER=https://<host>:8443/application/o/agentry/
AGENTRY_IDP_LOGOUT_URL=https://<host>:8443/flows/-/cancel/?next=/application/o/agentry/end-session/
```

The sign-out URL is the provider's `end-session/` endpoint wrapped in
authentik's cancel view. authentik answers an empty page, and does not sign
out, when the directory session still holds a flow plan (a flow the person
walked away from, for one); the cancel view drops that plan first and then
continues to `next` (agentry#441). The bootstrap script prints the value.

The bootstrap script attaches the `openid`, `profile`, and `email`
scope mappings to the provider — without them authentik issues an ID
token carrying `sub` alone and the registry can only create a placeholder
account (`<handle>@authentik.social.local`) instead of linking to the
existing one. For `email` it installs its own mapping, "Agentry:
OpenID 'email' (directory-verified)", asserting `email_verified: true`:
authentik's managed mapping hard-codes `false` (2026.8), and the
registry's auto-link rule (T-12) only links an IdP identity to an
existing account when *both* sides' addresses are verified. That
assertion is sound exactly when authentik is your directory of record —
accounts are created by operators, provisioned from an upstream
directory, or enrolled through a flow with an email-verification stage.
If you allow self-enrollment without one, drop that mapping and accept
that such accounts start as new registry users.

**Platform staff is membership of the staff organization.** Name the
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

The rule rests on facts nobody sets about themselves:

- **Membership** is granted by the organization's admins.
- **The organization itself** can be founded only by platform staff.
- **A stored address** changes only at erasure (SCIM refuses a change, and
  the directory denies self-service changes, DEV-134).

An address counts as verified when the registry's mailed link was
followed, the directory or a social provider asserted it at sign-in, an
invitation at an organization's verified domain was accepted, or an
organization's SCIM provisioned it. So an address at the staff domain in
the registry is not proof by itself that its holder controls the mailbox.
It is the membership an admin grants that makes staff.

A registry-side service account needs an address at the domain and a
membership like anyone else. With neither key set, nothing syncs and
existing flags stay as they are.

**The directory's mirror of platform staff** (agentry#598). An application
that signs in through the directory and should admit staff alone, such as
the log stack's OpenSearch Dashboards, can read only what the directory's
tokens carry. Set `AGENTRY_IDP_STAFF_MIRROR_GROUP` (the chart's
`config.auth.idpStaffMirrorGroup`), say `agentry-staff`, and the registry
keeps that directory group equal to its platform staff: for every active
account with the flag and a verified address, the directory account it
signed in with, and nobody else. That account is the registry's own record
of the person's directory sign-in (its subject, which is authentik's `uid`
under the `hashed_user_id` subject mode the bootstrap script sets). It is
found by address and added only when its `uid` matches and the account is
active, so a second directory account at a staff member's address gains
nothing. It needs the
staff organization and `AGENTRY_IDP_ADMIN_URL`/`AGENTRY_IDP_ADMIN_TOKEN`,
which it writes the group through; the token needs rights over groups as
well as users. The group is a mirror, never a source of staff: anyone
added to it in the directory by hand is removed at its next run, and each
change the registry makes is audited as `directory.staff_mirror`. It runs a
few seconds after any staff change, every ten minutes, and soon after the
server starts. So a removal reaches the directory within seconds when the
directory answers. While runs fail (the directory unreachable from the
registry, or an admin token without rights over groups), a removed member
keeps the group until a run succeeds: every failure is logged, and runs are
retried every ten minutes. A directory
session or an application session already open is not ended by it. Staff
who have not yet signed in to the registry through the directory are added
after their first such sign-in.

`scripts/dev/authentik-bootstrap.sh` makes the Dashboards side when
`AGENTRY_DASHBOARDS_URL` is set (idempotent, like the rest):

- the mirror group (`AGENTRY_IDP_STAFF_MIRROR_GROUP`, default
  `agentry-staff`; give the server the same value);
- a `roles` scope mapping whose claim is `["agentry-reader"]` for a member
  of that group and `[]` for anyone else;
- the OAuth2 provider `agentry-dashboards` (authorization code only,
  redirect `<url>/auth/openid/login`) and its application, which admits
  members of the group alone. The application uses an expression policy
  rather than a group binding, because authentik deletes a group's
  bindings along with the group, and the expression then fails closed. Its
  policy engine mode is `all`, so a policy bound later cannot admit anyone
  by itself;
- the client id and secret, written to `AGENTRY_DASHBOARDS_SECRET_FILE`
  (default `~/.config/agentry/dashboards-oidc.env`, mode 0600, outside any
  checkout) and never printed. A re-run keeps the secret in an existing
  file.

It prints the provider's OpenID configuration URL, which the log stack's
Dashboards takes (agentry-logging#49).

**Moving a deployment onto the rule, in this order.**

1. Make sure the staff organization exists, founded by an account that is
   staff under the old rules.
2. Give every account meant to stay staff (operators, service accounts) a
   verified address at the domain and an active membership.
3. Set both keys and restart.

The first start recomputes every flagged account: anyone not yet a member
loses staff, audited. If nobody is a member, nobody is staff, and only an
operator writing to the database can seed the first one again.

The directory group (`AGENTRY_IDP_STAFF_GROUP`) and the domain-alone rule
(`AGENTRY_IDP_STAFF_DOMAIN`) are retired: they grant nothing, and the server
logs a warning at start-up while either is set.

**Provisioning org members from Authentik (SCIM).** The registry's SCIM
endpoint is per organisation and authenticated by a token an org admin
mints (`POST /api/v1/orgs/{org}/scim/tokens`, or the org admin console).
In Authentik create a *SCIM provider* with URL
`https://<host>/scim/v2` and that token, attach it to the `agentry`
application as a backchannel provider, and scope it to the group(s) that
should become org members. Users then arrive as **pending** members and
Authentik groups as teams: the IdP says who exists, an admin says who is a
member, so each provisioned person waits for an approval (which is also
where their seat is taken) and holds nothing of the organisation until
then. Declining removes them. The registry keeps ownership of roles. A single Authentik
instance can provision several orgs — one SCIM provider per org, each
with its own token. This is deliberately not a blueprint: the token is
org-scoped and minted by the org, not by the platform.

The Helm chart carries the same knobs (`config.auth.externalOnly`,
`config.social.authentik`, `config.auth.staffOrg`,
`config.auth.staffDomain`,
`config.idp.logoutUrl`, `secret.authentikClientSecret`,
`secret.idpAdminToken`); the hosted service's Terraform (kept with the
site) carries them as `idp_client_id`, `idp_issuer` and `idp_logout_url`,
with the client secret in Secrets Manager; its `idp_staff_group` is retired
with the group (agentry#556).

**Account flows.** `deploy/compose/authentik/blueprints/agentry-account-flows.yaml`
is mounted into authentik as a blueprint and applied automatically on
boot. It defines both self-service routes and the controls on them, and
adds the "Sign up" and "Forgot username or password?" links to the login
page:

- **Sign-up** — CAPTCHA, then a form (username, display name, email,
  password), then the account written **inactive**, then an emailed
  confirmation link that activates it, then sign-in. Writing the account
  inactive is what makes the directory-verified `email` assertion above
  honest for self-enrolled users: no account is active, and so none
  reaches the registry, before its address is confirmed. The username
  becomes the registry handle at the first sign-in, so the form refuses
  one that is not a valid handle (lowercase letters, digits and hyphens,
  at most 39) or that the registry reserves for its own paths and names
  (agentry#590). Users created in the directory some other way are not
  checked; the registry maps such a username to a valid handle and
  records the one asked for (DEV-142).
- **The promo code field** (agentry#759) — an optional field at the end of
  the sign-up form, shown only when `AGENTRY_DIRECTORY_PROMO_FIELD` is set
  to any non-empty value in the directory's environment (the worker reads
  it when it applies the blueprint; compose passes it through, empty by
  default). Leave it unset unless an extension redeems codes: the core
  attaches no meaning to one. Off, the field is a hidden input, and
  authentik resets a hidden field to its empty default whatever is posted.
  On, the form holds a code to 4–32 letters, digits and hyphens, writes it
  to the account's `agentry_promo_code` attribute (so it survives a
  confirmation link opened on another device), and fills it in from the
  page's `?promo=` when the flow is opened as
  `/if/flow/agentry-enrollment/?promo=CODE`. The `agentry` scope sends it
  as the `agentry_promo_code` claim, and the registry passes it to its
  extensions as `promoCode` in `user.registered`, upper-cased, only on the
  sign-in that creates the account and only from the directory's token.
- **Password recovery** — identification, an emailed reset link, then a
  new password. The identification stage runs with `pretend_user_exists`,
  so an unknown address gets the same answer a real one does and the form
  cannot be used to discover who has an account. Recovery deliberately
  does **not** activate an inactive account, unlike the confirmation
  above: an operator-deactivated user must not be able to reactivate
  themselves by requesting a reset.
- **The two mails** (the sign-up confirmation and the reset link) are the
  core's own templates in `deploy/compose/authentik/templates/agentry/`,
  mounted read-only at `/templates`, not authentik's stock ones: they say
  Agentry and use the core's palette. Their header shows the Agentry mark
  inline (agentry#720): the HTML names `cid:logo`, and authentik attaches
  the PNG at its logo path, `/web/dist/assets/icons/icon_left_brand.png`,
  where the compose file mounts the core's
  `deploy/compose/authentik/brand/mail-logo.png` in the server and the
  worker. Nothing is a remote image. A deployment that sets
  `AGENTRY_BRAND_NAME` to another name mounts its own copies of those
  files, and its own logo, at the same paths (the subjects already follow
  the variable). An authentik upgrade that moves its logo path would
  attach authentik's own logo instead, so check the path in the new
  image's `authentik/stages/email/utils.py` when bumping it. The logo is a
  single-file bind mount, so a changed PNG reaches authentik only when the
  server and the worker are recreated (`up -d --force-recreate --no-deps
  authentik-server authentik-worker`).
  `scripts/acceptance/directory-email.sh` renders the mails in the pinned
  image and checks that the attached logo is the core's.
  Before agentry#518 `/templates` was an empty named volume,
  `authentik-templates`; a stack upgraded from then keeps that volume
  unused (`docker volume rm <project>_authentik-templates` removes it),
  and a template an operator had put in it is no longer mounted.
- **No authentik device cookie.** authentik's User Login stage writes its
  own "known device" cookie, `authentik_device`, for 30 days by default. It
  is a signed token the directory keeps no record of: it cannot be listed,
  cannot be revoked per browser, and survives a password change, a logout
  and a rotation of `AUTHENTIK_SECRET_KEY`, because its key derives from the
  installation's identifier and the stage. The blueprint sets
  `remember_device: seconds=0` on every login stage, the sign-in's,
  sign-up's and recovery's and authentik's two source stages, so the
  directory never writes it
  (agentry#460). A cookie written before that change is not revoked, since
  nothing can revoke it: it expires within its 30 days, and nothing in
  Agentry reads it. authentik also uses the cookie to refresh a person's
  other open sign-in tabs once they have signed in, which no longer
  happens. The one browser credential is the remembered browser
  below, which the registry records and a person can clear. Leave each
  stage's `remember_me_offset` at zero as well: above zero authentik shows
  its own "Remember me" box beside the remembered-browser one, and a login
  made with that box's answer never writes the device cookie at all, so
  the two settings interact without saying so.
  `TestDirectoryIssuesNoDeviceCookie` fails if a login stage is added to
  the blueprint, or changed in it, without both; a stage made in the admin
  interface or by an example blueprint is not covered.
- Both forms enforce the **same password policy** (12 characters minimum
  plus a zxcvbn strength score), because a password chosen during a reset
  should be held to the same bar as one chosen at sign-up. There is no
  Have I Been Pwned lookup: it needs egress from the container, and an
  outage there would block sign-ups and resets outright.

To run invite-only instead, delete the blueprint file (or disable its
instance in authentik's admin UI); operator-created accounts are
unaffected. Both mails go through authentik's own SMTP settings
(`AUTHENTIK_EMAIL__*` — mailpit on the dev stack), which are separate from
the registry's `AGENTRY_SMTP_*`.

**Abuse controls on those flows.** Two layers, and the defaults are not
production values:

- A **CAPTCHA** stage guards sign-up. It ships configured for Cloudflare
  Turnstile using Cloudflare's published *test* keys, which always pass —
  that keeps a dev stack working out of the box and stops nobody. Set
  `AUTHENTIK_CAPTCHA_SITE_KEY` and `AUTHENTIK_CAPTCHA_SECRET_KEY` (compose
  passes both through) before opening sign-up to the internet;
  `AUTHENTIK_CAPTCHA_JS_URL` / `_API_URL` point it at a different provider.
- A **per-IP rate limit** caps how much work one address can cause: at most
  10 accounts created plus mails sent per hour, counted from authentik's
  own event log. Ordinary use costs 2 (an account and its confirmation
  mail) to sign up and 1 to reset a password, so the budget is generous for
  a shared office address while ending bulk account creation. Raise or
  lower `MAX_PER_HOUR` in the blueprint to suit your users. Recovery also
  keeps authentik's own per-user control on the email stage
  (`recovery_max_attempts`, `recovery_cache_timeout`); the per-IP limit is
  what stops one source mailing a thousand different victims.
  The policy **fails open** on an unexpected error (a broken counter must
  not become an outage on the only route into the product); the failure
  shows up in authentik's event log as a `policy_exception` event, which
  is the thing to alert on — the registry's `FailOpenEvents` metric covers
  the registry's own fail-open paths, not this one.

`AUTHENTIK_ACCOUNT_FLOW_MAX_PER_HOUR` sets that budget (default 10):
compose passes it through, and the blueprint formats it into the policy at
apply time. Enrollment ends with authenticator (TOTP) setup, and recovery
verifies the authenticator before the password may change — a user who has
none is sent through the same setup stage. Lost-authenticator recovery is an
operator action in the Authentik admin UI; email alone never resets both
factors.

Sign-in from a browser runs in the API's browser mode: the server's
`/ui/login` (or a site's own sign-in page) forwards to
`/api/v1/auth/oidc/authentik/start?next=<path>` and the callback answers
a 303 back to that path (or to the sign-in page with `?error=…`) once the
session cookie is set; without `next` the same callback returns the JSON
result the CLI and tests consume.

With `AGENTRY_AUTH_EXTERNAL_ONLY=true` the native register, password
login, email-verify, and TOTP endpoints answer 410 Gone, and the web
login page offers the directory service only. Turning the flag off (the
default) restores the native flows — nothing was removed.

**How a person signs in, on the settings page.** With the same admin URL
and token, `GET /api/v1/user/directory` also reports the social provider
the caller's directory account was first connected to
(`firstSocialProvider`) and whether it has a password (`hasPassword`), so a
front end can say "Signed up with Google" and offer "Add a password". For
these two fields the account is the one carrying the caller's linked
directory `uid`, never one found by address alone, since authentik does not
keep addresses unique. Only OAuth sources count as a social provider. The
provider comes from authentik's OAuth source connections, so the token
needs to view them (`authentik_sources_oauth.view_useroauthsourceconnection`)
as well as users.
The password answer is the account's `agentry_has_password` attribute,
which the account-flows blueprint's `agentry-record-has-password` policy
keeps: set when a flow writes a password, refreshed from the account at
every sign-in (an account a social provider created holds an empty
password, which counts as none). authentik's API has no such field, and
its property-mapping test endpoint, the other way to ask, needs the right
to create property mappings for any token that is not a superuser. Until an
account has signed in or written a password under this blueprint the field
is absent, and so is either field when the directory does not answer.

**Account erasure spans both systems.** `POST /user/delete` pseudonymizes the
registry account (§12.7); the sign-in account — email, display name,
password hash — lives in authentik. Set `AGENTRY_IDP_ADMIN_URL` (the API
origin as the server reaches it: `http://authentik-server:9000` on the
compose stack) and `AGENTRY_IDP_ADMIN_TOKEN` (an authentik API token with
rights over users, and to view OAuth source connections for the settings
page below; the bootstrap token works) and erasure also deletes the
person's directory account — never a superuser or a service account. The
account is the one the directory's own id names, which the registry records
on the person's directory identity at every sign-in (the `agentry` scope's
`agentry_directory_id` claim, below), confirmed by its `uid`; for an
identity that has not signed in since, the account at the registry's
address carrying that `uid`; and for an account that never signed in
through the directory, the account at its address only when exactly one
account holds it (authentik does not keep addresses unique). The settings
page's authenticators and sign-in facts read the account by the same rule
(agentry#727). Each attempt is recorded as its own `user.directory_erase` audit
event (`deleted`, `not-found`, `unresolved`, `failed`, `not-configured`, or
`abandoned`, with `directoryLookup` naming the rule each linked account was
found by),
beside the `user.delete` event, and the erasure's 204 carries the
outcome in the `X-Agentry-Directory-Erasure` header. A failure does not undo the registry
erasure: the request answers `pending` and a `gdpr.directory_erase` job on
the worker retries with backoff (fourteen attempts, about four and a half
hours; the queued address is sealed with the sealing key) until the
directory deletes the account or finds none (agentry#499). When the
retries run out the last attempt is audited `abandoned` and the server
logs `failopen.directory_erasure` at ERROR and counts
`FailOpenEvents{path="directory_erasure"}`: alert on either, then delete the
sign-in account in authentik by hand. An erasure that could not tell the
person's directory account apart (two accounts at the address, a recorded
account id that now names an account with another `uid`, or a superuser) is
`unresolved`: nothing is deleted, it is not retried, and it is raised the
same way. Leave the variables unset and the privacy
policy's promise that deletion removes personal information is one you
have to keep manually.

**Two-factor authentication and public publishing.** Outside dev mode the
registry normally refuses to publish to a public namespace until the
account has a TOTP factor (§12.1, §19). With the directory service in
charge no account can enrol one — the native TOTP endpoints are the ones
answering 410 — so that gate is **off under `externalOnly`** and the
requirement is yours to enforce in authentik. Bind an MFA policy (or an
authenticator-validation stage) to the authentication flow or to the
`agentry` application, which also covers sign-in itself rather than only
publishing.

To turn trust back into evidence, set `AGENTRY_AUTH_REQUIRE_IDP_MFA=true`.
The gate is then on under `externalOnly`, and it is satisfied when the
account has signed in at least once with an ID token whose `amr` claim (RFC 8176)
names a second factor — `mfa`, `otp`, `hwk`, `webauthn` and the like, never
`pwd` alone — which the registry records as `users.idp_mfa_at`. authentik
emits `amr` on its ID tokens; check one sign-in's token (or the
`user.login` audit row) before enabling the flag, because with it on and a
directory that never asserts a factor, nobody can publish publicly.

With the same flag set, an organization's own SSO connection is evidence
too. When a member signs in through the organization's SAML or OIDC
connection and the validated assertion says a second factor was used, the
registry stamps `users.idp_mfa_at` as it does for the directory. Only with
the flag, because the organization's IdP belongs to that organization's
admins, not to you, and the stamp is account-wide and kept. With the flag
off, the gate asks for native TOTP, and an organization's claim never stands
in for it. For OIDC the evidence is the ID token's `amr`, by the list above. For SAML
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

**Remembering a browser that answered the second factor.** On a deployment
running the native flows — `AGENTRY_AUTH_EXTERNAL_ONLY` unset or false —
`POST /api/v1/auth/login` accepts a `rememberDevice` flag. Set on a sign-in
that actually answered a TOTP code, it issues an `agentry_trusted_device`
cookie and records the browser; a later password sign-in presenting that
cookie is not asked for the code. The flag defaults to false, and nothing is
remembered unless it is asked for.

The credential is narrow on purpose. It skips the second factor and nothing
else: the password is still required at every sign-in, it is not a session, it
does not lengthen one, and it carries no scope. Its lifetime is absolute —
using it does not extend it — so it expires `AGENTRY_AUTH_TRUSTED_DEVICE_TTL`
after it was issued. That defaults to 30 days, and 30 days is also the ceiling:
a larger value is refused at startup rather than honoured, because a deployment
that raised it would be issuing a credential the threat model never priced in.
Only the token's SHA-256 is stored, beside the issuing address and user agent;
those two are recorded so that a page listing remembered browsers can describe
them to their owner, and neither is consulted in the decision. A lookup that
cannot be answered — an outage, a revoked record, an expired one, somebody
else's — demands the code rather than skipping it.

A remembered browser is a second credential class, not a longer session:
§12.4's 24-hour cap still binds every session, and a `trusted_devices` record
lengthens none of them.

**Withdrawing it.** `GET /api/v1/user/trusted-devices` answers how many live
remembered browsers the caller's account has, and `DELETE` on the same path
revokes all of them, this browser's included, and clears this browser's
cookie (agentry#672). Both are for a session: a personal access token reads 0
and is refused the clear. There is no list and no per-browser removal; the
hosted site offers the clear as one "Clear remembered devices" button. Account
erasure deletes the account's records in the erasure transaction
(`handlers_gdpr.go`), and SCIM deactivation revokes them. Every lookup ignores a
record past its expiry, and an hourly sweep on the worker role
(`trusted_device.sweep`, agentry#464) deletes those rows, with the address and
user agent they hold. A revoked record is kept until its own expiry, inert,
and swept then. Signing out, and "sign out everywhere else", leave remembered
browsers alone: surviving them is the point, and the clear above is the
control that ends them.

On the native path nothing mints one unless asked: the flag is per-request and
no shipped client sends it, so a record is only created by an API call that
asks for one.

**Remembering a browser on the directory's sign-in.** Under
`AGENTRY_AUTH_EXTERNAL_ONLY=true` the native login answers 410 and the
directory asks for the second factor, so the choice and the skip both happen
there (agentry#670, DEV-163). The registry keeps the same record, with the same
lifetime, ceiling and fail-closed lookup:

- **Minting.** The registry asks the directory for one more scope, `agentry`.
  The directory's flow shows "Remember this device for 30 days" on its code
  page (unticked), and its `agentry` scope mapping passes the choice back as
  the ID-token claim `agentry_remember_device`. On the OIDC callback the
  registry mints a record only when that claim is `true`, the token's `amr`
  names a second factor, **and** its `auth_time` is within five minutes. The
  last matters because a live directory session answers a later sign-in
  silently, repeating the claim and the `amr` of the sign-in that started it;
  only `auth_time` shows it is old. So a sign-in whose code was skipped, or
  never asked, cannot extend its own trust. The cookie is httpOnly and scoped
  to the directory's flow executor (`Path=/api/v3/flows/executor/`); no route
  of the registry reads it. The `user.trusted_device_add` row carries
  `"via": "directory"`.
- **The check.** Before asking for the code, the directory's flow calls
  `POST /internal/directory/trusted-device` with `{token, sub}` and the bearer
  secret `AGENTRY_IDP_TRUST_CHECK_TOKEN` (at least 32 characters; the
  directory holds the same value). The answer is `{"trusted": true}` only for
  a live record owned by the active account linked to that directory subject;
  anything else is `false`, and a store that cannot answer is a 503, which
  the directory treats as "ask for the code". A `true` records the use
  (`last_seen_at`, and a `user.trusted_device_use` audit row) before it is
  given. The route answers 404 while the secret is unset.
- **Keep `/internal/` private.** The route is for the directory on the private
  network, calling the api directly. The compose edge answers `/internal/`
  with 404, and the server itself answers 404 to any request carrying
  `X-Forwarded-For` or `Forwarded`, which is what an ingress or a proxy in
  front of the api adds. So a directory that reaches the api through a proxy
  of its own is refused too, and asks for the code.
- **The cookie's domain.** The registry sets the cookie on the callback, at
  `AGENTRY_PUBLIC_URL`'s host, and the directory has to receive it. A
  directory on the same host (another port) gets a host-only cookie; one on a
  subdomain of the registry's host (`auth.example.com` under
  `example.com`) gets a cookie for the registry's host. For sibling hosts set
  `AGENTRY_AUTH_DIRECTORY_COOKIE_DOMAIN` to a parent domain of both. A
  configuration that cannot work is refused at startup. A parent-domain
  cookie reaches every host under that domain at the executor's path, not
  only the directory: if a staging or development deployment runs under the
  production registry's name, production's tokens reach its directory too.
  Keep such deployments on a name of their own, or accept that they receive
  those tokens (the hosted deployment accepts it, DEV-163).

The directory's half ships with the compose stack (agentry#671):

- **The checkbox.** `deploy/compose/authentik/templates/if/flow.html` is
  authentik's own flow page, byte for byte, plus one marked block that draws
  an unticked "Remember this device for 30 days" on the code page. authentik
  reads it from the `/templates` mount the mails already use. The box is
  offered on the sign-in flow only. A ticked box becomes a ten-minute
  `agentry_remember_intent` cookie on the directory's host, `__Host-`
  prefixed on https so no other host under the same parent domain can set
  it, and every load of the flow page clears it. The label says 30 days, the
  default and the ceiling; a deployment that shortens
  `AGENTRY_AUTH_TRUSTED_DEVICE_TTL` should change the label to match.
- **The claim.** The account-flows blueprint's `agentry-remember-intent`
  policy, on the sign-in's login stage, copies that choice into the sign-in's
  record, but only when a second factor was validated in the same flow. Its
  `agentry-remember-device` scope mapping answers the `agentry` scope with
  `agentry_remember_device`, and with `agentry_directory_id`, the signed-in
  account's directory id, which the registry records on the identity and
  reads the account by (agentry#727). `scripts/dev/authentik-bootstrap.sh` attaches the
  mapping to the registry's provider; re-run it once after upgrading.
- **The skip.** The blueprint's `agentry-remembered-browser-skip` policy, on
  the sign-in's MFA stage, calls the check before the code page. It reads
  `AGENTRY_IDP_TRUST_CHECK_TOKEN` and `AGENTRY_REGISTRY_INTERNAL_URL`
  (default `http://server:8080`) from the directory containers' environment
  when it runs, so the secret is never stored in the directory's database. It
  skips the code only on the registry's explicit `trusted: true`. The
  blueprint restates the MFA binding in policy mode `all`, and binds the
  policy with `failure_result: true`. Without both, the stock passwordless
  policy would hide the skip, and a policy error would skip the code. Do
  not run the directory with `AUTHENTIK_DEBUG` where the secret matters:
  authentik's debug HTTP session logs outgoing requests with their headers.

With the secret unset on either side, the code is asked every time. After an
authentik upgrade, re-copy the new image's `flows/templates/if/flow.html`
above the marked block: `scripts/acceptance/directory-remember.sh` fails
until the two match, and it also checks that the code stage the block writes
into still exists. The checkbox is not offered on a passkey sign-in or on
authentik's simplified flow page for old browsers, which asks for the code
as before. The directory's own remember-this-device behaviour is a
different thing and is not used: it keeps no server-side record of the
browsers it remembers, so they could be neither cleared nor individually
revoked (agentry#460).

The directory's flows are unbranded here and call the deployment
`AGENTRY_BRAND_NAME`; a site that fronts the registry applies its own
brand (title, wordmark, favicon, flow background, custom CSS) through the
directory's API — the hosted site's repository carries that script and
stylesheet (DEV-091).

**Upgrading the directory service.** Authentik refuses to skip a release
line: every `YYYY.M` line between the running version and the target
must be passed through in order, and the check runs before any migration
(a refused container crash-loops with "Major version skips are not
allowed" and leaves the database untouched). So to move, say, 2025.6 →
2026.8 the path is 2025.12 → 2026.2 → 2026.5 → 2026.8: `pg_dump` the
`authentik` database first, then for each hop set the image tag in
`docker-compose.yaml`, `docker compose --profile server up -d
authentik-server authentik-worker`, and wait for the server container to
report healthy before the next hop. Finish by restoring the committed
tag+digest pin (bump it when the target is new) and `docker image prune
-a` — each hop's image is ~1.4 GB and a full chain has filled a small
root volume. The registry needs no restart: the OIDC issuer, client, and
brand ride the database.

**The directory stays behind the scenes.** Nobody browses it directly:
the edge sends `auth.<site>/` and the directory's user panel
(`/if/user/…`) back to the site, and the registry's Settings page is
where a person changes their password, adds an authenticator app or
security key, or removes one — each is one short step in the directory
that returns to Settings. For that the directory needs to know the site.
Two variables tell it where its flows return (DEV-091): sign-out lands on
`AGENTRY_PUBLIC_WEB_URL` and a password change or an authenticator
enrolment on `AGENTRY_ACCOUNT_URL`. Both default to the server's own pages
(`<AGENTRY_PUBLIC_URL>/ui/` and `…/ui/account/directory`); a site in front
sets them to its home and its Settings → Authentication page. The flows'
titles and mail subjects call the deployment `AGENTRY_BRAND_NAME`
(default `Agentry`). `AGENTRY_PUBLIC_WEB_URL` (the same value the registry
uses) is passed to the `authentik-*` containers and read by the
account-flows blueprint.
`scripts/dev/authentik-bootstrap.sh` points the application's launch
URL at the registry's sign-in start and the brand's default application
at it, so a sign-in, sign-up or recovery that ends without a return lands
in the app signed in. Sign-out goes through the blueprint's
`agentry-invalidation` flow, which ends the directory session and
redirects to the site; `AGENTRY_IDP_LOGOUT_URL` is the provider's
`end-session/` endpoint wrapped in authentik's cancel view (above). The
password-change and authenticator flows return to `AGENTRY_ACCOUNT_URL`
through the flow plan's `redirect`, set by the blueprint's
`agentry-return-to-settings` policy, not through a redirect stage: a
redirect stage leaves the flow's plan parked in the session, and the next
sign-out then answers an empty page (agentry#441). The blueprint also
unsets the brand's user-settings flow. Re-run the bootstrap script after
upgrading a deployment that predates this (agentry#164).
`scripts/acceptance/directory-signout.py` proves sign-out against a live
directory — after a fresh sign-in, after an abandoned authenticator flow
and after a completed one — with a throwaway user it deletes on the way
out; it needs the directory's URL, the bootstrap token and
`AGENTRY_ACCOUNT_URL`.

Nobody changes their own directory email. The registry links accounts by
the address the directory holds, and the provider asserts it verified, so a
self-service change would let a person sign in as whoever owns the address
they typed. authentik's own `default-user-settings-flow` has an email field
and stays reachable by URL even with the settings panel unset; the only
thing refusing a change there is the system setting "Allow users to change
email" (off by default), which blueprints cannot pin. The account-flows
blueprint therefore binds a policy that always denies to that flow
(agentry#490): nobody can run it, whatever the setting says. Display name
and handle are the registry's; an operator who must correct an address
does it in the directory's admin console, and should confirm the new
address belongs to the person first.
`scripts/acceptance/directory-user-settings.py` proves the refusal against
a live directory with a throwaway user it deletes on the way out; it needs
the directory's URL and the bootstrap token, and never changes the system
settings.

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
The Windows artifacts are Authenticode-signed since desktop 0.5.0 (D-032):
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
readable at `/api/v1/platform/policy`. Defaults: findings up to `low`
auto-publish, `medium`/`high` go to review, `critical` is rejected, wildcard
network egress goes to review.

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
thresholds only move down.

Three notes on the knobs:

- `blockedMcpServers` rejects a submission whose manifest declares one of the
  listed MCP servers (`npm:<package>` / `pypi:<package>`, `path.Match` globs
  such as `npm:@evil/*`); it unions across baseline and org like
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
  identifiers are refused for public publish.

## Organizations

An organization is a namespace with members. Anyone with a verified
address creates one from the organizations page (`/ui/orgs`; `POST
/api/v1/orgs`) and becomes its first **admin**; the other role is
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
organization's page; a verified domain also belongs to one organization.

An admin **decommissions** the organization from its page by typing its
handle. It is then read-only for its members for the hold below, and
when the hold ends a sweep yanks its releases, deletes its archives and
repositories, ends every membership and releases its handle and domain.
Platform staff can **suspend** an organization from the same page — it
and everything under it answer as absent, over the API and over git and
to staff too, until reinstated — and **reinstate** one, which also
cancels a hold that has not run. Because a suspended organization's page
is absent as well, the staff console (`/ui/staff`) carries suspend and
reinstate by handle.

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
- **A new ruleset rescans the catalogue.** Registering a ruleset semver for the
  first time enqueues the §8.7 sweep automatically; the rescan sweep quarantines
  versions that newly trip a high or critical finding.
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

None of that is different from the hosted service; self-hosting makes it
visible.

## SSH git transport

Besides smart HTTP, the `git` and `all` roles serve `ssh://git@<host>:<port>/<ns>/<name>.git`
when `AGENTRY_GIT_SSH_ADDR` is set (the compose stack sets `:2222` and publishes it on the
host as `${AGENTRY_SSH_PORT:-2222}`; unset it to switch the transport off). Only
`git-upload-pack` and `git-receive-pack` are served — no shell, no forwarding — through the
same authorization, hooks and quotas as HTTPS.

- **Credential:** a user's SSH public key, registered on the settings page (or
  `POST /user/ssh-keys`). A key is worth repository read/write and the release tag the
  user's role allows; it never reaches the API. There is no anonymous mode over SSH.
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

Everything above is a complete registry. The hosted service puts a site in
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
- **`ui.mode` / `AGENTRY_UI_MODE`** — `full` serves every `/ui/` page,
  `authorize` keeps only the device-authorize page the CLI and the desktop
  app open (the site provides the rest), `off` serves none. A site in front
  normally runs `authorize`.
- **`brand.*` / `AGENTRY_BRAND_NAME`, `AGENTRY_BRAND_LOGO_URL`,
  `AGENTRY_BRAND_CSS_URL`, `AGENTRY_SUPPORT_EMAIL`, `AGENTRY_SECURITY_EMAIL`**
  — what the server calls the deployment in emails, in the directory's flow
  titles and authenticator names, and on the `/ui/` pages that remain; the
  stylesheet and logo the remaining pages load. `GET /api/v1/meta` reports
  `brand` and `ui` (with `authorizeUrl`) so clients need no other
  configuration.
- **The directory's returns** — `AGENTRY_PUBLIC_WEB_URL` (where sign-out
  lands) and `AGENTRY_ACCOUNT_URL` (where a password or authenticator change
  returns) default to the server's own pages; a site sets them to its home
  and its settings page, and applies its own brand object to the directory
  through the directory's API (the flows stay the core's blueprint).
  `AGENTRY_IDP_LOGOUT_URL` is the provider's end-session endpoint behind
  authentik's cancel view (agentry#441).
- **The edge** — a site replaces `edge/nginx.conf` with one that sends
  `/api/`, git, `/ui/` and `/downloads/` to the server and everything else to
  the site, and adds rate-limit zones for its own forms.

In compose that is one overlay file: a second `-f` that adds the site's
services, replaces the edge config, and sets the variables above; the core
stack is untouched. The site talks to the same API as the CLI, with the
browser's session cookie, under the same authorization matrix — a front end
cannot do anything the API refuses, and the server's own `/ui/` pages are the
proof that the API is enough.

A closed build can also extend the server itself: `pkg/extension` lets an
outside Go module mount routes under `/api/v1/x/<name>/`, run its own
migrations in its own schema, replace the entitlements resolver (limits and
the caps `Features` answers, such as a private-agent cap), subscribe to
committed events and add worker jobs, with `GET /api/v1/meta` listing what is
loaded. An extension may also admit or refuse a submission after every core
check and before anything is stored (`Admits`), name a route of its own
the anonymous rate class skips (`Unthrottles`: a payment provider's signed
webhook), receive the database pool, the logger and an audit writer at
start-up (`Binds`), delete the rows it keeps about a person inside the
account erasure's and the data clear's own transaction (`ErasesAccounts`),
run a job on a period, and register audit actions under its own name. The core carries no extension and behaves identically with none:
a self-hosted registry has no subscription tiers, caps nothing, and never
answers `402`.

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
| Transit | mounted at `transit/`, with one key, `hosted-vault`, of type `aes256-gcm96` and **derived**, so that each secret, encrypted with `user:<account id>` as the context, is under a key of its account's own |
| policy `encrypt` | `update` on `transit/encrypt/hosted-vault` and nothing else: the api's |
| policy `decrypt` | `update` on `transit/decrypt/hosted-vault` and nothing else: the worker's |
| an operator's policy | rotate the key, read its versions, rewrap, and set the version floors, never `exportable` or plaintext backup, which cannot be turned off once set. It never decrypts |
| two login roles | one bound to `encrypt` and one to `decrypt`, each **without the default policy**, so their tokens cannot renew themselves. The server logs in again at three quarters of the lease and once more on a `403` |

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

Give the api the encrypt role alone and the worker the decrypt role alone.
The api then writes rows it cannot read, and the worker opens them only at
a run's hand-off.

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
  request and response in the log stack. Each line names the path, the
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
