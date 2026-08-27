# Self-hosting Agentry

The whole product is open source: the scanners, the review queue, SSO and
SCIM, signing with your own key. There is no "community edition" with the
security features removed — a registry you cannot audit is not trust
infrastructure.

**Target: a working private registry in under 15 minutes.**

## What you need

- PostgreSQL 16 (the only hard dependency)
- Somewhere to put files — a local disk is fine to start; S3 for production
- The `git` binary on the host running the git role
- Optionally: an LLM provider for automated adjudication. Without one, the
  pipeline does **not** skip that step — it routes every version to human
  review instead (fail toward review, never toward skip).

## Quickstart with Docker Compose

```bash
git clone https://github.com/PLACEHOLDER_ORG/agentry.git
cd agentry
docker compose -f deploy/compose/docker-compose.yaml up -d   # postgres, minio, mailpit
docker compose -f deploy/compose/docker-compose.yaml --profile server up -d
```

Then create the first account:

```bash
curl -sX POST http://localhost:8080/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"handle":"you","email":"you@example.com","password":"a-long-passphrase"}'
```

Email verification is required before publishing. In a dev setup the token is
logged at debug level and mailpit (http://localhost:8025) catches the message;
in production configure real SMTP.

## Quickstart from source

```bash
brew install go postgresql@16       # or your platform's equivalent
make db-up                          # private Postgres cluster on :5477
make build
./bin/agentryd migrate
./bin/agentryd all                  # every role in one process
```

Point the CLI at it:

```bash
./bin/agentry login --registry http://localhost:8080
./bin/agentry init --kind=skill my-first-agent
cd my-first-agent && ../bin/agentry validate
```

`validate` runs the same manifest rules and the same hidden-content and
injection-signature scanners the server runs at publish time — offline.

## Deployment shapes

| Shape | What runs | Who it is for |
|---|---|---|
| **Single process** | `agentryd all` + Postgres | evaluation, small teams |
| **HA** | Helm chart: `api`×N, `git`×N (shared RWX volume), `worker`×N, `web`×N | production self-host |
| **AWS reference** | the Terraform modules in `deploy/terraform` | mirrors how the hosted service runs |

The same binary serves every role; `agentryd api|git|worker|all` selects it.
The `git` role is the only one that needs repo storage mounted, and the
`worker` role is the only one that needs to reach the LLM provider — which is
what lets you give the scanning workers a no-egress security group.

## Configuration

`agentry.yaml` (copy `agentry.yaml.example`) plus `AGENTRY_*` environment
overrides; environment always wins. The authoritative list is
`internal/config/config.go`. The settings that matter most:

```yaml
env: prod
devMode: false          # refused in prod anyway

database:
  url: postgres://…

storage:
  kind: s3              # or local
  s3Bucket: my-agentry-releases
  s3Region: us-east-1

auth:
  sealingKey: "<base64 32 bytes>"   # required outside dev; encrypts TOTP seeds
  cookieSecure: true

signing:
  kind: file            # file | kms — 'none' is refused in prod
  keyFile: /etc/agentry/signing-key.pem

judge:
  provider: none        # none | bedrock | anthropic
```

Generate a signing key:

```bash
openssl ecparam -name prime256v1 -genkey -noout -out signing-key.pem
chmod 600 signing-key.pem
```

Your public key is served at `/.well-known/agentry/signing-keys.json`, and
clients pin it on first use. **Back this key up**: it is what makes your
already-published attestations verifiable, and losing it means every installed
copy stops verifying.

Generate a sealing key:

```bash
openssl rand -base64 32
```

## Choosing your publication policy

The platform baseline lives in the `policies` table (`org_id IS NULL`) and is
readable at `/api/v1/platform/policy`. Defaults: findings up to `low`
auto-publish, `medium`/`high` go to review, `critical` is rejected, wildcard
network egress goes to review.

A stricter starting point for an internal registry — everything gets a human
look:

```json
{
  "requireHumanReview": "always",
  "maxAutoPublishSeverity": "info",
  "wildcardEgress": "reject",
  "allowedLicenses": ["Apache-2.0", "MIT"]
}
```

Organizations can tighten this for their own namespace but never loosen it.

## Operating it

- **Backups:** Postgres is the system of record — back it up. Release archives
  are content-addressed and write-once; repos are recoverable from any clone.
  Losing the repo store breaks pushes, not published installs.
- **The worker matters.** With no worker running, versions sit in `scanning`
  and never publish. That is the fail-closed design working, but it looks like
  a hang — check the worker first when publishes stall.
- **Rescan after ruleset updates.** New detection only protects you if you
  apply it to what you already published; the rescan sweep quarantines
  versions that newly trip a high finding.
- Runbooks for the failure modes above: [docs/ops/runbooks.md](ops/runbooks.md).

## What you are responsible for

Running your own registry means you own the trust decisions:

- the signing key and its backups;
- who has platform-staff rights (they can quarantine, block, and read
  everything on your instance);
- whether an LLM judge is configured, and therefore whether adjudication is
  automated or entirely human;
- keeping the ruleset current — a scanner from a year ago is a scanner that
  has not seen this year's techniques.

None of that is different from the hosted service; it is just visible.
