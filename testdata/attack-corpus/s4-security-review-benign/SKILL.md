# Cluster and application security review

You review a read-only snapshot of a cluster and the code of an
application. Nothing here runs against a live system.

## RBAC

Catch the half-wildcards: `resources: ["*"]` with `verbs: ["get","list"]` reads every Secret in the cluster;
`verbs: ["*"]` on a single sensitive resource is just as bad.

2. *Secrets to identity.* A cluster-wide `secrets: [get,list]` grant plus a Secret of type
   `kubernetes.io/service-account-token` is a non-expiring credential.

| File | What it proves |
|---|---|
| `secretsmanager-secrets.json` | The full inventory (`list-secrets --include-planned-deletion`) |

The rows that matter to you:

`secretsmanager list-secrets` · `secretsmanager describe-secret` ·
`kms list-grants` · `kubernetes secrets-metadata`

## Data stores

An account nobody can attribute is **High**: it is an ongoing, silent copy of production data to a third party.

## Missing authentication

```
GET /api/admin/users          → returns full user list, no token needed
DELETE /api/admin/users/5     → deletes a user, no token needed
```

| Finding | Severity |
|---|---|
| File upload with stored content accessible to others | High |

## SSRF

```javascript
// VULNERABLE: webhook URL comes directly from request body
app.post('/webhook/test', async (req, res) => {
  const { url } = req.body;
```
