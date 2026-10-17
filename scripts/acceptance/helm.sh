#!/usr/bin/env bash
# Helm chart acceptance: the headless helm chart lints and renders, and its
# production shape holds: the git role has a Service with its SSH port, the
# object-store credentials reach the api and worker pods and never the git
# pods, each role holds only the app Secret's keys it uses, pod annotations
# and disruption budgets render only when asked, the signing key Secret is
# projected read-only where a signer runs, nothing is mounted under the
# read-only config directory, pull secrets and the worker's NetworkPolicy
# and proxy render, and git ×1 with Recreate is a supported shape.
#
# Exits 0 on success so it is runnable in this environment; SKIPs without helm.
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"
export PATH=/opt/homebrew/bin:$PATH

HELM_DIR=deploy/helm/agentry

echo "== helm acceptance =="

if ! command -v helm >/dev/null 2>&1; then
  echo "SKIP helm: not installed. CI would run: helm lint $HELM_DIR"
  echo "== helm acceptance PASSED =="
  exit 0
fi
echo "helm: $(helm version --short 2>/dev/null || helm version | head -1)"
helm lint "$HELM_DIR"

BASE=(--set secret.databaseUrl='postgres://u:p@db:5432/agentry?sslmode=require'
  --set secret.sealingKey='c2VhbGluZ2tleXNlYWxpbmdrZXlzZWFsaW5na2V5MDA='
  --set config.storage.s3Bucket='agentry-releases')
KMS=(--set config.signing.kmsKeyARN='arn:aws:kms:us-east-1:111122223333:key/x')

# The KMS shape (the AWS reference): renders with nothing else set.
helm template acc "$HELM_DIR" "${BASE[@]}" "${KMS[@]}" >/dev/null
echo "helm template (kms): OK"

# The file-key shape with every optional knob set: a file signing key, existing
# Secrets for the object store and the database CA, a worker egress policy and
# proxy, and one git pod that is replaced rather than rolled, with an
# ownership init container.
PROD=("${BASE[@]}"
  --set config.git.sshAddr=':2222'
  --set config.signing.kind=file --set signingKey.existingSecret=agentry-signing
  --set objectStoreCredentials.existingSecret=agentry-object-store
  --set databaseCA.existingSecret=agentry-database-ca
  --set 'image.pullSecrets[0].name=agentry-ghcr-pull'
  --set worker.networkPolicy.enabled=true
  --set 'worker.networkPolicy.egress[0].cidr=10.40.0.0/20'
  --set 'worker.networkPolicy.egress[0].ports[0].port=16751'
  --set worker.proxy.httpsProxy=http://egress:3128
  --set git.replicaCount=1 --set git.updateStrategy.type=Recreate
  --set git.persistence.initOwnership=true)

fail=0
# render <name> <template> [extra --set…]: the template rendered under the
# production values, into the variable named; a failed or empty render is a
# failure here, so that no count below passes on nothing.
render() {
  local name=$1 tpl=$2 out; shift 2
  if ! out=$(helm template acc "$HELM_DIR" "${PROD[@]}" "$@" --show-only "templates/$tpl" 2>&1) || [ -z "$out" ]; then
    echo "FAIL render $tpl: ${out:-empty}" | head -3; fail=1; out=""
  fi
  printf -v "$name" '%s' "$out"
}
# count <rendered> <pattern>
count() { printf '%s\n' "$1" | grep -c -- "$2" || true; }
# check <description> <got> <want>
check() {
  if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: got $2, want $3"; fail=1; fi
}

render svc service-git.yaml
render svc_nossh service-git.yaml --set config.git.sshAddr=''
render cm configmap.yaml
render api deployment-api.yaml
render worker deployment-worker.yaml
render git deployment-git.yaml
render np networkpolicy-worker.yaml

check "git Service renders" "$(count "$svc" 'name: acc-agentry-git')" 1
check "git Service exposes SSH on 22" "$(count "$svc" 'port: 22')" 1
check "git Service has no SSH port when sshAddr is empty" "$(count "$svc_nossh" 'port: 22')" 0
check "git container listens on ssh" "$(count "$git" 'name: ssh')" 1
check "git ×1 with Recreate renders" "$(count "$git" 'type: Recreate')" 1
# The RWX volume's ownership: an init container as root with CAP_CHOWN only,
# and only when asked for (Vultr VFS is root-owned to a non-root pod).
check "git ownership init container renders when asked" "$(count "$git" 'name: volume-ownership')" 1
check "it chowns dataDir to the pod's user and group" "$(count "$git" 'chown 65532:65532 /data/git')" 1
check "it holds CAP_CHOWN alone" "$(printf '%s\n' "$git" | grep -A1 'drop: \["ALL"\]' | grep -c 'add: \["CHOWN"\]' || true)" 1
render git_plain deployment-git.yaml --set git.persistence.initOwnership=false
check "no init container unless asked" "$(count "$git_plain" 'initContainers')" 0
check "config carries git.sshAddr" "$(count "$cm" 'sshAddr: ":2222"')" 1
check "config carries signing.keyFile" "$(count "$cm" 'keyFile: "/etc/agentry-signing/signing-key.pem"')" 1

# Object-store credentials: two env entries in api and worker, none in git.
check "api gets the object-store credentials" "$(count "$api" 'name: agentry-object-store')" 2
check "worker gets the object-store credentials" "$(count "$worker" 'name: agentry-object-store')" 2
check "git never sees the object-store credentials" "$(count "$git" 'agentry-object-store')" 0

# The signing key is the worker's alone: the api
# and git roles start without it and never sign, so the pods that terminate
# untrusted traffic hold no private key.
check "worker mounts the signing Secret" "$(count "$worker" 'secretName: agentry-signing')" 1
check "worker projects the PEM to keyFile's directory" "$(count "$worker" 'path: signing-key.pem')" 1
check "worker mounts the key read-only" "$(printf '%s\n' "$worker" | grep -A1 'mountPath: /etc/agentry-signing' | grep -c 'readOnly: true' || true)" 1
for role in api git; do
  eval "r=\$$role"
  check "$role never mounts the signing Secret" "$(count "$r" 'agentry-signing')" 0
  check "$role has no signing-key volume" "$(count "$r" 'name: signing-key')" 0
done
for role in api worker git; do
  eval "r=\$$role"
  check "$role mounts the database CA read-only" "$(printf '%s\n' "$r" | grep -A1 'mountPath: /etc/agentry-db-ca' | grep -c 'readOnly: true' || true)" 1
  check "$role mounts nothing under the read-only /etc/agentry" "$(count "$r" 'mountPath: /etc/agentry/')" 0
  check "$role carries the pull secret" "$(count "$r" 'name: agentry-ghcr-pull')" 1
done
# A ServiceAccount per role: three rendered, each Deployment under its own, no two alike, so a
# pod's token names its role (OpenBao binds the encrypt policy to the api's
# and the decrypt policy to the worker's).
render sa serviceaccount.yaml
check "three ServiceAccounts render" "$(count "$sa" 'kind: ServiceAccount')" 3
sas=""
for role in api worker git; do
  eval "r=\$$role"
  name=$(printf '%s\n' "$r" | sed -n 's/^ *serviceAccountName: *//p')
  check "$role runs under its own ServiceAccount" "$name" "acc-agentry-$role"
  check "$role's ServiceAccount is one the chart makes" "$(count "$sa" "name: $name\$")" 1
  sas="$sas $name"
done
check "no two roles share a ServiceAccount" "$(printf '%s\n' $sas | sort -u | wc -l | tr -d ' ')" 3
long=$(printf 'a%.0s' $(seq 1 63))
long_sas=$(helm template acc "$HELM_DIR" "${PROD[@]}" --set fullnameOverride="$long" --show-only templates/serviceaccount.yaml | sed -n 's/^  name: //p' | sort -u | wc -l | tr -d ' ')
check "a 63-character fullname still gives three distinct accounts" "$long_sas" 3
if helm template acc "$HELM_DIR" "${PROD[@]}" --set serviceAccount.name=shared >/dev/null 2>&1; then
  echo "FAIL serviceAccount.name with create rendered (one account for every role)"; fail=1
else
  echo "ok   serviceAccount.name with create is refused"
fi
shared=$(helm template acc "$HELM_DIR" "${PROD[@]}" --set serviceAccount.create=false --set serviceAccount.name=shared | grep -c 'serviceAccountName: shared' || true)
check "create=false keeps one existing account for all three" "$shared" 3

if helm template acc "$HELM_DIR" "${BASE[@]}" --set config.signing.kind=file >/dev/null 2>&1; then
  echo "FAIL kind=file without signingKey.existingSecret rendered"; fail=1
else
  echo "ok   kind=file without signingKey.existingSecret is refused"
fi
if helm template acc "$HELM_DIR" "${PROD[@]}" --set config.signing.keyFile=/etc/agentry/signing/key.pem >/dev/null 2>&1; then
  echo "FAIL a keyFile under /etc/agentry rendered"; fail=1
else
  echo "ok   a keyFile under the read-only /etc/agentry is refused"
fi

# The worker's egress: proxy env on the worker only; the NetworkPolicy only
# when enabled, with the DNS, namespace and address allows.
check "worker gets the proxy" "$(count "$worker" 'name: HTTPS_PROXY')" 1
check "worker keeps in-cluster names off the proxy" "$(count "$worker" 'name: NO_PROXY')" 1
check "api gets no proxy" "$(count "$api" 'PROXY')" 0
check "worker NetworkPolicy renders" "$(count "$np" 'kind: NetworkPolicy')" 1
check "worker NetworkPolicy is egress-typed" "$(count "$np" 'policyTypes: \["Egress"\]')" 1
check "worker NetworkPolicy allows the listed address" "$(count "$np" 'cidr: "10.40.0.0/20"')" 1
check "worker NetworkPolicy allows DNS" "$(count "$np" 'kubernetes.io/metadata.name: kube-system')" 1
np_off=$(helm template acc "$HELM_DIR" "${BASE[@]}" "${KMS[@]}" | grep -c 'kind: NetworkPolicy' || true)
check "no NetworkPolicy unless enabled" "$np_off" 0

# Each role holds the app Secret's keys it uses and no other:
# git, which takes untrusted pushes, the database URL and the sealing key; the
# worker also mail, erasure and knowledge; the api every key. The exact set is
# asserted, so a key added to agentry.agentrydEnv fails here until it is
# placed. secretKeys <rendered>: the env names read from the app Secret,
# whatever the order of a reference's name and key lines.
secretKeys() {
  printf '%s\n' "$1" | awk '
    function flush() { if (n != "" && s == "agentry-app") print n; n = ""; s = "" }
    /^ *- name: / { flush(); n = $3; ref = 0; next }
    /secretKeyRef:/ { ref = 1; next }
    ref && /^ *name: / { s = $2 }
    END { flush() }' | sort | tr '\n' ' ' | sed 's/ $//'
}
APP=(--set secret.existingSecret=agentry-app)
render api_app deployment-api.yaml "${APP[@]}"
render worker_app deployment-worker.yaml "${APP[@]}"
render git_app deployment-git.yaml "${APP[@]}"
check "api holds every app key" "$(secretKeys "$api_app")" \
  "AGENTRY_AUTH_OIDC_CLIENT_SECRET AGENTRY_AUTH_SEALING_KEY AGENTRY_DATABASE_URL AGENTRY_KNOWLEDGE_SEALING_KEY AGENTRY_REDIS_URL AGENTRY_SMTP_PASS"
check "worker holds the database, sealing, knowledge and mail keys" "$(secretKeys "$worker_app")" \
  "AGENTRY_AUTH_SEALING_KEY AGENTRY_DATABASE_URL AGENTRY_KNOWLEDGE_SEALING_KEY AGENTRY_SMTP_PASS"
check "git holds the database URL and the sealing key alone" "$(secretKeys "$git_app")" \
  "AGENTRY_AUTH_SEALING_KEY AGENTRY_DATABASE_URL"

# Pod annotations and disruption budgets: nothing by default;
# the chart-wide annotations on every role with a role's own winning; a
# budget only for a role that asks, selecting that role's pods alone.
check "no PodDisruptionBudget by default" "$(helm template acc "$HELM_DIR" "${PROD[@]}" | grep -c 'kind: PodDisruptionBudget' || true)" 0
EVICT='cluster-autoscaler\.kubernetes\.io/safe-to-evict'
ANN=(--set-string "podAnnotations.$EVICT=false" --set-string "api.podAnnotations.$EVICT=true")
render api_ann deployment-api.yaml "${ANN[@]}"
render git_ann deployment-git.yaml "${ANN[@]}"
check "a role's own annotation wins" "$(count "$api_ann" 'safe-to-evict: "true"')" 1
check "the chart-wide annotation reaches the other roles" "$(count "$git_ann" 'safe-to-evict: "false"')" 1
check "the config checksum stays beside them" "$(count "$api_ann" 'checksum/config:')" 1
render pdb pdb.yaml --set api.podDisruptionBudget.enabled=true
check "a budget renders for the role that asks" "$(count "$pdb" 'name: acc-agentry-api$')" 1
check "and for no other role" "$(count "$pdb" 'kind: PodDisruptionBudget')" 1
check "it selects that role's pods alone" "$(count "$pdb" 'app.kubernetes.io/component: api')" 2
check "it allows one eviction at a time" "$(count "$pdb" 'maxUnavailable: 1')" 1

if [ "$fail" -ne 0 ]; then echo "== helm acceptance FAILED =="; exit 1; fi
echo "== helm acceptance PASSED =="
