#!/usr/bin/env bash
# M7 acceptance (PLAN §13, §16, WG-K): the headless helm chart lints and
# renders, and the production shape it grew for the Vultr cluster holds
# (agentry#450, DEV-124): the git role has a Service with its SSH port, the
# object-store credentials reach the api and worker pods and never the git
# pods, the signing key Secret is projected read-only where a signer runs,
# nothing is mounted under the read-only config directory, pull secrets and
# the worker's NetworkPolicy and proxy render, and git ×1 with Recreate is a
# supported shape. The AWS terraform moved to the site's repository with the
# split (DEV-091) and is checked there.
#
# Exits 0 on success so it is runnable in this environment; SKIPs without helm.
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"
export PATH=/opt/homebrew/bin:$PATH

HELM_DIR=deploy/helm/agentry

echo "== M7 acceptance =="

if ! command -v helm >/dev/null 2>&1; then
  echo "SKIP helm: not installed. CI would run: helm lint $HELM_DIR"
  echo "== M7 acceptance PASSED =="
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

# The file-key shape with every production knob (the Vultr cluster).
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
  --set git.replicaCount=1 --set git.updateStrategy.type=Recreate)

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
check "config carries git.sshAddr" "$(count "$cm" 'sshAddr: ":2222"')" 1
check "config carries signing.keyFile" "$(count "$cm" 'keyFile: "/etc/agentry-signing/signing-key.pem"')" 1

# Object-store credentials: two env entries in api and worker, none in git.
check "api gets the object-store credentials" "$(count "$api" 'name: agentry-object-store')" 2
check "worker gets the object-store credentials" "$(count "$worker" 'name: agentry-object-store')" 2
check "git never sees the object-store credentials" "$(count "$git" 'agentry-object-store')" 0

# The signing key: projected read-only to keyFile in every role, because
# agentryd constructs the signer in every role that has a database.
# agentry#479 is the seam that confines it to the worker; when it lands, the
# api and git "mounts the signing Secret" lines below want 0.
for role in api worker git; do
  eval "r=\$$role"
  check "$role mounts the signing Secret" "$(count "$r" 'secretName: agentry-signing')" 1
  check "$role projects the PEM to keyFile's directory" "$(count "$r" 'path: signing-key.pem')" 1
  check "$role mounts the key read-only" "$(printf '%s\n' "$r" | grep -A1 'mountPath: /etc/agentry-signing' | grep -c 'readOnly: true' || true)" 1
  check "$role mounts the database CA read-only" "$(printf '%s\n' "$r" | grep -A1 'mountPath: /etc/agentry-db-ca' | grep -c 'readOnly: true' || true)" 1
  check "$role mounts nothing under the read-only /etc/agentry" "$(count "$r" 'mountPath: /etc/agentry/')" 0
  check "$role carries the pull secret" "$(count "$r" 'name: agentry-ghcr-pull')" 1
done
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

if [ "$fail" -ne 0 ]; then echo "== M7 acceptance FAILED =="; exit 1; fi
echo "== M7 acceptance PASSED =="
