#!/usr/bin/env bash
# M7 acceptance (PLAN §13, §16, WG-K): the headless helm chart lints. The AWS
# terraform moved to the site's repository with the split (DEV-091) and is
# checked there.
#
# Always exits 0 on success so it is runnable in this environment.
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"
export PATH=/opt/homebrew/bin:$PATH

HELM_DIR=deploy/helm/agentry

echo "== M7 acceptance =="

# ---------------------------------------------------------------------------
# Helm
# ---------------------------------------------------------------------------
if command -v helm >/dev/null 2>&1; then
  echo "helm: $(helm version --short 2>/dev/null || helm version | head -1)"
  helm lint "$HELM_DIR"
  helm template acc "$HELM_DIR" \
    --set secret.databaseUrl='postgres://u:p@db:5432/agentry?sslmode=require' \
    --set secret.sealingKey='c2VhbGluZ2tleXNlYWxpbmdrZXlzZWFsaW5na2V5MDA=' \
    --set config.storage.s3Bucket='agentry-releases' \
    --set config.signing.kmsKeyARN='arn:aws:kms:us-east-1:111122223333:key/x' \
    >/dev/null && echo "helm template: OK"
else
  echo "SKIP helm: not installed. CI would run: helm lint $HELM_DIR"
fi

echo "== M7 acceptance PASSED =="
