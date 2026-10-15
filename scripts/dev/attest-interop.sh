#!/usr/bin/env bash
# Third-party verification of this registry's attestations: generate a fixture with our own signer, then verify both
# envelopes with cosign — a verifier that shares no code with pkg/attest.
# Fails when cosign disagrees with us about DSSE or in-toto. Needs cosign
# on PATH (CI: sigstore/cosign-installer; locally:
# go install github.com/sigstore/cosign/v2/cmd/cosign@latest).
set -euo pipefail
cd "$(dirname "$0")/../.."
command -v cosign >/dev/null || { echo "attest-interop: cosign not on PATH"; exit 2; }
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
go run ./scripts/dev/attest-fixture "$out"
for kind in publish ruleset; do
  type=$(cat "$out/predicate-$kind.txt")
  # --insecure-ignore-tlog: these envelopes are never in Rekor;
  # --check-claims (the default) makes cosign hash the blob and require it
  # as the statement subject, which is the binding that matters.
  cosign verify-blob-attestation \
    --key "$out/public.pem" \
    --signature "$out/$kind.dsse.json" \
    --type "$type" \
    --insecure-ignore-tlog \
    "$out/blob.bin"
  echo "attest-interop: cosign verified the $kind attestation ($type)"
done
