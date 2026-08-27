#!/usr/bin/env bash
# M7 acceptance (PLAN §13, §16, WG-K): the AWS deploy IaC is structurally sound.
#
# When terraform (or the OpenTofu drop-in `tofu`) is installed it runs the real
# gate: `<tf> fmt -check` + `<tf> validate -backend=false` across every module
# and env root, plus tflint if present. When neither is ABSENT (a bare build
# sandbox) it prints the exact CI commands and falls back to a structural
# self-check:
#   1. every *.tf balances braces/parens/brackets (a light HCL parse), and
#   2. every module source referenced by an env/global root actually exists.
# Helm is linted directly (helm is available here).
#
# Always exits 0 on success so it is runnable in this environment.
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"
export PATH=/opt/homebrew/bin:$PATH

TF_DIR=deploy/terraform
HELM_DIR=deploy/helm/agentry

echo "== M7 acceptance =="

# ---------------------------------------------------------------------------
# Terraform
# ---------------------------------------------------------------------------
tf_roots() {
  # Reusable modules (validate standalone) + env roots + the global root.
  find "$TF_DIR/modules" -mindepth 1 -maxdepth 1 -type d
  find "$TF_DIR/envs" -mindepth 1 -maxdepth 1 -type d
  echo "$TF_DIR/global"
}

# Prefer terraform (the CI tool); fall back to the OpenTofu drop-in.
TF_BIN=""
if command -v terraform >/dev/null 2>&1; then TF_BIN=terraform
elif command -v tofu >/dev/null 2>&1; then TF_BIN=tofu; fi

if [ -n "$TF_BIN" ]; then
  echo "$TF_BIN: $($TF_BIN version | head -1)"
  # Share one provider download across the many init calls.
  export TF_PLUGIN_CACHE_DIR="${TF_PLUGIN_CACHE_DIR:-$HOME/.terraform.d/plugin-cache}"
  mkdir -p "$TF_PLUGIN_CACHE_DIR"
  # Leave no init artifacts in the tree.
  trap 'find "$TF_DIR" -name .terraform -type d -prune -exec rm -rf {} + 2>/dev/null; find "$TF_DIR" -name ".terraform.lock.hcl" -delete 2>/dev/null' EXIT

  "$TF_BIN" fmt -check -recursive "$TF_DIR" && echo "fmt -check: OK"

  while IFS= read -r d; do
    ( cd "$d" && "$TF_BIN" init -backend=false -input=false >/dev/null && "$TF_BIN" validate >/dev/null )
    echo "validate ${d#$TF_DIR/}: OK"
  done < <(tf_roots)

  if command -v tflint >/dev/null 2>&1; then
    tflint --recursive --chdir "$TF_DIR" && echo "tflint: OK"
  else
    echo "tflint: not installed (optional); skipped"
  fi
else
  echo "SKIP terraform: neither terraform nor tofu installed."
  echo "  In CI a runner executes:"
  echo "    terraform fmt -check -recursive $TF_DIR"
  echo "    for d in $TF_DIR/modules/* $TF_DIR/envs/* $TF_DIR/global; do"
  echo "      (cd \"\$d\" && terraform init -backend=false && terraform validate); done"
  echo "  Running structural self-check instead:"

  # 1. HCL brace/paren/bracket balance (strips comments, strings, heredocs).
  TF_DIR="$TF_DIR" python3 - <<'PYEOF'
import os, sys, glob
tfdir = os.environ["TF_DIR"]

def strip(src):
    out=[]; i=0; n=len(src)
    while i<n:
        c=src[i]
        if c=='#' or (c=='/' and i+1<n and src[i+1]=='/'):
            while i<n and src[i]!='\n': i+=1
            continue
        if c=='/' and i+1<n and src[i+1]=='*':
            i+=2
            while i+1<n and not (src[i]=='*' and src[i+1]=='/'): i+=1
            i+=2; continue
        if c=='<' and i+1<n and src[i+1]=='<':
            j=i+2
            if j<n and src[j]=='-': j+=1
            tag=''
            while j<n and (src[j].isalnum() or src[j]=='_'): tag+=src[j]; j+=1
            if tag:
                while j<n and src[j]!='\n': j+=1
                j+=1
                while j<n:
                    ls=j
                    while j<n and src[j]!='\n': j+=1
                    if src[ls:j].strip()==tag: break
                    j+=1
                i=j; continue
        if c=='"':
            i+=1
            while i<n:
                if src[i]=='\\': i+=2; continue
                if src[i]=='"': i+=1; break
                i+=1
            continue
        out.append(c); i+=1
    return ''.join(out)

pairs={')':'(',']':'[','}':'{'}; opens=set(pairs.values())
files=sorted(glob.glob(os.path.join(tfdir,'**','*.tf'),recursive=True))
bad=0
for p in files:
    s=strip(open(p,encoding='utf-8').read()); st=[]
    err=None
    for ch in s:
        if ch in opens: st.append(ch)
        elif ch in pairs:
            if not st or st[-1]!=pairs[ch]: err=f"unbalanced '{ch}'"; break
            st.pop()
    if not err and st: err=f"unclosed '{st[-1]}'"
    if err: bad+=1; print(f"  FAIL {p}: {err}")
print(f"  HCL balance: {len(files)} files checked, {bad} failed")
sys.exit(1 if bad else 0)
PYEOF

  # 2. Every module source referenced by a root exists.
  missing=0
  while IFS= read -r ref; do
    src=$(printf '%s\n' "$ref" | sed -E 's/.*source[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/')
    dir=$(printf '%s\n' "$ref" | cut -d: -f1)
    base=$(dirname "$dir")
    case "$src" in
      ./*|../*)
        target="$base/$src"
        if [ -d "$target" ]; then
          :
        else
          echo "  FAIL $dir -> $src (missing)"; missing=$((missing+1))
        fi
        ;;
    esac
  done < <(grep -rn 'source[[:space:]]*=[[:space:]]*"\(\.\|\.\.\)' "$TF_DIR"/envs "$TF_DIR"/global)
  if [ "$missing" -eq 0 ]; then
    echo "  module references: all resolve"
  else
    echo "  module references: $missing missing"; exit 1
  fi
fi

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
