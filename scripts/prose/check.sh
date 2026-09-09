#!/usr/bin/env bash
# The prose gate (plan front-end-voice-and-warmth §7, agentry#258).
#
#   scripts/prose/check.sh              run the gate over the working tree
#   scripts/prose/check.sh --self-test  prove the gate fails when it should
#
# Two strengths, on purpose (D4):
#
#   BLOCKING  the posture sentences of §4.6 are present byte for byte, with
#             whitespace normalised, in the files that carry them; and no
#             never-word of §4.4 appears in the core's markdown outside an
#             allowlisted span. Both halves are needed: a word ban alone is
#             satisfied by deleting the disclaimer, and a presence check alone
#             lets "safe" spread everywhere else.
#
#   ADVISORY  the unslop battery over the markdown, the server's HTML
#             templates and the notifier's sentences, printed and never fatal.
#             A scanner hit is a candidate, not a finding: the panel of
#             2026-09-08 put thirty pairs through these scripts and every
#             softened disclaimer passed all of them.
#
# This is the core's copy of the site's gate (blaktron/agentry-web
# scripts/prose), with the TSX extractor dropped and quoted spans masked as
# well as fences and inline code. A never-word inside "…" on one line is a
# mention rather than a claim, so it is not a hit, and allow.txt carries the
# reasons only for the occurrences outside quotes. It is stdlib Python 3 and
# bash: the core's CI carries no Node, so nothing here may need one.
#
# Environment:
#   PYTHON       the interpreter both halves run under (default: python3)
#   UNSLOP_DIR   an existing unslop checkout; skips the clone
#   UNSLOP_URL   where the advisory battery is fetched from when cloning
#   UNSLOP_SHA   the commit to fetch when cloning (default: the pinned one)
#   UNSLOP_SKIP  set to 1 to skip the advisory half entirely
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
PY="${PYTHON:-python3}"
UNSLOP_URL="${UNSLOP_URL:-https://github.com/theclaymethod/unslop}"
UNSLOP_SHA="${UNSLOP_SHA:-17ed39c9d0b522f44190ff0c6233867eadee192a}"

rule() { printf '\n== %s\n' "$1"; }

# --------------------------------------------------------------- self-test

# Copies every file named in protected.txt into $1, keeping its path. Run
# again to undo an edit the self-test made to one of the copies.
copy_protected() {
  "$PY" - "$ROOT" "$1" "$HERE/protected.txt" <<'PY'
import shutil, sys
from pathlib import Path
root, tmp, protected = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
for line in protected.read_text(encoding="utf-8").splitlines():
    line = line.strip()
    if not line or line.startswith("#") or " :: " not in line:
        continue
    for rel in (f.strip() for f in line.split(" :: ", 1)[0].split(",")):
        dst = tmp / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(root / rel, dst)
PY
}

self_test() {
  local tmp status out
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  status=0

  rule "self-test 1/4: a faithful copy of the protected files passes"
  copy_protected "$tmp"
  if "$PY" "$HERE/gates.py" protected --root "$tmp"; then
    echo "  OK"
  else
    echo "  FAILED: the copy of the tree does not pass, so the rest proves nothing"
    status=1
  fi

  rule "self-test 2/4: the softening fixture fails the protected check"
  "$PY" - "$tmp/docs/trust.md" "$HERE/fixtures/softened.txt" <<'PY'
import re, sys
from pathlib import Path
page, fixture = Path(sys.argv[1]), Path(sys.argv[2])
softened = fixture.read_text(encoding="utf-8").strip()
src = page.read_text(encoding="utf-8")
pattern = re.compile(r"Static\s+analysis\s+cannot\s+prove\s+an\s+agent\s+safe\.")
new, n = pattern.subn(softened, src)
if n == 0:
    raise SystemExit("the fixture's target sentence is not in docs/trust.md")
page.write_text(new, encoding="utf-8")
PY
  out="$("$PY" "$HERE/gates.py" protected --root "$tmp" 2>&1)"
  if [ $? -eq 0 ]; then
    echo "$out"
    echo "  FAILED: every unslop script passes the softened sentence and so did the gate"
    status=1
  elif printf '%s' "$out" | grep -q "docs/trust.md"; then
    printf '%s\n' "$out" | sed 's/^/  /'
    echo "  OK: caught in docs/trust.md"
  else
    printf '%s\n' "$out" | sed 's/^/  /'
    echo "  FAILED: it failed, but not on the softened page"
    status=1
  fi

  # The never half runs over the copied docs/ tree only, so the softened
  # sentence from step 2 is put back first: it says "safe" outside every
  # allowlisted span, which would make step 4 fail for the wrong reason.
  copy_protected "$tmp"

  rule "self-test 3/4: a never-word outside the allowlist fails the never check"
  mkdir -p "$tmp/docs"
  cp "$HERE/fixtures/never-word.md" "$tmp/docs/never-word.md"
  out="$("$PY" "$HERE/gates.py" never --root "$tmp" --markdown docs 2>&1)"
  if [ $? -ne 0 ] && printf '%s' "$out" | grep -q "never-word.md"; then
    printf '%s\n' "$out" | sed 's/^/  /'
    echo "  OK"
  else
    printf '%s\n' "$out" | sed 's/^/  /'
    echo "  FAILED: the seeded never-word was not caught"
    status=1
  fi

  rule "self-test 4/4: the same tree without the fixture passes the never check"
  rm -f "$tmp/docs/never-word.md"
  if "$PY" "$HERE/gates.py" never --root "$tmp" --markdown docs; then
    echo "  OK"
  else
    echo "  FAILED: the never check flags a tree with nothing in it"
    status=1
  fi

  rule "self-test result"
  if [ "$status" -eq 0 ]; then echo "  PASSED"; else echo "  FAILED"; fi
  return "$status"
}

# --------------------------------------------------------------- advisory

unslop_checkout() {
  # Echoes a directory holding the unslop scripts, or nothing.
  if [ -n "${UNSLOP_DIR:-}" ] && [ -d "$UNSLOP_DIR/scripts" ]; then
    printf '%s' "$UNSLOP_DIR"
    return 0
  fi
  local dir
  dir="$(mktemp -d)"
  {
    git -C "$dir" init -q &&
    git -C "$dir" fetch -q --depth 1 "$UNSLOP_URL" "$UNSLOP_SHA" &&
    git -C "$dir" checkout -q FETCH_HEAD
  } >/dev/null 2>&1 || { rm -rf "$dir"; return 1; }
  printf '%s' "$dir"
}

advisory() {
  rule "advisory: the unslop battery (never fatal)"
  if [ "${UNSLOP_SKIP:-0}" = "1" ]; then
    echo "  skipped (UNSLOP_SKIP=1)"
    return 0
  fi
  local unslop corpus
  unslop="$(unslop_checkout)" || {
    echo "  skipped: no UNSLOP_DIR and $UNSLOP_URL at $UNSLOP_SHA could not be fetched"
    return 0
  }
  echo "  unslop: $unslop"
  corpus="$(mktemp -d)"

  # The corpus: the markdown a reader meets, the server's own pages with the
  # tags taken off, and the notifier's sentences. The HTML and the Go are
  # extracted, so their rows are fragments rather than documents.
  "$PY" - "$ROOT" "$corpus" <<'PY'
import html as _html, re, sys
from pathlib import Path

root, corpus = Path(sys.argv[1]), Path(sys.argv[2])
(corpus / "md").mkdir(parents=True, exist_ok=True)
(corpus / "extracted").mkdir(parents=True, exist_ok=True)

for path in sorted((root / "docs").rglob("*.md")):
    rel = path.relative_to(root)
    (corpus / "md" / str(rel).replace("/", "-")).write_bytes(path.read_bytes())
for name in ("README.md", "CONTRIBUTING.md", "SECURITY.md"):
    if (root / name).exists():
        (corpus / "md" / name).write_bytes((root / name).read_bytes())


def html_to_text(src: str) -> str:
    """Enough of an HTML-to-text for a scanner: the sentences, in order."""
    src = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", src)
    src = re.sub(r"(?s)<!--.*?-->", " ", src)
    src = re.sub(r"(?s)\{\{.*?\}\}", " ", src)          # Go template actions
    src = re.sub(r"(?i)<br\s*/?>|</(p|li|h[1-6]|div|tr)>", "\n", src)
    src = re.sub(r"(?s)<[^>]+>", " ", src)
    src = _html.unescape(src)
    lines = [re.sub(r"[ \t]+", " ", ln).strip() for ln in src.split("\n")]
    return "\n".join(ln for ln in lines if ln) + "\n"


for path in sorted((root / "internal/ui/templates").glob("*.html")):
    text = html_to_text(path.read_text(encoding="utf-8"))
    if len(text.split()) >= 20:
        (corpus / "extracted" / f"{path.name}.txt").write_text(text, encoding="utf-8")

# Go string literals of six or more words: a sentence a person reads, not a
# key, a format verb or an import path. The tests are left out; the notices
# they assert on are already in the files below.
LITERAL = re.compile(r'"((?:[^"\\\n]|\\.)*)"')
for path in sorted((root / "internal/notify").glob("*.go")):
    if path.name.endswith("_test.go"):
        continue
    out = []
    for raw in LITERAL.findall(path.read_text(encoding="utf-8")):
        text = raw.replace("\\n", " ").replace('\\"', '"').replace("\\t", " ")
        text = re.sub(r"%[-+ #0-9.]*[a-zA-Z]", "…", text).strip()
        if len(text.split()) >= 6:
            out.append(text)
    if out:
        (corpus / "extracted" / f"{path.name}.txt").write_text("\n".join(out) + "\n", encoding="utf-8")
PY

  "$PY" - "$unslop/scripts" "$corpus" <<'PY'
import json, subprocess, sys
from pathlib import Path

scripts, corpus = Path(sys.argv[1]), Path(sys.argv[2])


def run(script, path, genre=None):
    cmd = [sys.executable, str(scripts / script), str(path)]
    if genre:
        cmd += ["--genre", genre]
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode not in (0, 1) or not p.stdout.strip():
        return None
    try:
        return json.loads(p.stdout)
    except json.JSONDecodeError:
        return None


def flag_names(report):
    """A scanner's flags are dicts keyed by metric; older ones were strings."""
    out = []
    for f in (report or {}).get("flags") or []:
        out.append(f.get("metric") or f.get("name") or str(f) if isinstance(f, dict) else str(f))
    return out


rows = []
for kind in ("md", "extracted"):
    for path in sorted((corpus / kind).glob("*")):
        if not path.is_file() or path.stat().st_size == 0:
            continue
        banned = run("banned_phrase_scan.py", path)
        structure = run("structure_scan.py", path, "docs")
        silhouette = run("silhouette_scan.py", path, "docs")
        rows.append({
            "file": path.name,
            "banned": (banned or {}).get("total_violations", "-"),
            "hard": ((banned or {}).get("by_severity") or {}).get("hard", "-"),
            "structure": ", ".join(flag_names(structure) + flag_names(silhouette)) or "-",
            "silhouette": (silhouette or {}).get("penalty"),
        })

if not rows:
    print("  nothing to scan")
    raise SystemExit(0)

noisy = [r for r in rows if r["banned"] not in (0, "-") or r["structure"] != "-" or (r["silhouette"] or 0) >= 1.0]
print(f"  {len(rows)} files scanned, {len(noisy)} with something to look at\n")
print(f"  {'file':44s} {'phrases':>7s} {'hard':>4s} {'silh':>5s}  structure flags")
for r in sorted(noisy, key=lambda r: (-(r['hard'] if isinstance(r['hard'], int) else 0), r['file'])):
    silh = f"{r['silhouette']:.2f}" if isinstance(r["silhouette"], (int, float)) else "-"
    print(f"  {r['file'][:44]:44s} {str(r['banned']):>7s} {str(r['hard']):>4s} {silh:>5s}  {r['structure'][:60]}")
print("\n  A hit here is a candidate, not a finding: read the page before editing it.")
print("  The *.html.txt and *.go.txt rows are extracted fragments, not paragraphs,")
print("  so cadence flags on them (one_line_staccato, burstiness) are artefacts of")
print("  the extraction. The markdown rows are the document as a reader meets it.")
PY
  rm -rf "$corpus"
  [ -n "${UNSLOP_DIR:-}" ] || rm -rf "$unslop"
  return 0
}

# ------------------------------------------------------------------- main

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit $?
fi

status=0

rule "blocking: the posture sentences are where §4.6 says they are"
if "$PY" "$HERE/gates.py" protected --root "$ROOT"; then
  echo "  OK: every protected sentence is present, byte for byte"
else
  status=1
fi

rule "blocking: no never-word outside an allowlisted span"
if "$PY" "$HERE/gates.py" never --root "$ROOT"; then
  echo "  OK: no banned word in the core's docs, README, CONTRIBUTING or SECURITY"
else
  status=1
fi

advisory

rule "result"
if [ "$status" -eq 0 ]; then
  echo "  PROSE CHECK PASSED"
else
  echo "  PROSE CHECK FAILED"
fi
exit "$status"
