#!/usr/bin/env python3
"""structure-diff.py BEFORE.md AFTER.md [--json]

The parts of a markdown page a voice pass must not touch, compared as
multisets: fenced code blocks (fence lines included), tables (runs of lines
starting with |), admonitions (!!! / ??? lines with their indented bodies),
headings (text after the #s, and the slug MkDocs derives), link targets
(everything inside (...) of [..](...) and bare <...> autolinks), and every
inline `code` span (commands, flags, policy keys, paths, status values).
Exit 0 when every set is identical; 1 with a listing otherwise. Stdlib only.
"""
import json, re, sys
from collections import Counter

def slug(text):
    t = re.sub(r"[^\w\- ]", "", text.strip().lower())
    return re.sub(r"\s+", "-", t)

def parse(path):
    src = open(path, encoding="utf-8").read()
    lines = src.split("\n")
    fences, tables, adms, heads, links, codes = [], [], [], [], [], []
    i, n = 0, len(lines)
    prose_lines = []
    while i < n:
        line = lines[i]
        m = re.match(r"^\s*(```+|~~~+)", line)
        if m:
            fence = m.group(1)[:3]
            block = [line]; i += 1
            while i < n and not re.match(rf"^\s*{re.escape(fence)}", lines[i]):
                block.append(lines[i]); i += 1
            if i < n: block.append(lines[i]); i += 1
            fences.append("\n".join(block)); continue
        if re.match(r"^\s*\|", line):
            block = []
            while i < n and re.match(r"^\s*\|", lines[i]):
                block.append(lines[i]); i += 1
            tables.append("\n".join(block)); continue
        if re.match(r"^(!!!|\?\?\?\+?)\s", line):
            block = [line]; i += 1
            while i < n and (lines[i].startswith("    ") or lines[i].strip() == ""):
                if lines[i].strip() == "" and (i + 1 >= n or not lines[i + 1].startswith("    ")):
                    break
                block.append(lines[i]); i += 1
            adms.append("\n".join(block)); continue
        hm = re.match(r"^(#{1,6})\s+(.*?)\s*#*\s*$", line)
        if hm:
            heads.append((len(hm.group(1)), hm.group(2), slug(hm.group(2))))
        prose_lines.append(line)
        i += 1
    prose = "\n".join(prose_lines)
    links = re.findall(r"\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)", prose) + re.findall(r"<(https?://[^>\s]+)>", prose)
    codes = re.findall(r"`([^`\n]+)`", prose)
    return dict(fences=fences, tables=tables, admonitions=adms, headings=heads, links=links, code=codes)

def diff(a, b, name, out):
    ca, cb = Counter(a), Counter(b)
    gone = list((ca - cb).elements()); new = list((cb - ca).elements())
    out[name] = {"before": len(a), "after": len(b), "removed": gone, "added": new}
    return not gone and not new

def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    before, after = parse(args[0]), parse(args[1])
    out, ok = {}, True
    for k in ("fences", "tables", "admonitions", "headings", "links", "code"):
        ok &= diff(before[k], after[k], k, out)
    if "--json" in sys.argv:
        print(json.dumps(out, indent=1, default=str)); return 0 if ok else 1
    for k, v in out.items():
        state = "identical" if not v["removed"] and not v["added"] else "DIFFERENT"
        print(f"{k:12s} {v['before']:4d} -> {v['after']:4d}  {state}")
        for r in v["removed"]: print(f"   - {str(r)[:160]!r}")
        for a in v["added"]: print(f"   + {str(a)[:160]!r}")
    print("STRUCTURE OK" if ok else "STRUCTURE DIFFERS")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
