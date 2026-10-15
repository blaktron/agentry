#!/usr/bin/env python3
"""The two blocking halves of the prose gate. Driven by check.sh.

  gates.py protected [--protected FILE] [--root DIR]
      Every sentence of protected.txt is present, byte for byte after
      whitespace normalisation, in each file named beside it.

  gates.py never [--never FILE] [--allow FILE] [--root DIR] [--markdown T]
      No never-word (never.txt) appears in the core's markdown, except inside
      an allowlisted span (allow.txt).

Why a grep and not a scanner: every unslop script passes the softened
disclaimer "Static analysis does not claim an agent is safe." A word ban alone
is worse than useless here, because deleting the sentence that contains "safe"
satisfies it. The two halves are one gate: the protected list says the
disclaimers must be there, the never list says nothing else may use the word.

This is the core's copy of the hosted site's gate, with the TSX extractor
dropped: the core ships markdown, its HTML templates and its Go strings, and
only the markdown is gated. The templates and the notifier are read by the
advisory half in check.sh. It masks quoted spans as well, which the site's
copy does not. A never-word inside "…" on one line is a mention rather than a
claim, so it is not a hit, and allow.txt carries the reasons only for the
occurrences outside quotes.

Stdlib only: the core's CI carries no Node.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]

MARKDOWN_TARGETS = ["docs", "README.md", "CONTRIBUTING.md", "SECURITY.md"]

ENTITIES = [
    ("&apos;", "'"), ("&#39;", "'"), ("&amp;", "&"), ("&nbsp;", " "),
    ("&rsquo;", "’"), ("&lsquo;", "‘"), ("&rdquo;", "”"),
    ("&ldquo;", "“"), ("&mdash;", "—"), ("&ndash;", "–"),
    ("&hellip;", "…"), ("&quot;", '"'),
]


def unescape(text: str) -> str:
    for a, b in ENTITIES:
        text = text.replace(a, b)
    return text


def records(path: Path) -> list[tuple[str, str]]:
    """Lines of `<metadata> :: <literal text>`; comments and blanks dropped."""
    out = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if " :: " not in line:
            raise SystemExit(f"{path}:{raw!r}: expected '<metadata> :: <text>'")
        meta, text = line.split(" :: ", 1)
        out.append((meta.strip(), text.strip()))
    return out


def phrases(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


# ----------------------------------------------------------------- protected

def normalise_source(text: str) -> str:
    """What a reader sees, near enough: entities resolved and the line wraps
    markdown reflows collapsed to one space. Nothing else is stripped — the
    emphasis markers and the colons in these sentences are part of the claim,
    so they are compared too."""
    return re.sub(r"\s+", " ", unescape(text))


def check_protected(root: Path, protected: Path) -> int:
    missing = 0
    cache: dict[str, str] = {}
    for meta, sentence in records(protected):
        for rel in [f.strip() for f in meta.split(",") if f.strip()]:
            path = root / rel
            if not path.exists():
                print(f"MISSING FILE  {rel}  (should carry: {sentence})")
                missing += 1
                continue
            if rel not in cache:
                cache[rel] = normalise_source(path.read_text(encoding="utf-8"))
            if normalise_source(sentence) not in cache[rel]:
                print(f"SOFTENED      {rel}")
                print(f"              expected, byte for byte: {sentence}")
                missing += 1
    if missing:
        print(f"\nprotected: {missing} sentence(s) not found where protected.txt says they must be")
    return 1 if missing else 0


# --------------------------------------------------------------------- never

class Unit:
    """A run of prose with a line number for every character."""

    def __init__(self, file: str, text: str, lines: list[int]):
        self.file = file
        self.text = text
        self.lines = lines

    def line_at(self, index: int) -> int:
        return self.lines[index] if index < len(self.lines) else (self.lines[-1] if self.lines else 1)


def flexible(phrase: str) -> re.Pattern:
    """Whole-word, case-insensitive, whitespace- and apostrophe-tolerant."""
    parts = [re.escape(w).replace("'", "['’]") for w in phrase.split()]
    body = r"\s+".join(parts)
    lead = r"\b" if phrase[:1].isalnum() else ""
    tail = r"\b" if phrase[-1:].isalnum() else ""
    return re.compile(lead + body + tail, re.IGNORECASE)


def blank(match: re.Match) -> str:
    """Spaces of the same width, so a mask never moves a line or a column."""
    return " " * len(match.group(0))


# A quoted term of at most one line. The docs quote the words they ban — the
# honest-posture rule is `never "safe"` — and a quoted term is a mention, not a
# claim. Single quotes need the guard: an apostrophe in "the product's" would
# otherwise open a span that swallows the rest of the sentence.
QUOTED = [
    re.compile(r'"[^"\n]{0,300}"'),
    re.compile(r"“[^”\n]{0,300}”"),
    re.compile(r"(?<![A-Za-z0-9])'[^'\n]{0,300}'(?![A-Za-z0-9])"),
]


def mask_markdown(text: str) -> str:
    """Blank out fenced blocks, inline code spans and quoted terms, keeping
    every newline and every column so the line map stays true.

    Indented blocks are NOT masked. A four-space indent is a nested list item
    as often as it is a code block, and a blind spot in a gate is worse than a
    false positive: an indented block that trips the check gets a line in
    allow.txt, with the reason."""
    out_lines = []
    fence: str | None = None
    for line in text.split("\n"):
        m = re.match(r"^\s*(```+|~~~+)", line)
        if fence is None and m:
            fence = m.group(1)[:3]
            out_lines.append("")
            continue
        if fence is not None:
            if re.match(rf"^\s*{re.escape(fence)}", line):
                fence = None
            out_lines.append("")
            continue
        line = re.sub(r"`[^`\n]*`", blank, line)
        for rx in QUOTED:
            line = rx.sub(blank, line)
        out_lines.append(line)
    return "\n".join(out_lines)


def normalise_with_lines(text: str) -> tuple[str, list[int]]:
    """Collapse whitespace, returning the line number of every kept character."""
    out: list[str] = []
    lines: list[int] = []
    line = 1
    space = False
    for ch in text:
        if ch == "\n":
            line += 1
            space = True
            continue
        if ch.isspace():
            space = True
            continue
        if space and out:
            out.append(" ")
            lines.append(line)
        space = False
        out.append(ch)
        lines.append(line)
    return "".join(out), lines


def markdown_units(root: Path, targets: list[str]) -> list[Unit]:
    files: list[Path] = []
    for t in targets:
        p = root / t
        if p.is_dir():
            files += sorted(p.rglob("*.md"))
        elif p.exists():
            files.append(p)
    units = []
    for f in sorted(set(files)):
        masked = mask_markdown(f.read_text(encoding="utf-8"))
        text, lines = normalise_with_lines(unescape(masked))
        rel = str(f.relative_to(root)) if f.is_relative_to(root) else str(f)
        units.append(Unit(rel, text, lines))
    return units


def check_never(units: list[Unit], never: Path, allow: Path) -> int:
    bans = [(p, flexible(p)) for p in phrases(never)]
    allows = [(reason, span, flexible(span)) for reason, span in records(allow)]
    hits = 0
    for unit in units:
        spans: list[tuple[int, int]] = []
        for _reason, _span, rx in allows:
            spans += [(m.start(), m.end()) for m in rx.finditer(unit.text)]
        for phrase, rx in bans:
            for m in rx.finditer(unit.text):
                if any(s <= m.start() and m.end() <= e for s, e in spans):
                    continue
                where = f"{unit.file}:{unit.line_at(m.start())}"
                lo = max(0, m.start() - 60)
                hi = min(len(unit.text), m.end() + 60)
                print(f"NEVER-WORD    {where}  \"{phrase}\"")
                print(f"              …{unit.text[lo:hi]}…")
                hits += 1
    if hits:
        print(f"\nnever: {hits} banned word(s) outside an allowlisted span (never.txt)")
    return 1 if hits else 0


# ---------------------------------------------------------------------- main

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["protected", "never"])
    ap.add_argument("--root", default=str(ROOT))
    ap.add_argument("--protected", default=str(HERE / "protected.txt"))
    ap.add_argument("--never", default=str(HERE / "never.txt"))
    ap.add_argument("--allow", default=str(HERE / "allow.txt"))
    ap.add_argument("--markdown", action="append", default=[], help="markdown target (repeatable)")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    if args.command == "protected":
        return check_protected(root, Path(args.protected))
    markdown = args.markdown or MARKDOWN_TARGETS
    return check_never(markdown_units(root, markdown), Path(args.never), Path(args.allow))


if __name__ == "__main__":
    sys.exit(main())
