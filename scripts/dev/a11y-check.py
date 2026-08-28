#!/usr/bin/env python3
"""Structural accessibility checks against served HTML (§18.2 M5).

Not a substitute for a full Lighthouse/axe run, but it catches the
regressions that actually happen in review: a lost landmark, a second <h1>,
an unlabelled search input, a link with no accessible name. Runs with no
browser so it can gate CI.

Usage: a11y-check.py [--cookie-jar JAR] URL [URL ...]

--cookie-jar reads a curl/Netscape-format jar so authed pages (dashboard,
review, staff console) are audited signed-in.
"""
import re
import sys
import urllib.request
from html.parser import HTMLParser


class Audit(HTMLParser):
    def __init__(self):
        super().__init__()
        self.landmarks = set()
        self.headings = []
        self.controls = []          # (tag, attrs) for input/select/textarea
        self.label_for = set()
        self.open_label_depth = 0
        self.controls_in_label = 0
        self.links_missing_name = []
        self.imgs_missing_alt = []
        self._link_stack = []
        self.html_lang = None
        self.buttons_missing_name = []
        self._button_stack = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "html":
            self.html_lang = a.get("lang")
        if tag in ("main", "header", "nav", "footer"):
            self.landmarks.add(tag)
        if re.fullmatch(r"h[1-6]", tag):
            self.headings.append(int(tag[1]))
        if tag == "label":
            self.open_label_depth += 1
            if a.get("for"):
                self.label_for.add(a["for"])
        if tag in ("input", "select", "textarea"):
            if a.get("type") in ("hidden", "submit", "button", "reset"):
                return
            self.controls.append((tag, a, self.open_label_depth > 0))
        if tag == "a":
            self._link_stack.append([a, ""])
        if tag == "button":
            self._button_stack.append([a, ""])
        if tag == "img" and "alt" not in a:
            self.imgs_missing_alt.append(a.get("src", "?"))

    def handle_endtag(self, tag):
        if tag == "label" and self.open_label_depth:
            self.open_label_depth -= 1
        if tag == "a" and self._link_stack:
            a, text = self._link_stack.pop()
            if not text.strip() and not a.get("aria-label"):
                self.links_missing_name.append(a.get("href", "?"))
        if tag == "button" and self._button_stack:
            a, text = self._button_stack.pop()
            if not text.strip() and not a.get("aria-label"):
                self.buttons_missing_name.append(a.get("class", "?"))

    def handle_data(self, data):
        for stack in (self._link_stack, self._button_stack):
            if stack:
                stack[-1][1] += data


def read_jar(path):
    """Return a Cookie header value from a curl/Netscape cookie jar."""
    pairs = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.split("\t")
            if len(fields) >= 7:
                pairs.append(f"{fields[5]}={fields[6]}")
    return "; ".join(pairs)


def audit(url, cookie=None):
    req = urllib.request.Request(url)  # noqa: S310 - local test URL
    if cookie:
        req.add_header("Cookie", cookie)
    with urllib.request.urlopen(req, timeout=20) as r:  # noqa: S310 - local test URL
        html = r.read().decode("utf-8", "replace")
    p = Audit()
    p.feed(html)

    problems = []
    for lm in ("main", "header", "nav"):
        if lm not in p.landmarks:
            problems.append(f"missing <{lm}> landmark")
    if not p.html_lang:
        problems.append("<html> has no lang attribute")

    h1s = [h for h in p.headings if h == 1]
    if len(h1s) != 1:
        problems.append(f"expected exactly one <h1>, found {len(h1s)}")
    for prev, cur in zip(p.headings, p.headings[1:]):
        if cur - prev > 1:
            problems.append(f"heading level jumps h{prev} to h{cur}")

    for tag, a, in_label in p.controls:
        named = (
            in_label
            or a.get("aria-label")
            or a.get("aria-labelledby")
            or (a.get("id") and a["id"] in p.label_for)
        )
        if not named:
            problems.append(f"unlabelled <{tag} name={a.get('name', '?')}>")

    problems += [f"link with no accessible name: {h}" for h in p.links_missing_name]
    problems += [f"button with no accessible name: {c}" for c in p.buttons_missing_name]
    problems += [f"img without alt: {s}" for s in p.imgs_missing_alt]
    return problems


def main() -> int:
    failed = False
    args = sys.argv[1:]
    cookie = None
    if args and args[0] == "--cookie-jar":
        cookie = read_jar(args[1])
        args = args[2:]
    for url in args:
        problems = audit(url, cookie)
        if problems:
            failed = True
            print(f"  {url}: FAILED")
            for pr in problems:
                print(f"      - {pr}")
        else:
            print(f"  {url}: OK")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
