#!/usr/bin/env python3
"""Emit the public-flow CSP for the pinned directory template customizations."""
import argparse
import base64
import hashlib
import re
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

SCRIPT_IDS = {"shady-dom", "authentik-config", "flow-config", "agentry-remember-device",
              "agentry-signup-link", "agentry-terms"}


class Scripts(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.current = None
        self.bodies = {}

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "script" and attrs.get("data-id") in SCRIPT_IDS and not attrs.get("src"):
            self.current = attrs["data-id"]
            if self.current in self.bodies:
                raise ValueError("duplicate executable script identity")
            self.bodies[self.current] = ""

    def handle_data(self, data):
        if self.current:
            self.bodies[self.current] += data

    def handle_endtag(self, tag):
        if tag == "script":
            self.current = None


def policy(origin, root):
    url = urlsplit(origin)
    if url.scheme not in ("http", "https") or not url.netloc or url.path or url.query or url.fragment or url.username or not re.fullmatch(r"(?:[A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\])(?::[0-9]{1,5})?", url.netloc):
        raise ValueError("origin must be an HTTP(S) origin without a path or credentials")
    bodies = {}
    for template in (root / "deploy/compose/authentik/templates").rglob("*.html"):
        scripts = Scripts()
        scripts.feed(template.read_text())
        scripts.close()
        if bodies.keys() & scripts.bodies.keys():
            raise ValueError("duplicate executable script identity")
        bodies.update(scripts.bodies)
    if bodies.keys() != SCRIPT_IDS:
        raise ValueError("directory template lacks an expected static script")
    hashes = []
    for body in bodies.values():
        # Never authorize a rendered response or runtime template value.
        if "{{" in body or "{%" in body:
            raise ValueError("executable script contains runtime template values")
        digest = base64.b64encode(hashlib.sha256(body.encode()).digest()).decode()
        hashes.append("'sha256-" + digest + "'")
    websocket = ("wss" if url.scheme == "https" else "ws") + "://" + url.netloc
    return "; ".join(("default-src 'self'", "script-src 'self' " + " ".join(sorted(hashes)) + " https://challenges.cloudflare.com",
                      "script-src-attr 'none'", "style-src 'self' 'unsafe-inline'", "img-src 'self' https: data:",
                      "font-src 'self' data:", "connect-src 'self' " + websocket + " https://challenges.cloudflare.com",
                      "frame-src 'self' https://challenges.cloudflare.com", "object-src 'none'", "base-uri 'self'",
                      "frame-ancestors 'self'"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", required=True)
    args = parser.parse_args()
    print(policy(args.origin, Path(__file__).resolve().parent.parent))
