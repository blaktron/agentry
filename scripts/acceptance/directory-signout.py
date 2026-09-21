#!/usr/bin/env python3
"""Directory sign-out acceptance (agentry#441): sign-out ends the directory
session whatever the last directory flow left behind.

Authentik's end-session endpoint answers an empty 200 — a blank page, no
sign-out — to a session that still holds a flow plan. A flow that ends on a
redirect stage parks its plan (the browser navigates away and never answers
the redirect challenge), and so does a flow the person abandons. This script
drives the flow executor API the way the browser does and proves both halves
of the fix against a live directory:

  1. control: end-session straight after sign-in redirects into the
     invalidation flow, and the flow ends the session;
  2. after an ABANDONED authenticator-app flow, the configured sign-out URL
     (authentik's cancel view wrapping end-session) still reaches the
     invalidation flow;
  3. after a COMPLETED authenticator-app flow, the flow's last challenge is a
     final redirect to AGENTRY_ACCOUNT_URL (the plan-context redirect the
     blueprint's return-to-settings policy sets, not a redirect stage), and
     plain end-session redirects into the invalidation flow.

Stdlib only. It creates a throwaway directory user through the admin API and
deletes it on the way out; nothing else in the directory is touched.

Environment:
  AUTHENTIK_URL              the directory's public origin, e.g. https://auth.example.com
  AUTHENTIK_BOOTSTRAP_TOKEN  an admin API token (the one authentik-bootstrap.sh uses)
  AGENTRY_ACCOUNT_URL        where the stage-configuration flows return
                             (the value the authentik containers were given)
  AGENTRY_IDP_LOGOUT_URL     the sign-out URL the site and the server are
                             configured with; default: the cancel-wrapped
                             end-session URL docs/self-hosting.md recommends
  AGENTRY_AUTHENTIK_APP_SLUG the application's slug (default agentry)
  AUTHENTIK_AUTH_FLOW        the brand's authentication flow slug
                             (default default-authentication-flow)
"""

import base64
import hashlib
import hmac
import http.cookiejar
import json
import os
import secrets
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = os.environ["AUTHENTIK_URL"].rstrip("/")
TOKEN = os.environ["AUTHENTIK_BOOTSTRAP_TOKEN"]
ACCOUNT_URL = os.environ["AGENTRY_ACCOUNT_URL"]
APP = os.environ.get("AGENTRY_AUTHENTIK_APP_SLUG", "agentry")
AUTH_FLOW = os.environ.get("AUTHENTIK_AUTH_FLOW", "default-authentication-flow")
END_SESSION = f"/application/o/{APP}/end-session/"
SIGNOUT_URL = os.environ.get("AGENTRY_IDP_LOGOUT_URL") or f"{BASE}/flows/-/cancel/?next={END_SESSION}"
INVALIDATION = "/if/flow/agentry-invalidation/"
# Some edges refuse urllib's default agent string.
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0 Safari/537.36 agentry-acceptance"

fails = []


def check(name, ok, detail):
    print(f"{'PASS' if ok else 'FAIL'}  {name}: {detail}")
    if not ok:
        fails.append(name)


def admin(method, path, body=None):
    req = urllib.request.Request(
        BASE + path,
        method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json", "User-Agent": UA},
    )
    with urllib.request.urlopen(req) as r:
        raw = r.read()
        return r.status, (json.loads(raw) if raw else None)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPCookieProcessor(jar))


def csrf():
    return next((c.value for c in jar if c.name == "authentik_csrf"), "")


def browser(method, path, body=None):
    """One request with the throwaway user's cookies; redirects are not followed."""
    url = path if path.startswith("http") else BASE + path
    headers = {"Accept": "application/json", "Origin": BASE, "Referer": BASE + "/if/flow/", "User-Agent": UA}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
        headers["X-authentik-CSRF"] = csrf()
    req = urllib.request.Request(url, method=method, data=data, headers=headers)
    try:
        with opener.open(req) as r:
            return r.status, r.headers.get("Location", ""), r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Location", ""), e.read()


def challenge(path):
    st, loc, raw = browser("GET", path)
    if st == 302:
        return challenge(loc)
    return json.loads(raw)


def run_flow(slug, answers):
    """Walk a flow's executor until it redirects. `answers` maps a challenge component to its response."""
    path = f"/api/v3/flows/executor/{slug}/"
    ch = challenge(path)
    for _ in range(8):
        comp = ch.get("component")
        if comp == "xak-flow-redirect":
            return ch
        if comp not in answers:
            raise SystemExit(f"{slug}: unexpected challenge {comp}: {json.dumps(ch)[:200]}")
        st, loc, raw = browser("POST", path, answers[comp](ch))
        if st == 302:
            ch = challenge(loc)
        else:
            ch = json.loads(raw)
            if ch.get("response_errors"):
                raise SystemExit(f"{slug}: {comp} rejected: {ch['response_errors']}")
    raise SystemExit(f"{slug}: no redirect after 8 steps")


def totp_code(config_url):
    q = urllib.parse.parse_qs(urllib.parse.urlsplit(config_url).query)
    secret = q["secret"][0]
    digits = int(q.get("digits", ["6"])[0])
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    counter = struct.pack(">Q", int(time.time()) // int(q.get("period", ["30"])[0]))
    mac = hmac.new(key, counter, hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    return str((struct.unpack(">I", mac[off : off + 4])[0] & 0x7FFFFFFF) % (10**digits)).zfill(digits)


def end_session():
    st, loc, raw = browser("GET", END_SESSION)
    return st, loc, len(raw)


def walk(url, hops=6):
    """Follow a same-origin redirect chain without executing any flow; returns the final (status, url)."""
    for _ in range(hops):
        st, loc, _ = browser("GET", url)
        if st != 302:
            return st, url
        url = loc if loc.startswith("http") else BASE + loc
        if not url.startswith(BASE):
            return st, url
    return 302, url


def signed_out():
    """True once the invalidation flow has run and the directory no longer knows the session."""
    run_flow("agentry-invalidation", {})
    st, _, raw = browser("GET", "/api/v3/core/users/me/")
    return st != 200 or json.loads(raw)["user"]["username"] != username


print("== directory sign-out acceptance ==")
username = "signout-acceptance-" + secrets.token_hex(4)
password = secrets.token_urlsafe(24)
_, user = admin("POST", "/api/v3/core/users/", {"username": username, "name": "sign-out acceptance", "is_active": True, "type": "internal"})
pk = user["pk"]
admin("POST", f"/api/v3/core/users/{pk}/set_password/", {"password": password})
try:
    answers = {
        "ak-stage-identification": lambda ch: {"component": "ak-stage-identification", "uid_field": username, **({"password": password} if ch.get("password_fields") else {})},
        "ak-stage-password": lambda ch: {"component": "ak-stage-password", "password": password},
    }

    def sign_in():
        run_flow(AUTH_FLOW, answers)
        st, _, raw = browser("GET", "/api/v3/core/users/me/")
        return st == 200 and json.loads(raw)["user"]["username"] == username

    # 1. control
    check("sign-in", sign_in(), username)
    st, loc, n = end_session()
    check("control: end-session after sign-in redirects into the invalidation flow", st == 302 and INVALIDATION in loc, f"{st} {loc or f'{n}-byte body'}")
    check("control: the invalidation flow ends the directory session", signed_out(), "/users/me no longer answers for the user")

    # 2. abandoned flow, then the configured sign-out URL
    check("sign-in again", sign_in(), username)
    browser("GET", "/if/flow/agentry-totp-setup/")  # the page load hands out the CSRF cookie, as in a browser
    ch = challenge("/api/v3/flows/executor/agentry-totp-setup/")
    check("authenticator-app flow starts", ch.get("component") == "ak-stage-authenticator-totp", ch.get("component"))
    st, loc, n = end_session()
    print(f"info  plain end-session after the abandoned flow: {st} {loc or f'{n}-byte body'} (authentik's plan guard; the sign-out URL below is what the site uses)")
    st, final = walk(SIGNOUT_URL)
    check("sign-out URL after an ABANDONED flow reaches the invalidation flow", INVALIDATION in final, f"{st} {final}")
    check("…and it ends the directory session", signed_out(), "/users/me no longer answers for the user")

    # 3. completed flow: the return is a final redirect, and plain end-session works
    check("sign-in a third time", sign_in(), username)
    browser("GET", "/if/flow/agentry-totp-setup/")
    red = run_flow("agentry-totp-setup", {"ak-stage-authenticator-totp": lambda ch: {"component": "ak-stage-authenticator-totp", "code": totp_code(ch["config_url"])}})
    check("authenticator-app flow ends on a FINAL redirect to AGENTRY_ACCOUNT_URL", red.get("final_redirect") is True and red.get("to", "").startswith(ACCOUNT_URL), f"to={red.get('to')!r} final_redirect={red.get('final_redirect')!r}")
    st, loc, n = end_session()
    check("end-session after a COMPLETED authenticator-app flow redirects into the invalidation flow", st == 302 and INVALIDATION in loc, f"{st} {loc or f'{n}-byte body'}")
    check("…and the invalidation flow ends the directory session", signed_out(), "/users/me no longer answers for the user")
finally:
    admin("DELETE", f"/api/v3/core/users/{pk}/")
    print(f"throwaway user {username} deleted")

print("DIRECTORY SIGN-OUT FAILED: " + ", ".join(fails) if fails else "DIRECTORY SIGN-OUT OK")
sys.exit(1 if fails else 0)
