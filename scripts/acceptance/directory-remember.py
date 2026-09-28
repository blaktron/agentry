#!/usr/bin/env python3
"""Remembered-browser acceptance, the directory's half (agentry#671, DEV-163).

Run by directory-remember.sh inside a container on the same private network
as a throwaway directory. Stdlib only. Two roles in one file:

  serve      the registry, as far as the directory can tell: the check route
             POST /internal/directory/trusted-device, answering from
             /state/store.json the way the registry answers from its table,
             and misbehaving on demand (/state/mode: ok, error, hang,
             garbage) so the directory's fail-closed answer can be seen.
  scenarios  the browser and the relying party: it drives the directory's
             real sign-in through the flow executor's API (no JavaScript, so
             a ticked box is the intent cookie the page's script would set),
             exchanges the code, reads the ID token's amr,
             agentry_remember_device and auth_time, and mints a record exactly
             when the registry would (agentry#670).
  raise      one sign-in, after directory-remember.sh has made the skip
             policy raise: the code must be asked.

The directory's policies are what is under test: the skip happens in the
directory, before any token exists, so "was the code asked?" is read off the
flow itself.
"""
import base64
import hashlib
import hmac
import http.server
import json
import os
import secrets
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

AK = os.environ.get("AK", "http://dr-ak-server:9000")
CHECK_TOKEN = os.environ.get("CHECK_TOKEN", "")
CLIENT_ID = "dr"
CLIENT_SECRET = os.environ.get("CLIENT_SECRET", "")
REDIRECT = "http://dr-driver:8080/callback"
EXECUTOR = "/api/v3/flows/executor/"
FLOW = "default-authentication-flow"
STATE = "/state"
PASSWORD = os.environ.get("USER_PASSWORD", "")
# RFC 6238's test key, as the setup gives both users.
TOTP_KEY = bytes.fromhex("3132333435363738393031323334353637383930")


def state_read(name, default):
    try:
        with open(os.path.join(STATE, name)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def state_write(name, value):
    with open(os.path.join(STATE, name), "w") as f:
        json.dump(value, f)


# ---------------------------------------------------------------- the registry


class Registry(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/internal/directory/trusted-device":
            self.send_response(404)
            self.end_headers()
            return
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        mode = state_read("mode", "ok")
        authed = self.headers.get("Authorization") == "Bearer " + CHECK_TOKEN
        calls = state_read("calls", [])
        calls.append({"mode": mode, "authed": authed, "sub": body.get("sub"), "token_hash": sha(body.get("token", ""))})
        state_write("calls", calls)
        if not authed:
            return self.answer(401, b"")
        if mode == "error":
            return self.answer(500, b"")
        if mode == "hang":
            time.sleep(10)
        if mode == "garbage":
            return self.answer(200, b"not json")
        store = state_read("store", {})
        trusted = store.get(sha(body.get("token", ""))) == body.get("sub")
        self.answer(200, json.dumps({"trusted": trusted}).encode())

    def answer(self, status, payload):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


def sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


# ---------------------------------------------------------------- the browser


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


# Every authentik_device cookie the directory wrote, in any browser: authentik's
# own 30-day "known device" JWT, which the blueprint turns off on every login
# stage (agentry#460). It must stay empty.
DEVICE_COOKIES = []


class Browser:
    """One browser profile against the directory: its cookies, with their
    paths, sent where a browser would send them."""

    def __init__(self):
        self.cookies = {}  # name -> (value, path)

    def set_cookie(self, name, value, path="/"):
        self.cookies[name] = (value, path)

    def forget_directory_session(self):
        # A new sign-in on another day: the directory's session is gone,
        # the remembered-browser cookie is not.
        self.cookies = {k: v for k, v in self.cookies.items() if k == "agentry_trusted_device"}

    def request(self, method, url, data=None, headers=None):
        path = urllib.parse.urlparse(url).path
        jar = "; ".join(f"{k}={v}" for k, (v, p) in self.cookies.items() if path.startswith(p))
        hdrs = dict(headers or {})
        if jar:
            hdrs["Cookie"] = jar
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        try:
            res = OPENER.open(req, timeout=30)
        except urllib.error.HTTPError as err:
            res = err
        for raw in res.headers.get_all("Set-Cookie") or []:
            parts = [p.strip() for p in raw.split(";")]
            name, _, value = parts[0].partition("=")
            if name == "authentik_device" and value:
                DEVICE_COOKIES.append(raw[:80])
            attrs = {p.split("=", 1)[0].lower(): (p.split("=", 1) + [""])[1] for p in parts[1:]}
            if attrs.get("max-age") == "0" or not value:
                self.cookies.pop(name, None)
            else:
                self.cookies[name] = (value, attrs.get("path") or "/")
        return res.status, res.headers, res.read()

    def executor(self, url, payload=None):
        """GET or POST the flow executor, following its own 302 back to GET."""
        if payload is None:
            status, headers, body = self.request("GET", url)
        else:
            status, headers, body = self.request(
                "POST", url, json.dumps(payload).encode(), {"Content-Type": "application/json"})
            if status == 302:
                status, headers, body = self.request("GET", urllib.parse.urljoin(url, headers["Location"]))
        if status != 200:
            raise RuntimeError(f"flow executor answered {status}: {body[:200]!r}")
        return json.loads(body)


# ---------------------------------------------------------------- a sign-in


_last_step = {}


def totp(user):
    """The current code for a user, never the same time step twice: the
    directory refuses a code it has already accepted."""
    while True:
        step = int(time.time() // 30)
        if _last_step.get(user) != step:
            break
        time.sleep(1)
    _last_step[user] = step
    mac = hmac.new(TOTP_KEY, struct.pack(">Q", step), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    return "%06d" % ((struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % 1000000)


def sign_in(browser, user, tick=False):
    """One directory sign-in, start to ID token. Returns whether the code was
    asked and what the token says."""
    st, nonce = secrets.token_urlsafe(8), secrets.token_urlsafe(8)
    query = urllib.parse.urlencode({
        "client_id": CLIENT_ID, "redirect_uri": REDIRECT, "response_type": "code",
        "scope": "openid profile email agentry", "state": st, "nonce": nonce,
    })
    status, headers, _ = browser.request("GET", f"{AK}/application/o/authorize/?{query}")
    if status != 302:
        raise RuntimeError(f"authorize answered {status}")
    flow_query = urllib.parse.urlparse(headers["Location"]).query
    url = f"{AK}{EXECUTOR}{FLOW}/?query={urllib.parse.quote(flow_query)}"
    if tick:
        # What the flow page's script does when the box is ticked.
        browser.set_cookie("agentry_remember_intent", "1", "/")
    asked = False
    challenge = browser.executor(url)
    for _ in range(12):
        comp = challenge.get("component")
        if comp == "ak-stage-identification":
            challenge = browser.executor(url, {"component": comp, "uid_field": user})
        elif comp == "ak-stage-password":
            challenge = browser.executor(url, {"component": comp, "password": PASSWORD})
        elif comp == "ak-stage-authenticator-validate":
            asked = True
            challenge = browser.executor(url, {"component": comp, "code": totp(user)})
        elif comp == "xak-flow-redirect":
            break
        else:
            raise RuntimeError(f"unexpected stage {comp}: {json.dumps(challenge)[:300]}")
    else:
        raise RuntimeError("the flow did not finish")
    status, headers, _ = browser.request("GET", urllib.parse.urljoin(AK, challenge["to"]))
    loc = headers.get("Location", "")
    code = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query).get("code", [""])[0]
    if status != 302 or not loc.startswith(REDIRECT) or not code:
        raise RuntimeError(f"no code at the redirect ({status}, {loc[:120]})")
    form = urllib.parse.urlencode({
        "grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
        "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET,
    }).encode()
    status, _, body = browser.request("POST", f"{AK}/application/o/token/", form,
                                      {"Content-Type": "application/x-www-form-urlencoded"})
    if status != 200:
        raise RuntimeError(f"token endpoint answered {status}: {body[:200]!r}")
    payload = json.loads(body)["id_token"].split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    return {
        "asked": asked,
        "amr": claims.get("amr") or [],
        "claim": claims.get("agentry_remember_device"),
        "auth_time": claims.get("auth_time"),
        "sub": claims.get("sub"),
    }


def mint_if_earned(browser, result):
    """The registry's rule (agentry#670): the claim, a second factor, and a
    fresh auth_time. Returns the token when it minted."""
    fresh = result["auth_time"] and abs(time.time() - result["auth_time"]) <= 300
    if result["claim"] is True and "mfa" in result["amr"] and fresh:
        token = "agyd_" + secrets.token_urlsafe(32)
        store = state_read("store", {})
        store[sha(token)] = result["sub"]
        state_write("store", store)
        state_write("token", token)
        browser.set_cookie("agentry_trusted_device", token, EXECUTOR)
        return token
    return None


# ---------------------------------------------------------------- scenarios

FAILED = []


def expect(label, ok, detail):
    print(("ok   " if ok else "FAIL ") + label + ("" if ok else f": {detail}"), flush=True)
    if not ok:
        FAILED.append(label)


def remembered_browser():
    b = Browser()
    b.set_cookie("agentry_trusted_device", state_read("token", ""), EXECUTOR)
    return b


def scenarios():
    state_write("mode", "ok")
    state_write("store", {})

    b = Browser()
    r = sign_in(b, "dr-one")
    expect("unticked: the code is asked, the token says mfa and no remember",
           r["asked"] and "mfa" in r["amr"] and r["claim"] is False, r)
    expect("unticked: nothing is minted", mint_if_earned(b, r) is None, r)

    b = Browser()
    r = sign_in(b, "dr-one", tick=True)
    expect("ticked: the code is asked and the token says remember, with mfa and a fresh auth_time",
           r["asked"] and "mfa" in r["amr"] and r["claim"] is True and r["auth_time"], r)
    minted = mint_if_earned(b, r)
    expect("ticked: the registry would mint", minted is not None, r)
    one_sub = r["sub"]

    b = remembered_browser()
    calls_before = len(state_read("calls", []))
    r = sign_in(b, "dr-one")
    calls = state_read("calls", [])[calls_before:]
    expect("remembered: the code is not asked, and the token says no mfa",
           not r["asked"] and "mfa" not in r["amr"], r)
    expect("remembered: the directory asked the registry, with the secret, for this user and this cookie",
           any(c["authed"] and c["sub"] == one_sub and c["token_hash"] == sha(minted) for c in calls), calls)

    b = remembered_browser()
    r = sign_in(b, "dr-one", tick=True)
    expect("remembered and ticked again: no code, so no remember claim; trust cannot renew itself",
           not r["asked"] and r["claim"] is False and mint_if_earned(b, r) is None, r)

    r = sign_in(remembered_browser(), "dr-two")
    expect("another user with the same cookie: the code is asked", r["asked"], r)

    for mode in ("error", "hang", "garbage"):
        state_write("mode", mode)
        r = sign_in(remembered_browser(), "dr-one")
        expect(f"the registry answers {mode}: the code is asked", r["asked"], r)
    state_write("mode", "ok")

    r = sign_in(remembered_browser(), "dr-one")
    expect("the registry healthy again: the code is not asked", not r["asked"], r)

    kept = state_read("store", {})
    state_write("store", {})
    r = sign_in(remembered_browser(), "dr-one")
    expect("the record revoked: the code is asked", r["asked"], r)
    state_write("store", kept)

    r = sign_in(Browser(), "dr-one")
    expect("a browser that was never remembered: the code is asked", r["asked"], r)

    expect("no sign-in wrote authentik's own 30-day authentik_device cookie",
           not DEVICE_COOKIES, DEVICE_COOKIES)


def raise_scenario():
    r = sign_in(remembered_browser(), "dr-one")
    expect("the skip policy raises: the code is asked", r["asked"], r)


def main():
    phase = sys.argv[1] if len(sys.argv) > 1 else ""
    if phase == "serve":
        os.makedirs(STATE, exist_ok=True)
        http.server.ThreadingHTTPServer(("", 8080), Registry).serve_forever()
    elif phase == "scenarios":
        scenarios()
    elif phase == "raise":
        raise_scenario()
    else:
        sys.exit("usage: directory-remember.py serve|scenarios|raise")
    if FAILED:
        sys.exit(f"{len(FAILED)} failed")


if __name__ == "__main__":
    main()
