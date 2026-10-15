#!/usr/bin/env python3
"""Directory user-settings acceptance: a signed-in person cannot
change their own directory email address (nor username or name) through the
directory.

The registry links and finds accounts by the address the directory holds, and
the directory's OIDC provider asserts `email_verified: true` for it,
so a self-service address change would be an account takeover. authentik's
shipped `default-user-settings-flow` has an email field and is reachable at
/if/flow/default-user-settings-flow/ even with the brand's settings panel
unset; its only guard is the system setting `default_user_change_email`, one
toggle in the admin console. The core's account-flows blueprint binds a
policy that always denies to that flow, so the refusal holds whatever the
setting says.

This script drives the flow executor API the way the browser does, as a
throwaway directory user it creates through the admin API and deletes on the
way out:

  1. the user signs in through the brand's authentication flow (control);
  2. opening the user-settings flow answers the access-denied challenge, not
     the prompt;
  3. a direct POST of a changed email to the executor does not complete the
     flow;
  4. the user's email, username and name are what they were.

It never changes the directory's system settings. Stdlib only.

Environment:
  AUTHENTIK_URL              the directory's public origin, e.g. https://auth.example.com
  AUTHENTIK_BOOTSTRAP_TOKEN  an admin API token (the one authentik-bootstrap.sh uses)
  AUTHENTIK_AUTH_FLOW        the brand's authentication flow slug
                             (default default-authentication-flow)
  CURL_INSECURE=1            accept a self-signed certificate on the edge
"""

import http.cookiejar
import json
import os
import secrets
import ssl
import sys
import urllib.error
import urllib.request

BASE = os.environ["AUTHENTIK_URL"].rstrip("/")
TOKEN = os.environ["AUTHENTIK_BOOTSTRAP_TOKEN"]
AUTH_FLOW = os.environ.get("AUTHENTIK_AUTH_FLOW", "default-authentication-flow")
SETTINGS_FLOW = "default-user-settings-flow"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0 Safari/537.36 agentry-acceptance"
CTX = ssl._create_unverified_context() if os.environ.get("CURL_INSECURE") == "1" else None

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
    with urllib.request.urlopen(req, context=CTX) as r:
        raw = r.read()
        return json.loads(raw) if raw else None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


jar = http.cookiejar.CookieJar()
handlers = [NoRedirect, urllib.request.HTTPCookieProcessor(jar)]
if CTX is not None:
    handlers.append(urllib.request.HTTPSHandler(context=CTX))
opener = urllib.request.build_opener(*handlers)


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


def challenge(method, path, body=None, hops=6):
    st, loc, raw = browser(method, path, body)
    while st == 302 and hops:
        st, loc, raw = browser("GET", loc)
        hops -= 1
    try:
        return json.loads(raw)
    except ValueError:
        return {"component": f"(HTTP {st}, not a challenge)"}


def sign_in(username, password):
    path = f"/api/v3/flows/executor/{AUTH_FLOW}/?query="
    ch = challenge("GET", path)
    for _ in range(6):
        comp = ch.get("component")
        if comp == "xak-flow-redirect":
            return True
        if comp == "ak-stage-identification":
            body = {"component": comp, "uid_field": username}
            if ch.get("password_fields"):
                body["password"] = password
        elif comp == "ak-stage-password":
            body = {"component": comp, "password": password}
        else:
            print(f"sign-in stopped at {comp}: {json.dumps(ch)[:200]}")
            return False
        ch = challenge("POST", path, body)
    return False


print("== directory user-settings acceptance ==")
username = "settings-acceptance-" + secrets.token_hex(4)
email = username + "@example.invalid"
password = secrets.token_urlsafe(24)
user = admin("POST", "/api/v3/core/users/", {"username": username, "name": "settings acceptance", "email": email, "is_active": True, "type": "internal"})
pk = user["pk"]
try:
    admin("POST", f"/api/v3/core/users/{pk}/set_password/", {"password": password})
    ok = sign_in(username, password)
    check("sign-in (control)", ok, f"{username} through {AUTH_FLOW}")
    if not ok:
        sys.exit(1)

    path = f"/api/v3/flows/executor/{SETTINGS_FLOW}/?query="
    ch = challenge("GET", path)
    comp = ch.get("component")
    check("user-settings flow refused", comp == "ak-stage-access-denied", f"opening {SETTINGS_FLOW} answered {comp}")

    ch = challenge("POST", path, {
        "component": "ak-stage-prompt",
        "username": username + "-renamed",
        "name": "renamed",
        "email": "someone-else@example.invalid",
        "attributes.settings.locale": "",
    })
    comp = ch.get("component")
    check("direct POST does not complete", comp != "xak-flow-redirect", f"a changed email POSTed to the executor answered {comp}")

    after = admin("GET", f"/api/v3/core/users/{pk}/")
    check("email unchanged", after["email"] == email, after["email"])
    check("username unchanged", after["username"] == username, after["username"])
    check("name unchanged", after["name"] == "settings acceptance", after["name"])
finally:
    admin("DELETE", f"/api/v3/core/users/{pk}/")

if fails:
    print(f"FAIL: {len(fails)} check(s): {', '.join(fails)}")
    sys.exit(1)
print("OK: the directory refuses a self-service email change")
