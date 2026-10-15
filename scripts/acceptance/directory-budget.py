"""The per-IP sign-up budget's acceptance, the driver.

Run by directory-budget.sh inside a container on the same private network as
a throwaway directory whose budget is 4 an hour and whose registry
activation is off, so the sign-up sends its own confirmation mail. Stdlib
only. It plays the browser through the flow executor's API, passing the
CAPTCHA with Cloudflare's test token, which the blueprint's default test
keys accept.

  spend   one password sign-up to the confirmation mail (an account and a
          mail: 2), the mail page opened again (not a second mail), one
          resend from it (1), then a password reset of that account to its
          mail (1): 4, the budget.
          Prints the account.
  refuse  with the budget spent, a sign-up and a reset are refused at the
          start, in the policy's words, and reach neither the form nor the
          address step.
"""

import http.cookiejar
import json
import os
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request

AK = os.environ.get("AK", "http://dl-ak-server:9000")
CAPTCHA_TEST_TOKEN = "XXXX.DUMMY.TOKEN.XXXX"
REFUSED = "Too many attempts from this network"


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def ok(msg):
    print("ok  ", msg)


class Flow:
    """One browser in one flow."""

    def __init__(self, slug):
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.url = AK + "/api/v3/flows/executor/" + slug + "/?" + urllib.parse.urlencode({"query": ""})

    def step(self, payload=None):
        data = None if payload is None else json.dumps(payload).encode()
        req = urllib.request.Request(self.url, data, {"Content-Type": "application/json"}, method="GET" if data is None else "POST")
        try:
            res = self.op.open(req, timeout=60)
        except urllib.error.HTTPError as err:
            res = err
        return json.loads(res.read())


def errors(c):
    return json.dumps(c.get("response_errors") or {})


def spend():
    flow = Flow("agentry-enrollment")
    c = flow.step()
    if c.get("component") != "ak-stage-captcha":
        fail(f"the sign-up opened on {c.get('component')}, not the CAPTCHA: {json.dumps(c)[:300]}")
    c = flow.step({"component": "ak-stage-captcha", "token": CAPTCHA_TEST_TOKEN})
    if c.get("component") != "ak-stage-prompt":
        fail(f"after the CAPTCHA the sign-up is at {c.get('component')}: {json.dumps(c)[:300]}")
    user = "dl-" + secrets.token_hex(4)
    password = "Correct-Horse-" + secrets.token_hex(8)
    c = flow.step({"component": "ak-stage-prompt", "username": user, "email": user + "@example.test",
                   "password": password, "password_repeat": password, "name": ""})
    if c.get("component") != "ak-stage-email":
        fail(f"the sign-up's form led to {c.get('component')}, not the confirmation mail: {errors(c)[:300]}")
    c = flow.step()
    if c.get("component") != "ak-stage-email":
        fail(f"the mail page opened again is {c.get('component')}")
    c = flow.step({"component": "ak-stage-email"})
    if c.get("component") != "ak-stage-email":
        fail(f"a resend from the mail page led to {c.get('component')}: {json.dumps(c)[:300]}")
    ok("a password sign-up reaches its confirmation mail; the mail page is opened again, and the mail resent once")

    flow = Flow("agentry-recovery")
    c = flow.step()
    if c.get("component") != "ak-stage-identification":
        fail(f"the reset opened on {c.get('component')}: {json.dumps(c)[:300]}")
    c = flow.step({"component": "ak-stage-identification", "uid_field": user + "@example.test"})
    if c.get("component") != "ak-stage-email":
        fail(f"the reset's address step led to {c.get('component')}: {json.dumps(c)[:300]}")
    ok("a password reset of that account reaches its mail")
    print("ACCOUNT " + user)


def refuse():
    for slug, first, what in (("agentry-enrollment", "ak-stage-captcha", "sign-up"),
                              ("agentry-recovery", "ak-stage-identification", "reset")):
        c = Flow(slug).step()
        shown = json.dumps(c)
        if c.get("component") == first or REFUSED not in shown:
            fail(f"with the budget spent a {what} opened on {c.get('component')}: {shown[:300]}")
        ok(f"with the budget spent a {what} is refused at the start: {c.get('component')}, in the policy's words")
    # The refused sign-up cannot be pushed past its start either.
    flow = Flow("agentry-enrollment")
    flow.step()
    c = flow.step({"component": "ak-stage-captcha", "token": CAPTCHA_TEST_TOKEN})
    if c.get("component") == "ak-stage-prompt":
        fail("a refused sign-up reached the form by answering the CAPTCHA anyway")
    ok("a refused sign-up does not reach the form by answering the CAPTCHA anyway")


if __name__ == "__main__":
    {"spend": spend, "refuse": refuse}[sys.argv[1]]()
