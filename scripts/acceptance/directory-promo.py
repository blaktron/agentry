"""Promo code acceptance, the directory's half (agentry#759).

Run by directory-promo.sh inside a container on the same private network as
a throwaway directory. Stdlib only. It plays the browser through the flow
executor's API (no JavaScript), passing the CAPTCHA with Cloudflare's test
token, which the blueprint's default test keys accept.

  on   the field is on: the prompt stage shows it as an optional text field;
       a promo link fills it in; a code outside the grammar is refused on
       the form with the policy's words; a code and an empty field each get
       past the form. Prints the two accounts it made as JSON.
  off  the field is off: the prompt stage serves it hidden, a promo link
       fills nothing in, and a code posted into the hidden field anyway is
       dropped. Prints the account it made as JSON.

The accounts are made inactive and are left there: the flow stops at the
confirmation mail, which this directory cannot send. directory-promo.sh
reads their attributes and the agentry scope's claim with ak shell.
"""

import http.cookiejar
import json
import os
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request

AK = os.environ.get("AK", "http://dr-ak-server:9000")
FIELD = "attributes.agentry_promo_code"
CAPTCHA_TEST_TOKEN = "XXXX.DUMMY.TOKEN.XXXX"


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def ok(msg):
    print("ok  ", msg)


class Flow:
    """One browser in the enrolment flow, opened as a page with `page_query`."""

    def __init__(self, page_query=""):
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.url = AK + "/api/v3/flows/executor/agentry-enrollment/?query=" + urllib.parse.quote(page_query)

    def step(self, payload=None):
        data = None if payload is None else json.dumps(payload).encode()
        req = urllib.request.Request(self.url, data, {"Content-Type": "application/json"}, method="GET" if data is None else "POST")
        try:
            res = self.op.open(req, timeout=60)
        except urllib.error.HTTPError as err:
            res = err
        return json.loads(res.read())

    def to_prompt(self):
        c = self.step()
        if c.get("component") != "ak-stage-captcha":
            fail(f"the enrolment flow opened on {c.get('component')}, not the CAPTCHA")
        c = self.step({"component": "ak-stage-captcha", "token": CAPTCHA_TEST_TOKEN})
        if c.get("component") != "ak-stage-prompt":
            fail(f"after the CAPTCHA the flow is at {c.get('component')}: {json.dumps(c)[:300]}")
        return c

    def submit(self, code):
        user = "dp-" + secrets.token_hex(4)
        password = "Correct-Horse-" + secrets.token_hex(8)
        body = {"component": "ak-stage-prompt", "username": user, "name": user, "email": user + "@example.test",
                "password": password, "password_repeat": password, FIELD: code}
        return user, self.step(body)


def field_of(challenge):
    for f in challenge.get("fields", []):
        if f.get("field_key") == FIELD:
            return f
    fail(f"the prompt stage has no {FIELD} field")


def on():
    flow = Flow("promo=LINK-CODE-9&next=%2Fwelcome")
    f = field_of(flow.to_prompt())
    if f.get("type") != "text" or f.get("required"):
        fail(f"with the field on it is served {f.get('type')}, required {f.get('required')}")
    ok(f"the field is on: an optional text field labelled {f.get('label')!r}")
    if f.get("initial_value") != "LINK-CODE-9":
        fail(f"a promo link's code did not fill the field in: {f.get('initial_value')!r}")
    ok("a promo link (?promo=LINK-CODE-9) fills the field in")

    _, c = flow.submit("a b")
    errors = json.dumps(c.get("response_errors") or {})
    if c.get("component") != "ak-stage-prompt" or "A promo code is 4 to 32 letters" not in errors:
        fail(f"a code outside the grammar got past the form: {c.get('component')} {errors[:300]}")
    ok("a code outside the grammar is refused on the form, in the policy's words")

    made = {}
    for label, code in (("coded", "launch-2026"), ("empty", "")):
        flow = Flow()  # a fresh browser per account
        flow.to_prompt()
        user, c = flow.submit(code)
        if c.get("component") != "ak-stage-email":
            fail(f"the {label} sign-up stopped at {c.get('component')}: {json.dumps(c.get('response_errors') or {})[:300]}")
        made[label] = user
    ok("a code and an empty field each get past the form to the confirmation mail")
    print("ACCOUNTS " + json.dumps(made))


def off():
    flow = Flow("promo=LINK-CODE-9")
    f = field_of(flow.to_prompt())
    if f.get("type") != "hidden":
        fail(f"with the field off it is served {f.get('type')}")
    if f.get("initial_value"):
        fail(f"with the field off a promo link filled it in: {f.get('initial_value')!r}")
    ok("the field is off: served hidden, and a promo link fills nothing in")
    user, c = flow.submit("SMUGGLED-1")
    if c.get("component") != "ak-stage-email":
        fail(f"the sign-up with the field off stopped at {c.get('component')}")
    print("ACCOUNTS " + json.dumps({"smuggled": user}))


if __name__ == "__main__":
    {"on": on, "off": off}[sys.argv[1]]()
