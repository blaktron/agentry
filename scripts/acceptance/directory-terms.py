"""Terms of Service step acceptance, the directory's half (agentry#788).

Run by directory-terms.sh inside a container on the same private network as
a throwaway directory. Stdlib only. It plays the browser through the flow
executor's API (no JavaScript, so the scroll gate is not exercised here; it
is page script, checked in a browser), passing the CAPTCHA with Cloudflare's
test token, which the blueprint's default test keys accept.

  on       the server names a terms file: the display name is optional;
           after the form comes the terms step, the file's text and an
           unticked agreement; an unticked submission is refused in the
           policy's words; a ticked one reaches the confirmation mail. Makes
           one account with a blank display name and one with a name and a
           promo code. Prints them as JSON.
  missing  the file is gone: the step says the terms could not be loaded,
           and a ticked submission is still refused.
  off      the server names no terms file: the form leads straight to the
           confirmation mail, as before agentry#788.

The accounts are made inactive and are left there: the flow stops at the
confirmation mail, which this directory cannot send. directory-terms.sh
reads what was written with ak shell.
"""

import http.cookiejar
import json
import os
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request

AK = os.environ.get("AK", "http://dt-ak-server:9000")
VERSION = os.environ.get("TERMS_VERSION", "")
TEXT = "agentry_terms_text"
AGREE = "attributes_agentry_terms_accepted"
CAPTCHA_TEST_TOKEN = "XXXX.DUMMY.TOKEN.XXXX"


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def ok(msg):
    print("ok  ", msg)


class Flow:
    """One browser in the enrolment flow."""

    def __init__(self):
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.url = AK + "/api/v3/flows/executor/agentry-enrollment/?query="

    def step(self, payload=None):
        data = None if payload is None else json.dumps(payload).encode()
        req = urllib.request.Request(self.url, data, {"Content-Type": "application/json"}, method="GET" if data is None else "POST")
        try:
            res = self.op.open(req, timeout=60)
        except urllib.error.HTTPError as err:
            res = err
        return json.loads(res.read())

    def to_form(self):
        c = self.step()
        if c.get("component") != "ak-stage-captcha":
            fail(f"the enrolment flow opened on {c.get('component')}, not the CAPTCHA")
        c = self.step({"component": "ak-stage-captcha", "token": CAPTCHA_TEST_TOKEN})
        if c.get("component") != "ak-stage-prompt":
            fail(f"after the CAPTCHA the flow is at {c.get('component')}: {json.dumps(c)[:300]}")
        return c

    def submit_form(self, name, promo=""):
        user = "dt-" + secrets.token_hex(4)
        password = "Correct-Horse-" + secrets.token_hex(8)
        body = {"component": "ak-stage-prompt", "username": user, "email": user + "@example.test",
                "password": password, "password_repeat": password, "attributes.agentry_promo_code": promo}
        if name is not None:
            body["name"] = name
        return user, self.step(body)


def field(challenge, key):
    for f in challenge.get("fields", []):
        if f.get("field_key") == key:
            return f
    return None


def errors(c):
    return json.dumps(c.get("response_errors") or {})


def terms_step(c, label):
    if c.get("component") != "ak-stage-prompt" or field(c, AGREE) is None:
        fail(f"{label}: after the form the flow is at {c.get('component')} with fields "
             f"{[f.get('field_key') for f in c.get('fields', [])]}, not the terms step: {errors(c)[:300]}")
    return field(c, TEXT), field(c, AGREE)


def on():
    flow = Flow()
    name = field(flow.to_form(), "name")
    if name is None or name.get("required"):
        fail(f"the display name is not optional: {name}")
    if "different than your username" not in (name.get("sub_text") or ""):
        fail(f"the display name's help text is {name.get('sub_text')!r}")
    ok(f"the display name is optional, labelled {name.get('label')!r}, with the help text")

    made = {}
    user, c = flow.submit_form("")
    text, agree = terms_step(c, "a blank display name")
    shown = text.get("initial_value") or "" if text else ""
    if f'data-terms-version="{VERSION}"' not in shown or "Fixture clause 40" not in shown:
        fail(f"the terms step does not show the deployment's file: {shown[:300]!r}")
    if 'class="agentry-terms"' not in shown or "onload=" not in shown:
        fail("the terms are not in the scrolling box with its gate")
    ok("after the form comes the terms step, with the deployment's file in the scrolling box")
    if agree.get("type") != "checkbox" or not agree.get("required") or agree.get("initial_value"):
        fail(f"the agreement is {agree.get('type')}, required {agree.get('required')}, initial {agree.get('initial_value')!r}")
    ok(f"the agreement is a required checkbox, unticked: {agree.get('label')!r}")

    c = flow.step({"component": "ak-stage-prompt", AGREE: False})
    if c.get("component") != "ak-stage-prompt" or "tick the box to agree" not in errors(c):
        fail(f"an unticked agreement got past the terms: {c.get('component')} {errors(c)[:300]}")
    c = flow.step({"component": "ak-stage-prompt"})
    if c.get("component") != "ak-stage-prompt" or "tick the box to agree" not in errors(c):
        fail(f"a submission without the agreement got past the terms: {c.get('component')} {errors(c)[:300]}")
    ok("an unticked or absent agreement is refused, in the policy's words")

    c = flow.step({"component": "ak-stage-prompt", AGREE: True, TEXT: "<p>smuggled</p>"})
    if c.get("component") != "ak-stage-email":
        fail(f"a ticked agreement stopped at {c.get('component')}: {errors(c)[:300]}")
    made["blank"] = user
    ok("a ticked agreement reaches the confirmation mail")

    flow = Flow()
    flow.to_form()
    user, c = flow.submit_form("Ada Lovelace", promo="launch-2026")
    terms_step(c, "a named sign-up")
    c = flow.step({"component": "ak-stage-prompt", AGREE: "on"})
    if c.get("component") != "ak-stage-email":
        fail(f"the named sign-up stopped at {c.get('component')}: {errors(c)[:300]}")
    made["named"] = user
    ok("a sign-up with a display name and a promo code goes through the terms too")
    print("ACCOUNTS " + json.dumps(made))


def missing():
    flow = Flow()
    flow.to_form()
    _, c = flow.submit_form("")
    text, _ = terms_step(c, "the missing file")
    if "could not be loaded" not in (text.get("initial_value") or ""):
        fail(f"with the file gone the step shows {(text.get('initial_value') or '')[:200]!r}")
    c = flow.step({"component": "ak-stage-prompt", AGREE: True})
    if c.get("component") != "ak-stage-prompt" or "could not be loaded" not in errors(c):
        fail(f"with the file gone a ticked agreement got through: {c.get('component')} {errors(c)[:300]}")
    ok("with the terms file unreadable the step says so and refuses the sign-up (fail closed)")


def off():
    flow = Flow()
    flow.to_form()
    _, c = flow.submit_form("")
    if c.get("component") != "ak-stage-email":
        fail(f"with no terms file the form led to {c.get('component')} {[f.get('field_key') for f in c.get('fields', [])]}")
    ok("with no terms file named, the form leads straight to the confirmation mail")


if __name__ == "__main__":
    {"on": on, "missing": missing, "off": off}[sys.argv[1]]()
