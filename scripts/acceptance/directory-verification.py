"""Run in the pinned directory's ak shell; all account fixtures roll back.

The real policy and email mapping read an HTTP stand-in for the registry.
Only the external HTTP boundary is substituted. This checks the subject,
address and credential, both verdicts, failures and legacy accounts.
"""

import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from django.db import transaction
from authentik.core.models import User
from authentik.providers.oauth2.models import ScopeMapping
from authentik.policies.expression.models import ExpressionPolicy
from authentik.policies.types import PolicyRequest


mode = "false"
seen = []


class Registry(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_POST(self):
        seen.append((self.path, self.headers.get("Authorization"),
                     json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
        if mode == "timeout":
            time.sleep(2.5)
        status = {"denied": 401, "unavailable": 503, "redirect": 302}.get(mode, 200)
        self.send_response(status)
        if mode == "redirect":
            self.send_header("Location", "/must-not-follow")
        self.end_headers()
        body = b"not JSON" if mode == "garbage" else json.dumps({"verified":
               "true" if mode == "string" else mode == "true"}).encode()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            pass


server = ThreadingHTTPServer(("127.0.0.1", 0), Registry)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
os.environ["AGENTRY_REGISTRY_INTERNAL_URL"] = "http://127.0.0.1:" + str(server.server_port)
os.environ["AGENTRY_IDP_TRUST_CHECK_TOKEN"] = "fixture-verification-token"

try:
    with transaction.atomic():
        user = User.objects.create(username="verification-read-fixture", email="read@example.test",
                                   attributes={"agentry_email_verified": False})
        mapping = ScopeMapping.objects.get(name="agentry-verified-email")
        policy = ExpressionPolicy.objects.get(name="agentry-email-verification")
        for mode in ("false", "true", "denied", "unavailable", "redirect", "garbage", "string", "timeout"):
            request = PolicyRequest(user)
            request.context["registry_account"] = user
            result = policy.passes(request).raw_result
            assert result == {"available": mode in ("true", "false"), "verified": mode == "true"}, (mode, result)
            claim = mapping.evaluate(user=user, request=None)
            assert claim == {"email": user.email, "email_verified": mode == "true"}, (mode, claim)
            user.refresh_from_db()
            assert user.attributes == {"agentry_email_verified": False}
        assert all(path == "/internal/directory/email-verification" and auth == "Bearer fixture-verification-token"
                   and body == {"sub": user.uid, "email": user.email} for path, auth, body in seen), seen
        for name in ("AGENTRY_REGISTRY_INTERNAL_URL", "AGENTRY_IDP_TRUST_CHECK_TOKEN"):
            value = os.environ.pop(name)
            assert mapping.evaluate(user=user, request=None)["email_verified"] is False
            os.environ[name] = value
        for attrs in ({}, {"agentry_email_verified": True}):
            user.attributes = attrs
            user.save()
            assert mapping.evaluate(user=user, request=None)["email_verified"] is True
        transaction.set_rollback(True)
    print("PASS: registry confirmation read, both verdicts, subject/address binding, refusal and failure closed, legacy claims, no directory writes")
finally:
    server.shutdown()
    server.server_close()
