"""HTTP probes for directory-edge.sh; run inside each isolated client."""
import http.client
import json
import socket
import ssl
import sys
import time


def request(path, method="GET", spoof=False):
    conn = http.client.HTTPSConnection("edge", 8443, context=ssl._create_unverified_context(), timeout=5)
    headers = {"Host": "auth.edge.test"}
    if spoof:
        headers.update({"CF-Connecting-IP": "203.0.113.70", "X-Forwarded-For": "203.0.113.71"})
    conn.request(method, path, body="{}" if method == "POST" else None, headers=headers)
    response = conn.getresponse()
    status, body = response.status, response.read()
    conn.close()
    return status, body


for attempt in range(50):
    try:
        status, _ = request("/api/v3/root/config/")
        if status == 200:
            break
    except (OSError, http.client.HTTPException):
        pass
    time.sleep(0.1)
else:
    raise SystemExit("FAIL: edge or upstream did not become ready")

flows = ["agentry-enrollment", "default-authentication-flow", "agentry-recovery", "agentry-authenticator"]
for flow in flows:
    path = f"/api/v3/flows/executor/{flow}/?query=next%3D%2Fapplication%2Fo%2Fauthorize%2F"
    status, body = request(path, "POST", spoof=True)
    assert status == 200, f"ordinary flow request refused: {status}"
    result = json.loads(body)
    assert result["path"] == path, "query or path changed before the directory"
    assert result["headers"]["Host"] == "auth.edge.test"
    assert result["headers"]["X-Forwarded-Proto"] == "https"
    ip = socket.gethostbyname(socket.gethostname())
    assert result["headers"]["X-Forwarded-For"] == ip, "a forged client address reached the directory"
    assert result["headers"]["X-Real-IP"] == ip
    assert result["headers"]["X-Request-Id"], "edge request ID lost"
assert request("/if/flow/agentry-enrollment/")[0] == 200
print("ok ordinary flow requests retain their path, query and trusted forwarding headers")

if sys.argv[1] == "exhaust":
    statuses = [request("/api/v3/flows/executor/default-authentication-flow/", "POST", spoof=True)[0] for _ in range(40)]
    assert 429 in statuses, "FAIL: direct executor requests never exhausted an edge budget"
    for path in ["/if/flow/agentry-enrollment/", "/if/flow", "/api/v3/flows/executor", "/api/v3/%66lows/executor/agentry-enrollment/"]:
        assert request(path)[0] == 429, f"exhausted budget bypassed by {path}"
    print("ok direct executor requests are throttled; page shells and normalized paths share the budget")
    for _ in range(40):
        for path in ["/application/o/token/", "/application/o/authorize/", "/api/v3/core/users/"]:
            assert request(path, "POST")[0] == 200, f"unrelated directory endpoint limited: {path}"
    print("ok token exchange and unrelated directory calls remain outside the visitor budget")
else:
    print("ok a second client retains an independent flow budget")
