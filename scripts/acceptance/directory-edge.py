"""HTTP probes for directory-edge.sh; run inside each isolated client."""
import http.client
import json
import socket
import ssl
import sys
import time


def exchange(path, method="GET", spoof=False, port=8443):
    # This private fixture uses a one-day self-signed certificate.
    conn = http.client.HTTPSConnection("edge", port, context=ssl._create_unverified_context(), timeout=5)
    headers = {"Host": "auth.edge.test" if port == 8443 else "registry.edge.test"}
    if spoof:
        headers.update({"CF-Connecting-IP": "203.0.113.70", "X-Forwarded-For": "203.0.113.71"})
    conn.request(method, path, body="{}" if method == "POST" else None, headers=headers)
    response = conn.getresponse()
    status, body, headers = response.status, response.read(), response.headers
    conn.close()
    return status, body, headers


def request(path, method="GET", spoof=False):
    return exchange(path, method, spoof)[:2]


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
    responses = [exchange("/api/v3/flows/executor/default-authentication-flow/", "POST", spoof=True) for _ in range(40)]
    statuses = [response[0] for response in responses]
    assert 429 in statuses, "FAIL: direct executor requests never exhausted an edge budget"
    for status, _, headers in responses:
        assert headers.get("Strict-Transport-Security") == "max-age=31536000", "HSTS lost on an edge response"
        if status == 429:
            assert headers.get("Retry-After") == "6", "FAIL: request refusal must carry the conservative six-second retry delay"
        else:
            assert "Retry-After" not in headers, "successful request received retry instructions"
    for path in ["/if/flow/agentry-enrollment/", "/if/flow", "/api/v3/flows/executor", "/api/v3/%66lows/executor/agentry-enrollment/"]:
        status, _, headers = exchange(path)
        assert status == 429 and headers.get_all("Retry-After") == ["6"], f"exhausted budget bypassed or retry header lost at {path}"
    for path in ["/api/v1/auth/login", "/ui/login"]:
        status, _, headers = exchange(path, port=443)
        assert status == 429 and headers.get_all("Retry-After") == ["6"], f"shared registry authentication budget or retry header lost at {path}"
        assert headers.get("Strict-Transport-Security") == "max-age=31536000", "HSTS lost on registry authentication refusal"
    print("ok direct executor requests are throttled; page shells and normalized paths share the budget")
    for _ in range(40):
        for path in ["/application/o/token/", "/application/o/authorize/", "/api/v3/core/users/"]:
            assert request(path, "POST")[0] == 200, f"unrelated directory endpoint limited: {path}"
    print("ok token exchange and unrelated directory calls remain outside the visitor budget")
    time.sleep(6)
    status, _, headers = exchange("/if/flow/agentry-enrollment/")
    assert status == 200 and "Retry-After" not in headers, "traffic did not resume after the advertised retry delay"
    print("ok edge request refusals carry Retry-After and HSTS; traffic resumes after the delay")
elif sys.argv[1] == "fresh":
    print("ok a second client retains an independent flow budget")
elif sys.argv[1] == "concurrency":
    for path in ["/api/upstream-429", "/api/v1/auth/upstream-429", "/api/v3/flows/executor/upstream-429"]:
        port = 8443 if path.startswith("/api/v3/") else 443
        status, _, headers = exchange(path, port=port)
        assert status == 429 and headers.get_all("Retry-After") == ["42"], "upstream retry instructions were changed or duplicated"
        assert headers.get("X-RateLimit-Remaining") == "0", "upstream rate headers lost"
        assert headers.get("Strict-Transport-Security") == "max-age=31536000", "HSTS lost on upstream refusal"
    print("ok upstream 429s retain their own retry and rate headers, including on edge-limited routes")
    held = []
    try:
        for _ in range(8):
            conn = http.client.HTTPSConnection("edge", 443, context=ssl._create_unverified_context(), timeout=20)
            conn.request("GET", "/fixture/repository.git/hold", headers={"Host": "registry.edge.test"})
            response = conn.getresponse()
            held.append((conn, response))
            assert response.status == 200, "git concurrency cap changed below eight active requests"
            assert response.getheader("Retry-After") is None, "active git request received retry instructions"
            assert response.getheader("Strict-Transport-Security") == "max-age=31536000", "HSTS lost on streamed git request"
        status, _, headers = exchange("/fixture/repository.git/info/refs", port=443)
        assert status == 429, "ninth active git request escaped the concurrency cap"
        assert headers.get("Retry-After") == "1", "FAIL: concurrency refusal must carry a one-second retry hint"
        assert headers.get("Strict-Transport-Security") == "max-age=31536000", "HSTS lost on concurrency refusal"
        assert exchange("/api/fixture-release", port=443)[0] == 200
        for conn, response in held:
            assert response.read() == b"{}", "active git response changed"
            conn.close()
        held.clear()
        time.sleep(1)
        status, _, headers = exchange("/fixture/repository.git/info/refs", port=443)
        assert status == 200 and "Retry-After" not in headers, "git traffic did not resume after slots were released"
        print("ok eight active git requests remain allowed; the ninth gets Retry-After and traffic resumes when slots clear")
    finally:
        if held:
            exchange("/api/fixture-release", port=443)
            for conn, response in held:
                conn.close()
else:
    raise SystemExit("unknown edge probe mode")
