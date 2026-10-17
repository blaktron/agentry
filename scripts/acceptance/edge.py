"""HTTP probes for edge.sh; run inside each isolated client."""
import http.client
import ssl
import sys
import time


def exchange(path, method="GET"):
    # This private fixture uses a one-day self-signed certificate.
    conn = http.client.HTTPSConnection("edge", 443, context=ssl._create_unverified_context(), timeout=5)
    conn.request(method, path, body="{}" if method == "POST" else None, headers={"Host": "registry.edge.test"})
    response = conn.getresponse()
    status, body, headers = response.status, response.read(), response.headers
    conn.close()
    return status, body, headers


for attempt in range(50):
    try:
        if exchange("/api/v1/meta")[0] == 200:
            break
    except (OSError, http.client.HTTPException):
        pass
    time.sleep(0.1)
else:
    raise SystemExit("FAIL: edge or upstream did not become ready")

if sys.argv[1] == "exhaust":
    responses = [exchange("/api/v1/auth/desktop/exchange", "POST") for _ in range(40)]
    statuses = [response[0] for response in responses]
    assert 429 in statuses, "FAIL: sign-in requests never exhausted the edge budget"
    for status, _, headers in responses:
        assert headers.get("Strict-Transport-Security") == "max-age=31536000", "HSTS lost on an edge response"
        if status == 429:
            assert headers.get("Retry-After") == "6", "FAIL: request refusal must carry the conservative six-second retry delay"
        else:
            assert "Retry-After" not in headers, "successful request received retry instructions"
    for path in ["/api/v1/auth/oidc/oidc/start", "/ui/login"]:
        status, _, headers = exchange(path)
        assert status == 429 and headers.get_all("Retry-After") == ["6"], f"shared sign-in budget or retry header lost at {path}"
        assert headers.get("Strict-Transport-Security") == "max-age=31536000", "HSTS lost on a sign-in refusal"
    print("ok sign-in requests are throttled, and the API and the sign-in page share the budget")
    for _ in range(40):
        assert exchange("/api/v1/meta")[0] == 200, "an unrelated API call was limited by the sign-in budget"
    print("ok other API calls stay outside the sign-in budget")
    time.sleep(6)
    status, _, headers = exchange("/ui/login")
    assert status == 200 and "Retry-After" not in headers, "traffic did not resume after the advertised retry delay"
    print("ok edge refusals carry Retry-After and HSTS; traffic resumes after the delay")
elif sys.argv[1] == "fresh":
    assert exchange("/api/v1/auth/desktop/exchange", "POST")[0] == 200, "a second client shares the first client's budget"
    print("ok a second client keeps an independent sign-in budget")
    for path in ["/internal/x/anything/check", "/metrics"]:
        assert exchange(path, "POST" if path.startswith("/internal/") else "GET")[0] == 404, f"{path} reached the server through the edge"
    print("ok /internal/ and /metrics stay off the public listener")
elif sys.argv[1] == "concurrency":
    for path in ["/api/upstream-429", "/api/v1/auth/upstream-429"]:
        status, _, headers = exchange(path)
        assert status == 429 and headers.get_all("Retry-After") == ["42"], "upstream retry instructions were changed or duplicated"
        assert headers.get("X-RateLimit-Remaining") == "0", "upstream rate headers lost"
        assert headers.get("Strict-Transport-Security") == "max-age=31536000", "HSTS lost on upstream refusal"
    print("ok upstream 429s keep their own retry and rate headers, including on edge-limited routes")
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
        status, _, headers = exchange("/fixture/repository.git/info/refs")
        assert status == 429, "ninth active git request escaped the concurrency cap"
        assert headers.get("Retry-After") == "1", "FAIL: concurrency refusal must carry a one-second retry hint"
        assert headers.get("Strict-Transport-Security") == "max-age=31536000", "HSTS lost on concurrency refusal"
        assert exchange("/api/fixture-release")[0] == 200
        for conn, response in held:
            assert response.read() == b"{}", "active git response changed"
            conn.close()
        held.clear()
        time.sleep(1)
        status, _, headers = exchange("/fixture/repository.git/info/refs")
        assert status == 200 and "Retry-After" not in headers, "git traffic did not resume after slots were released"
        print("ok eight active git requests remain allowed; the ninth gets Retry-After and traffic resumes when slots clear")
    finally:
        if held:
            exchange("/api/fixture-release")
            for conn, response in held:
                conn.close()
else:
    raise SystemExit("unknown edge probe mode")
