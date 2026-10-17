#!/usr/bin/env bash
# Exercise the headless edge's actual HTTP routing and per-client budgets:
# the shared sign-in budget, upstream 429s passed through unchanged, the git
# concurrency cap, and HSTS on every answer. The registry is an HTTP stub:
# no real account or credential is needed.
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"

EDGE_IMAGE=$(awk '/image: nginx:/{print $2; exit}' deploy/compose/docker-compose.yaml)
PY_IMAGE=${PY_IMAGE:-python:3.12-slim}
P="de-$(openssl rand -hex 4)"
NET="$P-net"
SCRATCH=${AGENTRY_SCRATCH_DIR:-$HOME/scratch}
mkdir -p "$SCRATCH"
TMP=$(mktemp -d "$SCRATCH/edge.XXXXXX")
cleanup() {
  docker rm -fv "$P-edge" "$P-upstream" "$P-client" "$P-other" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$TMP"
}
trap cleanup EXIT

mkdir "$TMP/certs"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=registry.edge.test \
  -keyout "$TMP/certs/edge.key" -out "$TMP/certs/edge.crt" >/dev/null 2>&1
docker network create --internal "$NET" >/dev/null
docker run -d --network "$NET" --name "$P-upstream" \
  --network-alias server "$PY_IMAGE" sleep 600 >/dev/null
cat > "$TMP/upstream.py" <<'PY'
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

released = threading.Event()


class Upstream(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path.endswith("/hold"):
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{")
            self.wfile.flush()
            released.wait(30)
            self.wfile.write(b"}")
            return
        if self.path == "/api/fixture-release":
            released.set()
        body = json.dumps({"path": self.path, "headers": dict(self.headers)}).encode()
        limited = self.path.endswith("/upstream-429")
        self.send_response(429 if limited else 200)
        if limited:
            self.send_header("Retry-After", "42")
            self.send_header("X-RateLimit-Remaining", "0")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.do_GET()


ThreadingHTTPServer(("0.0.0.0", 8080), Upstream).serve_forever()
PY
docker cp "$TMP/upstream.py" "$P-upstream:/upstream.py"
docker exec -d "$P-upstream" python /upstream.py
docker create --network "$NET" --name "$P-edge" \
  --network-alias edge "$EDGE_IMAGE" sh -c 'nginx -t && exec nginx -g "daemon off;"' >/dev/null
docker cp deploy/compose/edge/nginx.conf "$P-edge:/etc/nginx/nginx.conf"
docker cp "$TMP/certs" "$P-edge:/etc/nginx/"
# docker cp works from a CI container whose checkout path is not on the daemon.
docker start "$P-edge" >/dev/null
for client in client other; do
  docker run -d --network "$NET" --name "$P-$client" "$PY_IMAGE" sleep 600 >/dev/null
  docker cp scripts/acceptance/edge.py "$P-$client:/probe.py"
done
docker exec "$P-client" python /probe.py exhaust
docker exec "$P-other" python /probe.py fresh
docker exec "$P-other" python /probe.py concurrency
echo '== edge acceptance PASSED =='
