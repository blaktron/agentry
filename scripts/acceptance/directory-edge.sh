#!/usr/bin/env bash
# Exercise the headless edge's actual HTTP routing and per-client budgets
# (agentry#983). The directory is an external HTTP stub: no real account,
# credential or mail is needed. Token exchange must stay outside this budget.
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"
source scripts/acceptance/directory-resources.sh

EDGE_IMAGE=$(awk '/image: nginx:/{print $2; exit}' deploy/compose/docker-compose.yaml)
PY_IMAGE=${PY_IMAGE:-python:3.12-slim}
P="de-$(openssl rand -hex 4)"
NET="$P-net"
SCRATCH=${AGENTRY_SCRATCH_DIR:-$HOME/scratch}
mkdir -p "$SCRATCH"
TMP=$(mktemp -d "$SCRATCH/directory-edge.XXXXXX")
cleanup() {
  docker rm -fv "$P-edge" "$P-upstream" "$P-client" "$P-other" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$TMP"
}
trap cleanup EXIT

mkdir "$TMP/certs"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=auth.edge.test \
  -keyout "$TMP/certs/edge.key" -out "$TMP/certs/edge.crt" >/dev/null 2>&1
docker network create "${DIRECTORY_DOCKER_LABELS[@]}" --internal "$NET" >/dev/null
docker run -d "${DIRECTORY_DOCKER_LABELS[@]}" --network "$NET" --name "$P-upstream" \
  --network-alias authentik-server --network-alias server "$PY_IMAGE" sleep 600 >/dev/null
cat > "$TMP/upstream.py" <<'PY'
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Upstream(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        body = json.dumps({"path": self.path, "headers": dict(self.headers)}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.do_GET()


threading.Thread(target=ThreadingHTTPServer(("0.0.0.0", 8080), Upstream).serve_forever, daemon=True).start()
ThreadingHTTPServer(("0.0.0.0", 9000), Upstream).serve_forever()
PY
docker cp "$TMP/upstream.py" "$P-upstream:/upstream.py"
docker exec -d "$P-upstream" python /upstream.py
docker create "${DIRECTORY_DOCKER_LABELS[@]}" --network "$NET" --name "$P-edge" \
  --network-alias edge "$EDGE_IMAGE" sh -c 'nginx -t && exec nginx -g "daemon off;"' >/dev/null
docker cp deploy/compose/edge/nginx.conf "$P-edge:/etc/nginx/nginx.conf"
docker cp "$TMP/certs" "$P-edge:/etc/nginx/"
# docker cp works from a CI container whose checkout path is not on the daemon.
docker start "$P-edge" >/dev/null
for client in client other; do
  docker run -d "${DIRECTORY_DOCKER_LABELS[@]}" --network "$NET" --name "$P-$client" "$PY_IMAGE" sleep 600 >/dev/null
  docker cp scripts/acceptance/directory-edge.py "$P-$client:/probe.py"
done
docker exec "$P-client" python /probe.py exhaust
docker exec "$P-other" python /probe.py fresh
echo '== directory edge acceptance PASSED =='
