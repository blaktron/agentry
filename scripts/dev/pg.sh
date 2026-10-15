#!/usr/bin/env bash
# Local PostgreSQL 16 lifecycle for machines without Docker.
# Creates a private cluster under .devdata/pg on port 5477 with
# databases agentry_dev and agentry_test, role agentry/agentry.
set -euo pipefail

# macOS: postmaster refuses to start under an unset/invalid locale
# ("postmaster became multithreaded during startup").
export LC_ALL="${LC_ALL:-en_US.UTF-8}"

PGBIN="${PGBIN:-}"
if [ -z "$PGBIN" ]; then
  for cand in /opt/homebrew/opt/postgresql@16/bin /usr/local/opt/postgresql@16/bin; do
    [ -x "$cand/pg_ctl" ] && PGBIN="$cand" && break
  done
fi
if [ -z "$PGBIN" ]; then
  echo "postgresql@16 not found; install it or set PGBIN" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DATA="$ROOT/.devdata/pg"
PORT="${AGENTRY_PG_PORT:-5477}"
LOG="$DATA/pg.log"
URL_DEV="postgres://agentry:agentry@localhost:$PORT/agentry_dev?sslmode=disable"
URL_TEST="postgres://agentry:agentry@localhost:$PORT/agentry_test?sslmode=disable"

up() {
  if [ ! -d "$DATA" ]; then
    mkdir -p "$DATA"
    "$PGBIN/initdb" -D "$DATA" -U postgres --auth=trust --no-instructions -E UTF8 >/dev/null
    # Local dev cluster: listen on localhost only.
    echo "listen_addresses = '127.0.0.1'" >> "$DATA/postgresql.conf"
    echo "port = $PORT" >> "$DATA/postgresql.conf"
  fi
  if ! "$PGBIN/pg_ctl" -D "$DATA" status >/dev/null 2>&1; then
    "$PGBIN/pg_ctl" -D "$DATA" -l "$LOG" start >/dev/null
  fi
  # Wait for readiness.
  for _ in $(seq 1 30); do
    "$PGBIN/pg_isready" -h localhost -p "$PORT" -U postgres >/dev/null 2>&1 && break
    sleep 0.3
  done
  PSQL=("$PGBIN/psql" -h localhost -p "$PORT" -U postgres -v ON_ERROR_STOP=1 -qAt)
  "${PSQL[@]}" -c "SELECT 1 FROM pg_roles WHERE rolname='agentry'" | grep 1 >/dev/null || \
    "${PSQL[@]}" -c "CREATE ROLE agentry LOGIN PASSWORD 'agentry' SUPERUSER"
  for db in agentry_dev agentry_test; do
    "${PSQL[@]}" -c "SELECT 1 FROM pg_database WHERE datname='$db'" | grep 1 >/dev/null || \
      "${PSQL[@]}" -c "CREATE DATABASE $db OWNER agentry"
  done
  echo "postgres up on :$PORT (data: $DATA)"
}

down() {
  if "$PGBIN/pg_ctl" -D "$DATA" status >/dev/null 2>&1; then
    "$PGBIN/pg_ctl" -D "$DATA" stop -m fast >/dev/null
    echo "postgres stopped"
  else
    echo "postgres not running"
  fi
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  status) "$PGBIN/pg_ctl" -D "$DATA" status ;;
  url) echo "$URL_DEV" ;;
  test-url) echo "$URL_TEST" ;;
  *) echo "usage: pg.sh up|down|status|url|test-url" >&2; exit 2 ;;
esac
