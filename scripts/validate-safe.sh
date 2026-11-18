#!/bin/bash
# Build nginx natively (aarch64 works; the root cause is not
# architecture-specific), serve an 896-byte static file over HTTP/2, and assert
# that --safe distinguishes the vulnerable and patched trees.
#
#   ./scripts/validate-safe.sh                 # both versions
#   ./scripts/validate-safe.sh release-1.31.8  # one version
set -euo pipefail

ROOT="${ROOT:-$HOME/poc/nginx/nginx}"
POC="$(cd "$(dirname "$0")/.." && pwd)/target/release/poc"
PORT="${PORT:-8443}"

if [ ! -x "$POC" ]; then
  echo "build the tool first: cargo build --release" >&2
  exit 1
fi

build_and_start() {
  local version="$1"
  local build="/tmp/poc-nginx-$version"
  if [ ! -x "$build/objs/nginx" ]; then
    rm -rf "$build"
    mkdir -p "$build"
    git -C "$ROOT" archive "$version" | tar -x -C "$build"
    (
      cd "$build"
      ./auto/configure \
        --prefix="$build/run" \
        --with-http_ssl_module \
        --with-http_v2_module \
        --without-http_rewrite_module \
        --without-http_gzip_module >/dev/null
      make -j"$(nproc)" >/dev/null
      make install >/dev/null
    )
  fi

  local run="$build/run"
  mkdir -p "$build/logs" "$run/logs" "$run/html"
  python3 - "$run/html/index.html" <<'PY'
import sys
body = (b"<!doctype html>\n<html><head><title>poc</title></head><body>\n"
        + b"golden fixture for CVE-2026-123007; " * 20)
open(sys.argv[1], "wb").write(body[:896].ljust(896, b"."))
PY

  if [ ! -f "$build/nginx-h2.crt" ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 3 \
      -keyout "$build/nginx-h2.key" -out "$build/nginx-h2.crt" \
      -subj /CN=localhost -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
  fi

  cat > "$build/nginx.conf" <<EOF
user $(id -un);
worker_processes 4;
pid $build/nginx.pid;
error_log $build/logs/error.log info;
events { worker_connections 1024; }
http {
    default_type application/octet-stream;
    access_log $build/logs/access.log;
    sendfile on;
    keepalive_timeout 65;
    keepalive_requests 100000;
    keepalive_time 1h;
    server {
        listen $PORT ssl;
        http2 on;
        server_name localhost;
        ssl_certificate $build/nginx-h2.crt;
        ssl_certificate_key $build/nginx-h2.key;
        root $run/html;
        location / { try_files \$uri \$uri/ =404; }
    }
}
EOF

  if [ -f "$build/nginx.pid" ]; then
    kill "$(cat "$build/nginx.pid")" 2>/dev/null || true
    sleep 0.3
  fi
  "$build/objs/nginx" -p "$build" -c "$build/nginx.conf"
  NGINX_PID_FILE="$build/nginx.pid"
}

stop_target() {
  if [ -n "${NGINX_PID_FILE:-}" ] && [ -f "$NGINX_PID_FILE" ]; then
    kill "$(cat "$NGINX_PID_FILE")" 2>/dev/null || true
    sleep 0.3
    NGINX_PID_FILE=""
  fi
}
trap stop_target EXIT

check() {
  local version="$1" expected="$2" expected_status="$3"
  build_and_start "$version"
  sleep 0.4
  echo "== $(/tmp/poc-nginx-"$version"/objs/nginx -v 2>&1)"
  set +e
  output=$("$POC" --host "https://127.0.0.1:$PORT" --safe 2>&1)
  status=$?
  set -e
  echo "$output"
  if ! grep -q "$expected" <<<"$output"; then
    echo "FAIL: expected $expected for $version (exit $status)" >&2
    stop_target
    return 1
  fi
  if [ "$status" -ne "$expected_status" ]; then
    echo "FAIL: expected exit $expected_status for $version, got $status" >&2
    stop_target
    return 1
  fi
  stop_target
  echo "OK: $version -> $expected (exit $status)"
}

if [ $# -ge 1 ]; then
  case "$1" in
    *1.31.8*) check "$1" "VULNERABLE" 0 ;;
    *) check "$1" "NOT PROVEN" 4 ;;
  esac
else
  check release-1.31.8 "VULNERABLE" 0
  check master "NOT PROVEN" 4
fi
