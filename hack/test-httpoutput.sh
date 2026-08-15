#!/usr/bin/env bash
#
# test-httpoutput.sh — end-to-end smoke test for the Cloudanix --httpoutput path.
#
# Exercises the full dispatch chain that the upstream merge touched:
#   --httpoutput flag (cmd/root.go) -> writeHttpOutput (cmd/common.go)
#   -> initHttpConfig + publishResults (cmd/http.go) which depend on
#   github.com/hashicorp/go-retryablehttp and github.com/google/uuid.
#
# cmd/http.go reads three FIXED paths (not flag-overridable):
#   /etc/cdx/config/config.yaml      <- listenerUrl + account/cluster fields
#   /etc/cdx/secrets/auth-token      <- bearer token
#   env NODE_NAME, env SERVICE_VERSION <- node name + service version headers
# so this script needs sudo to populate /etc/cdx.
#
# Usage:
#   hack/test-httpoutput.sh [BENCHMARK] [TARGETS]
#   BENCHMARK defaults to cis-1.12, TARGETS defaults to master.
#
# Run from the repo root. NOT for sandboxed environments (needs port bind + /etc write).

set -euo pipefail

BENCHMARK="${1:-cis-1.12}"
TARGETS="${2:-master}"
PORT="${PORT:-9999}"
LISTENER_URL="http://localhost:${PORT}/ingest"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

CDX_CONFIG_DIR="/etc/cdx/config"
CDX_SECRETS_DIR="/etc/cdx/secrets"
TMP_BIN="$(mktemp -d)/kube-bench"
LISTENER_LOG="$(mktemp)"
LISTENER_PID=""

cleanup() {
  [ -n "$LISTENER_PID" ] && kill "$LISTENER_PID" 2>/dev/null || true
  rm -f "$LISTENER_LOG"
}
trap cleanup EXIT

echo "==> building kube-bench"
go build -o "$TMP_BIN" .

echo "==> writing /etc/cdx config + secret (needs sudo)"
sudo mkdir -p "$CDX_CONFIG_DIR" "$CDX_SECRETS_DIR"
sudo tee "$CDX_CONFIG_DIR/config.yaml" >/dev/null <<EOF
listenerUrl: "${LISTENER_URL}"
accountId: "test-acct"
clusterIdentifier: "test-cluster-id"
clusterName: "test-cluster"
clusterDomain: "test.local"
EOF
echo -n "test-auth-token" | sudo tee "$CDX_SECRETS_DIR/auth-token" >/dev/null

echo "==> starting mock listener on :${PORT}"
python3 - "$PORT" "$LISTENER_LOG" <<'PYEOF' &
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
port = int(sys.argv[1])
logf = open(sys.argv[2], "w")
class H(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence default access log
        pass
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n)
        logf.write("---REQUEST---\n")
        for k, v in self.headers.items():
            logf.write(f"{k}: {v}\n")
        logf.write(f"BODY_BYTES: {len(body)}\n")
        logf.flush()
        self.send_response(200); self.end_headers(); self.wfile.write(b'{"ok":true}')
HTTPServer(("localhost", port), H).serve_forever()
PYEOF
LISTENER_PID=$!
sleep 1

echo "==> running kube-bench with --httpoutput=true"
export NODE_NAME="test-node" SERVICE_VERSION="0.15.6-cdx"
"$TMP_BIN" run --targets "$TARGETS" --benchmark "$BENCHMARK" --httpoutput=true || true

sleep 1
echo
echo "==> listener received:"
cat "$LISTENER_LOG"

echo
echo "==> validating expected headers"
fail=0
check_header() {
  if grep -qi "^$1: $2" "$LISTENER_LOG"; then
    echo "  OK   $1: $2"
  else
    echo "  MISS $1 (expected: $2)"
    fail=1
  fi
}
check_header "cdx-template-type"   "KUBERNETESMISCONFIG"
check_header "cdx-service-version" "0.15.6-cdx"
check_header "cdx-node-name"       "test-node"
check_header "Authorization"       "Bearer test-auth-token"
check_header "cdx-account-id"      "test-acct"
check_header "cdx-cluster-name"    "test-cluster"
grep -qi "^cdx-session-id: " "$LISTENER_LOG" && echo "  OK   cdx-session-id present" || { echo "  MISS cdx-session-id"; fail=1; }

echo
if [ "$fail" -eq 0 ]; then
  echo "PASS: httpoutput path intact post-merge"
else
  echo "FAIL: missing headers above"
  exit 1
fi
