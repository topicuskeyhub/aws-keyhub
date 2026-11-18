#!/usr/bin/env bash
# End-to-end test of the `browserCommand` setting (keyhub.browserCommand in config-v2.json).
#
# Runs `aws-keyhub login` against a fake KeyHub (local python HTTP server) with a temporary HOME,
# so the user's real configuration is never touched. The "browser" is a logging script that writes
# every received argument as [arg]; the system default browser (xdg-open) is replaced by a logging
# script that writes "DEFAULT [url]".
#
# Usage: test-browser-command.sh [path/to/aws-keyhub]   (default: ./build/linux-amd64/aws-keyhub)
# Exits with code 0 when all scenarios pass, 1 otherwise.
set -u

BIN=$(readlink -f "${1:-./build/linux-amd64/aws-keyhub}")
[ -x "$BIN" ] || { echo "Binary not found: $BIN" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }

WORK=$(mktemp -d)
trap 'kill $SERVER_PID 2>/dev/null; rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin"

PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
URL="http://127.0.0.1:$PORT/verify?code=ABCD&x=1"

cat > "$WORK/fake_keyhub.py" <<'EOF'
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
PORT = int(sys.argv[1])
polls = {}
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        if self.path.endswith("/authorizedevice"):
            # Unique device_code per login, so the poll counter restarts for every scenario.
            dev = "dev%d" % len(polls); polls[dev] = 0
            self.send(200, {"user_code": "ABCD", "device_code": dev, "interval": 1,
                            "verification_uri_complete": "http://127.0.0.1:%d/verify?code=ABCD&x=1" % PORT,
                            "verification_uri": "http://127.0.0.1:%d/verify" % PORT, "expires_in": 60})
            return
        dev = next((p.split("=", 1)[1] for p in body.split("&") if p.startswith("device_code=")), "")
        polls[dev] = polls.get(dev, 0) + 1
        # Answer "pending" twice so a failing browserCommand has time to fall back to the default browser.
        if polls[dev] < 3:
            self.send(400, {"error": "authorization_pending", "error_description": "pending"})
        else:
            self.send(400, {"error": "access_denied", "error_description": "fake keyhub: test done"})
HTTPServer(("127.0.0.1", PORT), H).serve_forever()
EOF

cat > "$WORK/bin/logbrowser" <<'EOF'
#!/bin/sh
{ printf 'BROWSER'; for a in "$@"; do printf ' [%s]' "$a"; done; printf '\n'; } >> "$LOGFILE"
EOF
cat > "$WORK/bin/failbrowser" <<'EOF'
#!/bin/sh
{ printf 'FAILBROWSER'; for a in "$@"; do printf ' [%s]' "$a"; done; printf '\n'; } >> "$LOGFILE"
exit 3
EOF
cat > "$WORK/bin/xdg-open" <<'EOF'
#!/bin/sh
{ printf 'DEFAULT'; for a in "$@"; do printf ' [%s]' "$a"; done; printf '\n'; } >> "$LOGFILE"
EOF
chmod +x "$WORK/bin/"*

python3 "$WORK/fake_keyhub.py" "$PORT" &
SERVER_PID=$!
sleep 0.5

FAILED=0
# scenario <name> <browserCommand-json> <expected browser log (lines separated by \n)> [expected text in output]
scenario() {
  local name=$1 bc=$2 expected=$3 expected_out=${4:-}
  local home="$WORK/home-$name"
  export LOGFILE="$WORK/log-$name.txt"
  mkdir -p "$home/.aws-keyhub" "$home/.aws"
  printf '[default]\nregion = eu-west-1\n' > "$home/.aws/config"
  : > "$home/.aws/credentials"
  printf '{"keyhub":{"url":"http://127.0.0.1:%s","clientId":"c","awsSamlClientId":"s","allowInsecureTLS":false,"browserCommand":%s},"aws":{"assumeDuration":3600}}\n' \
    "$PORT" "$bc" > "$home/.aws-keyhub/config-v2.json"

  local out
  out=$(HOME="$home" PATH="$WORK/bin:$PATH" timeout 20 "$BIN" login 2>&1)
  local actual
  actual=$(cat "$LOGFILE" 2>/dev/null)

  local ok=1
  [ "$actual" = "$(printf "$expected")" ] || ok=0
  [ -z "$expected_out" ] || grep -qF -- "$expected_out" <<<"$out" || ok=0
  grep -q 'fake keyhub: test done' <<<"$out" || ok=0

  if [ $ok = 1 ]; then
    echo "PASS  $name"
  else
    FAILED=1
    echo "FAIL  $name"
    echo "  browserCommand: $bc"
    echo "  expected log:   $(printf "$expected" | tr '\n' '|')"
    echo "  actual log:     $(tr '\n' '|' <<<"$actual")"
    [ -z "$expected_out" ] || echo "  expected output to contain: $expected_out"
    echo "  output:"; sed 's/^/    /' <<<"$out"
  fi
}

scenario placeholder   '["logbrowser","-P","my profile","--new-tab","{url}"]' "BROWSER [-P] [my profile] [--new-tab] [$URL]"
scenario append-url    '["logbrowser","--flag"]'                                "BROWSER [--flag] [$URL]"
scenario embedded      '["logbrowser","--app={url}"]'                           "BROWSER [--app=$URL]"
scenario not-found     '["does-not-exist-browser","{url}"]'                     "DEFAULT [$URL]" "Failed to start configured browserCommand"
scenario exits-nonzero '["failbrowser","{url}"]'                                "FAILBROWSER [$URL]\nDEFAULT [$URL]" "Configured browserCommand failed"
scenario not-set       'null'                                                   "DEFAULT [$URL]"
scenario empty-array   '[]'                                                     "DEFAULT [$URL]"
scenario blank-exe     '[" "]'                                                  "DEFAULT [$URL]"

exit $FAILED
