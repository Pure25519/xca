#!/bin/sh
# The explicit limits of xca-server (BTD-304): with limits.worker_threads 1
# and limits.accept_queue_max 1, one idle client holds the only thread and a
# second one the only queue place; a third connection is refused at once
# (closed without an HTTP answer, not queued without bound), the server
# logs accept_queue_full, and once the idle clients are gone a request is
# served again.
# Environment: SERVER, BXC_PKI, OPENSSL, WORK.

set -u
for v in SERVER BXC_PKI OPENSSL WORK; do
    eval "val=\${$v:-}"
    [ -n "$val" ] || { echo "FAIL: $v is not set" >&2; exit 1; }
done
[ -x "$SERVER" ] || { echo "FAIL: xca-server not built: $SERVER" >&2; exit 1; }

rm -rf "$WORK"
mkdir -p "$WORK/home" "$WORK/pki"
export HOME="$WORK/home"
unset QT_QPA_PLATFORM
cd "$WORK" || exit 1
P="$WORK/pki"
DB="$WORK/server.xdb"
export XCA_SERVER_DB_PASSWORD="Server-Db-Pw-304"
PORT=$((20000 + ($$ + 17) % 20000))
PID=""
IDLE=""
fails=0

log() { echo "$*" >&2; }
fail() { log "FAIL: $*"; fails=$((fails + 1)); }
ok() { log "ok $*"; }
cleanup() {
    for i in $IDLE; do kill -KILL "$i" 2>/dev/null; done
    [ -n "$PID" ] && kill -KILL "$PID" 2>/dev/null
}
die() {
    log "FAIL: $*"
    cleanup
    exit 1
}

o() { "$OPENSSL" "$@" > /dev/null 2>&1 || die "openssl $1 failed"; }
o req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$P/ca.key" \
    -out "$P/ca.pem" -subj "/CN=xca-server limits test CA" -days 2
for n in server client; do
    o req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$P/$n.key" \
        -out "$P/$n.csr" -subj "/CN=$n"
done
printf 'subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > "$P/server.ext"
printf 'extendedKeyUsage=clientAuth\n' > "$P/client.ext"
o x509 -req -in "$P/server.csr" -CA "$P/ca.pem" -CAkey "$P/ca.key" -CAcreateserial \
    -out "$P/server.pem" -days 2 -extfile "$P/server.ext"
o x509 -req -in "$P/client.csr" -CA "$P/ca.pem" -CAkey "$P/ca.key" -CAcreateserial \
    -out "$P/client.pem" -days 2 -extfile "$P/client.ext"

"$BXC_PKI" init --db "$DB" --password env:XCA_SERVER_DB_PASSWORD \
    --cn "Limits Test CA" --validity P1Y > "$WORK/init.json" 2> "$WORK/init.err" ||
    die "bxc-pki init failed: $(cat "$WORK/init.err")"
cat > "$WORK/xca-server.json" <<EOF
{
  "schema": "urn:bxc-pki:schema:xca-server:v1",
  "listen": { "address": "127.0.0.1", "port": $PORT },
  "database": { "path": "$DB", "password": "env:XCA_SERVER_DB_PASSWORD" },
  "tls": { "cert": "$P/server.pem", "key": "$P/server.key", "client_ca": "$P/ca.pem" },
  "limits": { "payload_max_bytes": 65536, "header_max_bytes": 8192,
              "read_timeout_s": 20, "write_timeout_s": 10, "keep_alive_max_count": 10,
              "job_timeout_s": 60, "queue_max": 64,
              "worker_threads": 1, "accept_queue_max": 1 },
  "auth": { "api_keys": false, "denied_per_minute": 1000 },
  "roles": [ { "name": "reader",
               "client_certs": [ { "subject": "CN=client",
                                   "issuer": "CN=xca-server limits test CA" } ] } ]
}
EOF

# req <out>: GET /v1/health, the s_client output
req() {
    printf 'GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' |
        timeout 30 "$OPENSSL" s_client -quiet -connect "127.0.0.1:$PORT" \
            -CAfile "$P/ca.pem" -cert "$P/client.pem" -key "$P/client.key" > "$1" 2>&1
}

"$SERVER" --config "$WORK/xca-server.json" > "$WORK/server.out" 2> "$WORK/server.err" &
PID=$!
up=0
for _ in $(seq 1 60); do
    kill -0 "$PID" 2> /dev/null || die "xca-server exited at start: $(cat "$WORK/server.err")"
    req "$WORK/up.txt"
    if grep -q '^HTTP/1.1 200' "$WORK/up.txt"; then up=1; break; fi
    sleep 1
done
[ "$up" = 1 ] || die "xca-server does not answer /v1/health: $(cat "$WORK/server.err")"
ok "start with worker_threads 1, accept_queue_max 1"

# two idle clients: one holds the thread (handshake done, no request until
# the read timeout), one waits in the queue
for i in 1 2; do
    sleep 25 | timeout 40 "$OPENSSL" s_client -quiet -connect "127.0.0.1:$PORT" \
        -CAfile "$P/ca.pem" -cert "$P/client.pem" -key "$P/client.key" \
        > "$WORK/idle$i.txt" 2>&1 &
    IDLE="$IDLE $!"
    sleep 2
done

# the third connection is refused at once
start=$(date +%s)
req "$WORK/third.txt"
took=$(( $(date +%s) - start ))
if grep -q '^HTTP/' "$WORK/third.txt"; then
    fail "the third connection got an answer: $(grep '^HTTP/' "$WORK/third.txt")"
elif [ "$took" -gt 5 ]; then
    fail "the third connection waited ${took}s instead of being refused at once"
else
    ok "the third connection is refused at once (${took}s, no HTTP answer)"
fi
grep -q 'accept_queue_full' "$WORK/server.err" ||
    fail "no accept_queue_full in the server log: $(tail -3 "$WORK/server.err")"

# the idle clients gone, the server serves again
for i in $IDLE; do kill -KILL "$i" 2>/dev/null; wait "$i" 2>/dev/null; done
IDLE=""
served=0
for _ in $(seq 1 40); do
    req "$WORK/after.txt"
    if grep -q '^HTTP/1.1 200' "$WORK/after.txt"; then served=1; break; fi
    sleep 1
done
[ "$served" = 1 ] && ok "served again once the idle clients are gone" ||
    fail "not served after the idle clients are gone"

kill -TERM "$PID"
wait "$PID" 2> /dev/null
PID=""
cleanup
[ "$fails" -eq 0 ] || { log "FAIL: $fails check(s)"; exit 1; }
log "ok: explicit limits"
