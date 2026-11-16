#!/bin/sh
# xca-server from start to stop (BTD-154), against a real database and mTLS:
#  1. a test PKI (openssl): CA, server certificate for 127.0.0.1, a client
#     certificate, and a client certificate of a foreign CA
#  2. a database (bxc-pki init), the server started with xca-server.json
#  3. GET /v1/health and /v1/status over mTLS; the actor is cert:<SHA-256 of
#     the client certificate>, and the status job ran on the DB worker
#  4. no client certificate, or one of the foreign CA: the handshake fails,
#     no HTTP answer
#  5. 50 parallel status requests: every one 200, every one on the worker,
#     no SQLite busy or locked error
#  6. an unknown path: 404 application/problem+json
#  7. the database is the server's: bxc-pki list and a second server are
#     refused with database_in_use
#  8. SIGTERM: exit 0; the audit log has server.start and server.stop with
#     the channel rest, xca --audit-verify is ok, and bxc-pki opens the
#     database again
# Environment: SERVER, BXC_PKI, XCA, SQL_EXEC, OPENSSL, WORK.

set -u
for v in SERVER BXC_PKI XCA SQL_EXEC OPENSSL WORK; do
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
export XCA_SERVER_DB_PASSWORD="Server-Db-Pw-154"
PORT=$((20000 + $$ % 20000))
PID=""
fails=0

log() { echo "$*" >&2; }
fail() { log "FAIL: $*"; fails=$((fails + 1)); }
ok() { log "ok $*"; }
die() {
    log "FAIL: $*"
    [ -n "$PID" ] && kill -KILL "$PID" 2>/dev/null
    exit 1
}

# 1. the test PKI
o() { "$OPENSSL" "$@" > /dev/null 2>&1 || die "openssl $1 failed"; }
o req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$P/ca.key" \
    -out "$P/ca.pem" -subj "/CN=xca-server test CA" -days 2
o req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$P/other.key" \
    -out "$P/other.pem" -subj "/CN=foreign CA" -days 2
for n in server client foreign; do
    o req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$P/$n.key" \
        -out "$P/$n.csr" -subj "/CN=$n"
done
printf 'subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > "$P/server.ext"
printf 'extendedKeyUsage=clientAuth\n' > "$P/client.ext"
o x509 -req -in "$P/server.csr" -CA "$P/ca.pem" -CAkey "$P/ca.key" -CAcreateserial \
    -out "$P/server.pem" -days 2 -extfile "$P/server.ext"
o x509 -req -in "$P/client.csr" -CA "$P/ca.pem" -CAkey "$P/ca.key" -CAcreateserial \
    -out "$P/client.pem" -days 2 -extfile "$P/client.ext"
o x509 -req -in "$P/foreign.csr" -CA "$P/other.pem" -CAkey "$P/other.key" -CAcreateserial \
    -out "$P/foreign.pem" -days 2 -extfile "$P/client.ext"
FP=$("$OPENSSL" x509 -in "$P/client.pem" -noout -fingerprint -sha256 | cut -d= -f2 |
    tr -d : | tr 'A-F' 'a-f')

# 2. the database and the server
"$BXC_PKI" init --db "$DB" --password env:XCA_SERVER_DB_PASSWORD \
    --cn "Server Test CA" --validity P1Y > "$WORK/init.json" 2> "$WORK/init.err" ||
    die "bxc-pki init failed: $(cat "$WORK/init.err")"
config() {
    cat <<EOF
{
  "schema": "urn:bxc-pki:schema:xca-server:v1",
  "listen": { "address": "127.0.0.1", "port": $1 },
  "database": { "path": "$DB", "password": "env:XCA_SERVER_DB_PASSWORD" },
  "tls": { "cert": "$P/server.pem", "key": "$P/server.key", "client_ca": "$P/ca.pem" },
  "limits": { "payload_max_bytes": 65536, "header_max_bytes": 8192,
              "read_timeout_s": 10, "write_timeout_s": 10, "keep_alive_max_count": 10,
              "job_timeout_s": 60, "queue_max": 64 },
  "auth": { "api_keys": false, "denied_per_minute": 100 },
  "roles": [ { "name": "reader",
               "client_certs": [ { "subject": "CN=client", "issuer": "CN=xca-server test CA" } ] } ]
}
EOF
}
config "$PORT" > "$WORK/xca-server.json"
"$SERVER" --config "$WORK/xca-server.json" > "$WORK/server.out" 2> "$WORK/server.err" &
PID=$!

# req <path> [cert key]: one HTTP/1.1 request over TLS, the raw answer
req() {
    if [ $# -ge 3 ]; then
        auth="-cert $2 -key $3"
    else
        auth=""
    fi
    # shellcheck disable=SC2086
    printf 'GET %s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' "$1" |
        timeout 30 "$OPENSSL" s_client -quiet -connect "127.0.0.1:$PORT" \
            -CAfile "$P/ca.pem" $auth 2> /dev/null
}

up=0
for _ in $(seq 1 60); do
    kill -0 "$PID" 2> /dev/null || die "xca-server exited at start: $(cat "$WORK/server.err")"
    if req /v1/health "$P/client.pem" "$P/client.key" | grep -q '^HTTP/1.1 200'; then
        up=1
        break
    fi
    sleep 1
done
[ "$up" = 1 ] || die "xca-server does not answer /v1/health: $(cat "$WORK/server.err")"
ok "start, /v1/health"

# 3. status over mTLS
req /v1/status "$P/client.pem" "$P/client.key" > "$WORK/status.txt"
grep -q '^HTTP/1.1 200' "$WORK/status.txt" || fail "/v1/status: $(head -1 "$WORK/status.txt")"
grep -q "\"actor\": *\"cert:$FP\"" "$WORK/status.txt" ||
    fail "/v1/status: actor is not cert:$FP: $(tail -1 "$WORK/status.txt")"
grep -q '"on_worker": *true' "$WORK/status.txt" ||
    fail "/v1/status: the job did not run on the DB worker"
ok "status over mTLS, actor cert:$FP"

# 4. no client certificate, or a foreign one
req /v1/status > "$WORK/nocert.txt"
grep -q '^HTTP/' "$WORK/nocert.txt" && fail "an answer without client certificate"
req /v1/status "$P/foreign.pem" "$P/foreign.key" > "$WORK/foreign.txt"
grep -q '^HTTP/' "$WORK/foreign.txt" && fail "an answer to a certificate of a foreign CA"
ok "no answer without a certificate of the client CA"

# 5. 50 requests at once
mkdir -p "$WORK/load"
i=0
# the PIDs by $!: in dash, $(jobs -p) runs in a subshell and lists nothing
load_pids=""
while [ $i -lt 50 ]; do
    req /v1/status "$P/client.pem" "$P/client.key" > "$WORK/load/$i.txt" &
    load_pids="$load_pids $!"
    i=$((i + 1))
done
wait_load=0
for j in $load_pids; do
    wait "$j" || wait_load=1
done
n200=$(grep -l '^HTTP/1.1 200' "$WORK"/load/*.txt | wc -l)
nworker=$(grep -l '"on_worker": *true' "$WORK"/load/*.txt | wc -l)
[ "$n200" -eq 50 ] || fail "parallel load: $n200 of 50 answers 200"
[ "$nworker" -eq 50 ] || fail "parallel load: $nworker of 50 jobs on the DB worker"
if grep -qiE 'database is locked|busy' "$WORK"/load/*.txt "$WORK/server.err"; then
    fail "parallel load: SQLite busy or locked"
fi
ok "50 parallel requests: $n200 x 200, $nworker on the DB worker"

# 6. unknown path
req /v1/nothing-here "$P/client.pem" "$P/client.key" > "$WORK/404.txt"
grep -q '^HTTP/1.1 404' "$WORK/404.txt" || fail "unknown path: $(head -1 "$WORK/404.txt")"
grep -qi '^content-type: application/problem+json' "$WORK/404.txt" ||
    fail "unknown path: no application/problem+json"
ok "unknown path: 404 problem+json"

# 7. the database belongs to the server
"$BXC_PKI" list --db "$DB" --password env:XCA_SERVER_DB_PASSWORD > "$WORK/list.out" 2> "$WORK/list.err"
rc=$?
[ "$rc" -ne 0 ] && grep -q '"code": *"database_in_use"' "$WORK/list.err" ||
    fail "bxc-pki list while the server runs: exit $rc, $(cat "$WORK/list.err")"
config $((PORT + 1)) > "$WORK/second.json"
timeout 60 "$SERVER" --config "$WORK/second.json" > "$WORK/second.out" 2> "$WORK/second.err"
rc=$?
[ "$rc" -ne 0 ] && grep -q '"code": *"database_in_use"' "$WORK/second.err" ||
    fail "a second server on the database: exit $rc, $(cat "$WORK/second.err")"
ok "bxc-pki and a second server refused with database_in_use"

# 8. stop
kill -TERM "$PID"
rc=0
wait "$PID" || rc=$?
PID=""
[ "$rc" -eq 0 ] || fail "xca-server exit $rc after SIGTERM: $(cat "$WORK/server.err")"
"$SQL_EXEC" "$DB" -c "SELECT action || ' ' || channel FROM audit_log WHERE action LIKE 'server.%' ORDER BY seq" \
    > "$WORK/server-entries.txt" 2>&1
printf 'server.start rest\nserver.stop rest\n' > "$WORK/expected-entries.txt"
diff "$WORK/expected-entries.txt" "$WORK/server-entries.txt" > /dev/null ||
    fail "audit entries of the server: $(cat "$WORK/server-entries.txt")"
QT_QPA_PLATFORM=offscreen "$XCA" --no-gui --database="$DB" --password=env:XCA_SERVER_DB_PASSWORD \
    --audit-verify > "$WORK/audit-verify.json" 2> "$WORK/audit-verify.err" ||
    fail "xca --audit-verify: $(cat "$WORK/audit-verify.json" "$WORK/audit-verify.err")"
"$BXC_PKI" list --db "$DB" --password env:XCA_SERVER_DB_PASSWORD > /dev/null 2> "$WORK/after.err" ||
    fail "bxc-pki list after the stop: $(cat "$WORK/after.err")"
ok "stop: exit 0, server.start and server.stop, audit verified, database free again"

[ "$fails" -eq 0 ] || { log "FAIL: $fails check(s)"; exit 1; }
log "ok: xca-server lifecycle"
