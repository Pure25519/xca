#!/bin/sh
# The health listener of xca-server (BTD-163): plain HTTP on loopback,
# exactly GET /health and GET /ready, no details, no client certificate.
#  1. /health 200 {"status":"ok"}, /ready 200 once the server runs; every
#     other path and method 404, a declared body is not read
#  2. the database is unavailable (another process holds BEGIN EXCLUSIVE):
#     /ready 503 {"status":"not_ready"}, /health still 200 at once; ready
#     again when the lock is gone
#  3. the database worker is stuck (test seam, BXC_PKI_TEST_SEAMS=1): /ready
#     503 while it stalls, /health 200, ready again afterwards
#  4. without BXC_PKI_TEST_SEAMS the seam path is 404 like any other
#  5. without "health" in xca-server.json nothing listens on that port
# Environment: SERVER, BXC_PKI, SQL_EXEC, OPENSSL, WORK, CMAKE,
# SERVER_TEST_DIR, CURL.

set -u
for v in SERVER BXC_PKI SQL_EXEC OPENSSL WORK CMAKE SERVER_TEST_DIR CURL; do
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
DB="$WORK/health.xdb"
export XCA_SERVER_DB_PASSWORD="Server-Db-Pw-163"
PORT=$((20000 + $$ % 20000))
HPORT=$((PORT + 1))
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

o() { "$OPENSSL" "$@" > /dev/null 2>&1 || die "openssl $1 failed"; }
o req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$P/ca.key" \
    -out "$P/ca.pem" -subj "/CN=xca-server health test CA" -days 2
o req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$P/server.key" \
    -out "$P/server.csr" -subj "/CN=server"
printf 'subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > "$P/server.ext"
o x509 -req -in "$P/server.csr" -CA "$P/ca.pem" -CAkey "$P/ca.key" -CAcreateserial \
    -out "$P/server.pem" -days 2 -extfile "$P/server.ext"

"$BXC_PKI" init --db "$DB" --password env:XCA_SERVER_DB_PASSWORD \
    --cn "Health Test CA" --validity P1Y > "$WORK/init.json" 2> "$WORK/init.err" ||
    die "bxc-pki init failed: $(cat "$WORK/init.err")"

. "$SERVER_TEST_DIR/config/lib.sh"
# config [<health JSON>]: the base config with this test's members; a job
# timeout of 2 s, so a stuck worker shows quickly
config() {
    if [ $# -ge 1 ]; then
        set -- health "$1"
    fi
    xs_config listen/port "$PORT" database/path "$(xs_str "$DB")" \
        tls/cert "$(xs_str "$P/server.pem")" tls/key "$(xs_str "$P/server.key")" \
        tls/client_ca "$(xs_str "$P/ca.pem")" limits/job_timeout_s 2 "$@"
}

# get <out> <method> <path> [curl options]: one plain HTTP request to the
# health listener; <out> gets the status line and the body
get() {
    out=$1; method=$2; path=$3; shift 3
    "$CURL" -s -o "$out.body" -w '%{http_code}' -X "$method" --max-time 10 "$@" \
        "http://127.0.0.1:$HPORT$path" > "$out.code" 2> "$out.err"
}
code() { cat "$1.code" 2> /dev/null; }
body() { cat "$1.body" 2> /dev/null; }

start() {
    "$SERVER" --config "$WORK/xca-server.json" > "$WORK/server.out" 2> "$WORK/server.err" &
    PID=$!
    for _ in $(seq 1 60); do
        kill -0 "$PID" 2> /dev/null || die "xca-server exited at start: $(cat "$WORK/server.err")"
        get "$WORK/up" GET /ready
        [ "$(code "$WORK/up")" = 200 ] && return 0
        sleep 1
    done
    die "xca-server is not ready: $(cat "$WORK/server.err")"
}
stop() {
    kill -TERM "$PID"
    rc=0
    wait "$PID" || rc=$?
    PID=""
    [ "$rc" -eq 0 ] || fail "xca-server exit $rc after SIGTERM: $(cat "$WORK/server.err")"
}
# until_code <label> <path> <code> <seconds>: polls until the code comes
until_code() {
    i=0
    while [ $i -lt "$4" ]; do
        get "$WORK/poll" GET "$2"
        [ "$(code "$WORK/poll")" = "$3" ] && return 0
        sleep 1
        i=$((i + 1))
    done
    fail "$1: $2 did not answer $3 within $4 s (last $(code "$WORK/poll"): $(body "$WORK/poll"))"
    return 1
}

HEALTH="{ \"address\": \"127.0.0.1\", \"port\": $HPORT }"

# 1. the two probes, nothing else
config "$HEALTH" > "$WORK/xca-server.json" || die "no configuration"
BXC_PKI_TEST_SEAMS=1
export BXC_PKI_TEST_SEAMS
start
get "$WORK/h" GET /health
[ "$(code "$WORK/h")" = 200 ] && [ "$(body "$WORK/h")" = '{"status":"ok"}' ] ||
    fail "/health: $(code "$WORK/h") $(body "$WORK/h")"
get "$WORK/r" GET /ready
[ "$(code "$WORK/r")" = 200 ] && [ "$(body "$WORK/r")" = '{"status":"ok"}' ] ||
    fail "/ready: $(code "$WORK/r") $(body "$WORK/r")"
for path in / /v1/health /v1/status /metrics /v1/metrics /health/x /ready/ "/health?x=1"; do
    get "$WORK/p" GET "$path"
    case "$path" in
    "/health?x=1") want=200 ;;
    *) want=404 ;;
    esac
    [ "$(code "$WORK/p")" = "$want" ] || fail "GET $path: $(code "$WORK/p"), expected $want"
done
for method in POST PUT DELETE HEAD; do
    get "$WORK/m" "$method" /health
    [ "$(code "$WORK/m")" = 404 ] || fail "$method /health: $(code "$WORK/m"), expected 404"
done
# a declared body of 100 MB that never comes: the answer is there at once
get "$WORK/b" POST /health -H 'Content-Length: 104857600' --max-time 5
[ "$(code "$WORK/b")" = 404 ] || fail "POST /health with a declared body: $(code "$WORK/b")"
grep -q 'xca-server' "$WORK/h.body" "$WORK/r.body" && fail "the probes name the server"
ok "1. /health and /ready 200, everything else 404"

# 2. the database is unavailable
"$SQL_EXEC" "$DB" -c 'BEGIN EXCLUSIVE' --sleep 8 > "$WORK/lock.out" 2>&1 &
LOCK=$!
sleep 1
until_code "database locked" /ready 503 6 &&
    { [ "$(body "$WORK/poll")" = '{"status":"not_ready"}' ] ||
        fail "/ready while locked: $(body "$WORK/poll")"; }
t0=$(date +%s)
get "$WORK/h2" GET /health
t1=$(date +%s)
[ "$(code "$WORK/h2")" = 200 ] || fail "/health while the database is locked: $(code "$WORK/h2")"
[ $((t1 - t0)) -le 1 ] || fail "/health took $((t1 - t0)) s while the database is locked"
wait "$LOCK"
until_code "lock released" /ready 200 15
ok "2. database locked: not ready, ready again"

# 3. the worker is stuck
get "$WORK/s" POST "/_test/stall?seconds=6"
[ "$(code "$WORK/s")" = 202 ] || fail "the stall seam: $(code "$WORK/s") $(body "$WORK/s")"
until_code "worker stuck" /ready 503 4
get "$WORK/h3" GET /health
[ "$(code "$WORK/h3")" = 200 ] || fail "/health while the worker is stuck: $(code "$WORK/h3")"
until_code "worker free again" /ready 200 15
ok "3. worker stuck: not ready, ready again"
stop

# 4. without the seam variable the seam path is like any other
unset BXC_PKI_TEST_SEAMS
start
get "$WORK/s2" POST "/_test/stall?seconds=6"
[ "$(code "$WORK/s2")" = 404 ] || fail "the seam without BXC_PKI_TEST_SEAMS: $(code "$WORK/s2")"
get "$WORK/r4" GET /ready
[ "$(code "$WORK/r4")" = 200 ] || fail "/ready after the refused seam: $(code "$WORK/r4")"
ok "4. no seam without BXC_PKI_TEST_SEAMS"
stop

# 5. without "health" nothing listens there
config > "$WORK/xca-server.json" || die "no configuration"
"$SERVER" --config "$WORK/xca-server.json" > "$WORK/server.out" 2> "$WORK/server.err" &
PID=$!
sleep 3
kill -0 "$PID" 2> /dev/null || die "xca-server without health exited: $(cat "$WORK/server.err")"
get "$WORK/n" GET /health --max-time 3
[ "$(code "$WORK/n")" = 000 ] || fail "something answers on $HPORT without a health listener: $(code "$WORK/n")"
stop
ok "5. no health listener unless configured"

[ "$fails" -eq 0 ] || { log "FAIL: $fails check(s)"; exit 1; }
log "ok: xca-server health listener"
