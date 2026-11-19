#!/bin/sh
# HTTP contract answers that cpp-httplib's parser decides before the
# pre-routing handler of xca-server (BTD-318, BTD-319):
#  1. a method outside the library's built-in set (QUERY, PROPFIND) and an
#     undeclared built-in one (TRACE): 405 application/problem+json with
#     code method_not_allowed and the Allow header of the path
#  2. a method token in no registry (FOOBAR): 400 bad_request, the
#     documented deviation (cpp-httplib only accepts registered tokens)
#  3. one header line over header_max_bytes (8192) up to the line limit of
#     16384: 431 header_too_large; several lines over it: 431 as well
#  4. one header line over the line limit: 400, the documented deviation
#  5. the server still answers afterwards
# Environment: SERVER, BXC_PKI, OPENSSL, WORK, CMAKE, SERVER_TEST_DIR.

set -u
for v in SERVER BXC_PKI OPENSSL WORK CMAKE SERVER_TEST_DIR; do
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
export XCA_SERVER_DB_PASSWORD="Server-Db-Pw-318"
PORT=$((20000 + ($$ + 31) % 20000))
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
    -out "$P/ca.pem" -subj "/CN=xca-server http test CA" -days 2
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
    --cn "HTTP Test CA" --validity P1Y > "$WORK/init.json" 2> "$WORK/init.err" ||
    die "bxc-pki init failed: $(cat "$WORK/init.err")"
# the base config of the server tests with this test's members (BTD-320)
. "$SERVER_TEST_DIR/config/lib.sh"
xs_config listen/port "$PORT" database/path "$(xs_str "$DB")" \
    tls/cert "$(xs_str "$P/server.pem")" tls/key "$(xs_str "$P/server.key")" \
    tls/client_ca "$(xs_str "$P/ca.pem")" \
    roles "[ $(xs_role reader '"client_certs": [ { "subject": "CN=client", "issuer": "CN=xca-server http test CA" } ]') ]" \
    > "$WORK/xca-server.json" || die "xs_config failed"
"$SERVER" --config "$WORK/xca-server.json" > "$WORK/server.out" 2> "$WORK/server.err" &
PID=$!

# req <file> <method> <path> [<extra header line>...]: one request with the
# client certificate, the raw answer in <file>
req() {
    out=$1 method=$2 path=$3
    shift 3
    {
        printf '%s %s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n' "$method" "$path"
        for h in "$@"; do printf '%s\r\n' "$h"; done
        printf '\r\n'
    } | timeout 30 "$OPENSSL" s_client -quiet -connect "127.0.0.1:$PORT" \
        -CAfile "$P/ca.pem" -cert "$P/client.pem" -key "$P/client.key" \
        > "$out" 2> /dev/null
}
# filler <n>: n bytes of 'a'
filler() { head -c "$1" /dev/zero | tr '\0' a; }

up=0
for _ in $(seq 1 60); do
    kill -0 "$PID" 2> /dev/null || die "xca-server exited at start: $(cat "$WORK/server.err")"
    req "$WORK/up.txt" GET /v1/health
    if grep -q '^HTTP/1.1 200' "$WORK/up.txt"; then
        up=1
        break
    fi
    sleep 1
done
[ "$up" = 1 ] || die "xca-server does not answer /v1/health: $(cat "$WORK/server.err")"
ok "start, /v1/health"

# expect <tag> <file> <status> <code> [<Allow value>]
expect() {
    tag=$1 f=$2 status=$3 code=$4 allow=${5:-}
    line=$(head -1 "$f" | tr -d '\r')
    if ! echo "$line" | grep -q "^HTTP/1.1 $status "; then
        fail "$tag: not $status: ${line:-no answer}"
        return
    fi
    grep -qi '^Content-Type: application/problem+json' "$f" ||
        { fail "$tag: no application/problem+json"; return; }
    grep -q "\"code\":\"$code\"" "$f" ||
        { fail "$tag: not code $code: $(tail -1 "$f")"; return; }
    if [ -n "$allow" ]; then
        got=$(grep -i '^Allow:' "$f" | tr -d '\r' | cut -d' ' -f2-)
        [ "$got" = "$allow" ] || { fail "$tag: Allow is '$got', not '$allow'"; return; }
    fi
    ok "$tag: $status $code${allow:+, Allow: $allow}"
}

# 1. methods the path does not declare
req "$WORK/query-health.txt" QUERY /v1/health
expect "QUERY /v1/health" "$WORK/query-health.txt" 405 method_not_allowed "GET, HEAD"
req "$WORK/query-status.txt" QUERY /v1/status
expect "QUERY /v1/status" "$WORK/query-status.txt" 405 method_not_allowed "GET, HEAD"
req "$WORK/propfind.txt" PROPFIND /v1/health
expect "PROPFIND /v1/health" "$WORK/propfind.txt" 405 method_not_allowed "GET, HEAD"
req "$WORK/trace.txt" TRACE /v1/health
expect "TRACE /v1/health" "$WORK/trace.txt" 405 method_not_allowed "GET, HEAD"

# 2. a token in no registry: the parser refuses it (documented deviation)
req "$WORK/foobar.txt" FOOBAR /v1/health
expect "FOOBAR /v1/health (deviation)" "$WORK/foobar.txt" 400 bad_request

# 3. header lines over header_max_bytes
req "$WORK/line-8200.txt" GET /v1/health "X-Long: $(filler 8200)"
expect "one header line of 8200 bytes" "$WORK/line-8200.txt" 431 header_too_large
req "$WORK/line-16000.txt" GET /v1/health "X-Long: $(filler 16000)"
expect "one header line of 16000 bytes" "$WORK/line-16000.txt" 431 header_too_large
req "$WORK/lines.txt" GET /v1/health "X-A: $(filler 3000)" "X-B: $(filler 3000)" \
    "X-C: $(filler 3000)"
expect "three header lines of 3000 bytes" "$WORK/lines.txt" 431 header_too_large

# 4. a line over the library's line limit (documented deviation)
req "$WORK/line-20000.txt" GET /v1/health "X-Long: $(filler 20000)"
expect "one header line of 20000 bytes (deviation)" "$WORK/line-20000.txt" 400 bad_request

# 5. still serving
req "$WORK/after.txt" GET /v1/health
grep -q '^HTTP/1.1 200' "$WORK/after.txt" || fail "no /v1/health after the cases"
kill -0 "$PID" 2> /dev/null || fail "xca-server is gone"

kill -TERM "$PID" 2> /dev/null
wait "$PID" 2> /dev/null
if [ "$fails" -ne 0 ]; then
    log "FAIL: $fails check(s)"
    exit 1
fi
log "ok: HTTP contract answers"
