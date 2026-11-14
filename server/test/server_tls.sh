#!/bin/sh
# The mTLS refusals of xca-server (BTD-306): each client below is refused in
# the TLS handshake with its own alert, gets no HTTP answer, and the server
# still answers a valid client afterwards (a crash or a timeout is no
# refusal):
#  1. no client certificate              alert certificate required
#  2. a certificate of a foreign CA      alert unknown ca
#  3. an expired client certificate      alert certificate expired
#  4. EKU serverAuth only (no clientAuth) alert unsupported certificate
#  5. TLS 1.1 and 6. TLS 1.0             alert protocol version
# A certificate without any EKU is valid for every purpose (RFC 5280);
# the test records that it is accepted. The lock after kill -9 is
# test_server_lock (BTD-302).
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
export XCA_SERVER_DB_PASSWORD="Server-Db-Pw-306"
PORT=$((20000 + ($$ + 13) % 20000))
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

o() { "$OPENSSL" "$@" > /dev/null 2>&1 || die "openssl $1 failed: $*"; }
o req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$P/ca.key" \
    -out "$P/ca.pem" -subj "/CN=xca-server TLS test CA" -days 2
o req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$P/other.key" \
    -out "$P/other.pem" -subj "/CN=foreign CA" -days 2
for n in server client foreign expired serveronly noeku; do
    o req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$P/$n.key" \
        -out "$P/$n.csr" -subj "/CN=$n"
done
printf 'subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > "$P/server.ext"
printf 'extendedKeyUsage=clientAuth\n' > "$P/client.ext"
printf 'extendedKeyUsage=serverAuth\n' > "$P/serveronly.ext"
printf 'basicConstraints=CA:FALSE\n' > "$P/noeku.ext"
sign() { # sign <name> <ext> [CA] [x509 options]
    n=$1; ext=$2; ca=${3:-ca}; shift 3 2>/dev/null || shift $#
    o x509 -req -in "$P/$n.csr" -CA "$P/$ca.pem" -CAkey "$P/$ca.key" -CAcreateserial \
        -out "$P/$n.pem" -extfile "$P/$ext.ext" "$@"
}
sign server server ca -days 2
sign client client ca -days 2
sign foreign client other -days 2
sign expired client ca -not_before 20200101000000Z -not_after 20200102000000Z
sign serveronly serveronly ca -days 2
sign noeku noeku ca -days 2

"$BXC_PKI" init --db "$DB" --password env:XCA_SERVER_DB_PASSWORD \
    --cn "TLS Test CA" --validity P1Y > "$WORK/init.json" 2> "$WORK/init.err" ||
    die "bxc-pki init failed: $(cat "$WORK/init.err")"
# every test client has a role: a refusal can only come from TLS
cat > "$WORK/xca-server.json" <<EOF
{
  "schema": "urn:bxc-pki:schema:xca-server:v1",
  "listen": { "address": "127.0.0.1", "port": $PORT },
  "database": { "path": "$DB", "password": "env:XCA_SERVER_DB_PASSWORD" },
  "tls": { "cert": "$P/server.pem", "key": "$P/server.key", "client_ca": "$P/ca.pem" },
  "limits": { "payload_max_bytes": 65536, "header_max_bytes": 8192,
              "read_timeout_s": 10, "write_timeout_s": 10, "keep_alive_max_count": 10,
              "job_timeout_s": 60, "queue_max": 64 },
  "auth": { "api_keys": false, "denied_per_minute": 1000 },
  "roles": [ { "name": "reader",
               "client_certs": [
                 { "subject": "CN=client", "issuer": "CN=xca-server TLS test CA" },
                 { "subject": "CN=expired", "issuer": "CN=xca-server TLS test CA" },
                 { "subject": "CN=serveronly", "issuer": "CN=xca-server TLS test CA" },
                 { "subject": "CN=noeku", "issuer": "CN=xca-server TLS test CA" } ] } ]
}
EOF

# req <out> [s_client options]: GET /v1/health, the full s_client output
req() {
    out=$1; shift
    printf 'GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' |
        timeout 30 "$OPENSSL" s_client -connect "127.0.0.1:$PORT" -CAfile "$P/ca.pem" \
            -ign_eof "$@" > "$out" 2>&1
}

alive() {
    kill -0 "$PID" 2> /dev/null || return 1
    req "$WORK/alive.txt" -cert "$P/client.pem" -key "$P/client.key"
    grep -q '^HTTP/1.1 200' "$WORK/alive.txt"
}

"$SERVER" --config "$WORK/xca-server.json" > "$WORK/server.out" 2> "$WORK/server.err" &
PID=$!
up=0
for _ in $(seq 1 60); do
    kill -0 "$PID" 2> /dev/null || die "xca-server exited at start: $(cat "$WORK/server.err")"
    if alive; then up=1; break; fi
    sleep 1
done
[ "$up" = 1 ] || die "xca-server does not answer /v1/health: $(cat "$WORK/server.err")"
ok "start, a valid client gets /v1/health"

# refused <tag> <alert pattern> [s_client options]
refused() {
    tag=$1; alert=$2; shift 2
    req "$WORK/$tag.txt" "$@"
    if grep -q '^HTTP/' "$WORK/$tag.txt"; then
        fail "$tag: an HTTP answer: $(grep '^HTTP/' "$WORK/$tag.txt")"
    elif ! grep -qiE "$alert" "$WORK/$tag.txt"; then
        fail "$tag: not the alert /$alert/: $(grep -iE 'alert|error|errno' "$WORK/$tag.txt" | head -3)"
    elif ! alive; then
        fail "$tag: the server does not answer afterwards"
    else
        ok "$tag: refused with /$alert/, the server answers afterwards"
    fi
}

refused no-certificate "alert certificate required"
refused foreign-ca "alert unknown ca" -cert "$P/foreign.pem" -key "$P/foreign.key"
refused expired "alert certificate expired" -cert "$P/expired.pem" -key "$P/expired.key"
refused serverauth-only "alert unsupported certificate" \
    -cert "$P/serveronly.pem" -key "$P/serveronly.key"
for v in tls1_1 tls1; do
    refused "$v" "alert protocol version" -cert "$P/client.pem" -key "$P/client.key" \
        -"$v" -cipher 'DEFAULT:@SECLEVEL=0'
done

# no EKU at all: valid for every purpose (RFC 5280 4.2.1.12)
req "$WORK/noeku.txt" -cert "$P/noeku.pem" -key "$P/noeku.key"
if grep -q '^HTTP/1.1 200' "$WORK/noeku.txt"; then
    ok "a certificate without EKU is accepted (any purpose)"
else
    fail "a certificate without EKU: $(grep -iE '^HTTP|alert' "$WORK/noeku.txt" | head -2)"
fi

kill -TERM "$PID"
wait "$PID" 2> /dev/null
PID=""
[ "$fails" -eq 0 ] || { log "FAIL: $fails check(s)"; exit 1; }
log "ok: mTLS refusals"
