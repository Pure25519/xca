#!/bin/sh
# GET /v1/metrics of xca-server (BTD-163), against a database with two
# bootstrap CAs (ca-a, ca-b):
#  1. before the start the command line issues a certificate of ca-a,
#     revokes it and fails one issuance (unknown CA): the counters of the
#     audit log show 1 issuance, 1 revocation and 1 error of the channel cli
#  2. the remaining lifetime of both CA certificates and of the issued
#     certificate; labels hold ids, serials and fingerprints, no subject
#  3. ca_admin and auditor read the metrics (text/plain); reader and a
#     ca_admin limited to ca-a get 403
#  4. the audit counters are cached for metrics.audit_cache_s: a second
#     scrape at once shows the same refusals, one after the cache time the
#     new ones; latency, queue length and job counters are there
#  5. with metrics.certificates_max 1 the per-certificate values give way to
#     the per-CA aggregates; the counters survive the restart
# The last scrape is kept as $WORK/metrics.txt (promtool check metrics, in
# the pull request).
# Environment: SERVER, BXC_PKI, SQL_EXEC, OPENSSL, WORK, CMAKE,
# SERVER_TEST_DIR.

set -u
for v in SERVER BXC_PKI SQL_EXEC OPENSSL WORK CMAKE SERVER_TEST_DIR; do
    eval "val=\${$v:-}"
    [ -n "$val" ] || { echo "FAIL: $v is not set" >&2; exit 1; }
done
[ -x "$SERVER" ] || { echo "FAIL: xca-server not built: $SERVER" >&2; exit 1; }

rm -rf "$WORK"
mkdir -p "$WORK/home" "$WORK/pki" "$WORK/r"
export HOME="$WORK/home"
unset QT_QPA_PLATFORM
cd "$WORK" || exit 1
P="$WORK/pki"
R="$WORK/r"
DB="$WORK/metrics.xdb"
export XCA_SERVER_DB_PASSWORD="Server-Db-Pw-163m"
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

# --- the test PKI ---------------------------------------------------------------
o() { "$OPENSSL" "$@" > /dev/null 2>&1 || die "openssl $1 failed"; }
o req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$P/ca.key" \
    -out "$P/ca.pem" -subj "/CN=xca-server metrics test CA" -days 2
printf 'subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > "$P/server.ext"
printf 'extendedKeyUsage=clientAuth\n' > "$P/client.ext"
leaf() {
    o req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$P/$1.key" \
        -out "$P/$1.csr" -subj "/CN=$1"
    o x509 -req -in "$P/$1.csr" -CA "$P/ca.pem" -CAkey "$P/ca.key" -CAcreateserial \
        -out "$P/$1.pem" -days 2 -extfile "$P/$2.ext"
}
leaf server server
for n in admin auditor reader scoped; do
    leaf "$n" client
done
CA1="CN=xca-server metrics test CA"

# --- the database: two CAs, an issuance, a revocation, a failure ------------------
cat > "$WORK/bootstrap.json" <<EOF
{ "schema": "urn:bxc-pki:schema:bootstrap:v1",
  "database": { "type": "sqlite", "path": "$DB", "password": "env:XCA_SERVER_DB_PASSWORD" },
  "cas": [ { "id": "ca-a", "cn": "Metrics CA A", "key": "ec-p256", "validity": "P1Y" },
           { "id": "ca-b", "cn": "Metrics CA B", "key": "ec-p256", "validity": "P2Y" } ] }
EOF
"$BXC_PKI" bootstrap --file "$WORK/bootstrap.json" --db "$DB" > "$WORK/bootstrap.out" \
    2> "$WORK/bootstrap.err" || die "bxc-pki bootstrap failed: $(cat "$WORK/bootstrap.err")"
PW="--password env:XCA_SERVER_DB_PASSWORD"
# shellcheck disable=SC2086
cli() { "$BXC_PKI" "$@" --db "$DB" $PW > "$WORK/cli.out" 2> "$WORK/cli.err"; }
cli request-cert --cn device --key ec-p256 --dns device.example ||
    die "request-cert: $(cat "$WORK/cli.err")"
cli sign device --ca "Metrics CA A" || die "sign: $(cat "$WORK/cli.err")"
cli revoke device --reason keyCompromise || die "revoke: $(cat "$WORK/cli.err")"
cli sign device --ca "No Such CA" && die "sign with an unknown CA succeeded"
sql() { "$SQL_EXEC" "$DB" -c "$1" 2>&1; }
[ "$(sql "SELECT COUNT(*) FROM audit_log WHERE action = 'certificate.issue' AND result = 'failure' AND channel = 'cli'")" = 1 ] ||
    die "the failed issuance wrote no failure entry"
SERIAL=$(sql "SELECT serial FROM certs JOIN items ON items.id = certs.item WHERE items.name = 'device'")
[ -n "$SERIAL" ] || die "no serial of the issued certificate"

# --- configuration, requests --------------------------------------------------------
. "$SERVER_TEST_DIR/config/lib.sh"
cc() { printf '[ { "subject": "CN=%s", "issuer": "%s" } ]' "$1" "$CA1"; }
ROLES="[ $(xs_role ca-admin "\"client_certs\": $(cc admin)"),
  $(xs_role auditor "\"client_certs\": $(cc auditor)"),
  $(xs_role reader "\"client_certs\": $(cc reader)"),
  $(xs_role ca-admin "\"client_certs\": $(cc scoped)" '[ "ca-a" ]') ]"
# config <certificates_max>
config() {
    xs_config listen/port "$PORT" database/path "$(xs_str "$DB")" \
        tls/cert "$(xs_str "$P/server.pem")" tls/key "$(xs_str "$P/server.key")" \
        tls/client_ca "$(xs_str "$P/ca.pem")" metrics/certificates_max "$1" \
        metrics/audit_cache_s 2 roles "$ROLES"
}
# send <out> <cert> <path>: one GET over mTLS, the raw answer
send() {
    printf 'GET %s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' "$3" |
        timeout 30 "$OPENSSL" s_client -quiet -connect "127.0.0.1:$PORT" -CAfile "$P/ca.pem" \
            -cert "$P/$2.pem" -key "$P/$2.key" > "$1" 2> /dev/null
}
status() { head -1 "$1" | tr -d '\r' | cut -d' ' -f2; }
# value <answer> <series>: the value of one series line, "" if absent
value() {
    grep -F "$2 " "$1" | head -1 | sed 's/.* //' | tr -d '\r'
}
start() {
    "$SERVER" --config "$WORK/xca-server.json" > "$WORK/server.out" 2> "$WORK/server.err" &
    PID=$!
    for _ in $(seq 1 60); do
        kill -0 "$PID" 2> /dev/null || die "xca-server exited at start: $(cat "$WORK/server.err")"
        send "$R/up" admin /v1/health
        [ "$(status "$R/up")" = 200 ] && return 0
        sleep 1
    done
    die "xca-server does not answer: $(cat "$WORK/server.err")"
}
stop() {
    kill -TERM "$PID"
    rc=0
    wait "$PID" || rc=$?
    PID=""
    [ "$rc" -eq 0 ] || fail "xca-server exit $rc after SIGTERM: $(cat "$WORK/server.err")"
}

config 100 > "$WORK/xca-server.json" || die "no configuration"
start
send "$R/status" admin /v1/status

# 1. the counters of the command line
send "$R/m1" admin /v1/metrics
[ "$(status "$R/m1")" = 200 ] || die "metrics as ca_admin: $(head -1 "$R/m1")"
grep -qi '^content-type: text/plain' "$R/m1" || fail "metrics are not text/plain"
for s in 'xca_issuances_total{channel="cli"} 1' 'xca_revocations_total{channel="cli"} 1' \
         'xca_errors_total{channel="cli",action="certificate.issue"} 1'; do
    grep -qF "$s" "$R/m1" || fail "no '$s': $(grep -E '^xca_(issuances|revocations|errors)' "$R/m1")"
done
ok "1. issuance, revocation and failure of the command line counted"

# 2. remaining lifetime
n=$(grep -c '^xca_ca_certificate_expiry_seconds{' "$R/m1")
[ "$n" = 2 ] || fail "$n CA certificate expiry series, expected 2"
for ca in ca-a ca-b; do
    grep -q "^xca_ca_certificate_expiry_seconds{ca_id=\"$ca\",fingerprint=\"[0-9a-f]\{64\}\"} [0-9]" "$R/m1" ||
        fail "no expiry of the CA certificate of $ca"
done
a=$(grep "^xca_ca_certificate_expiry_seconds{ca_id=\"ca-a\"" "$R/m1" | sed 's/.* //')
b=$(grep "^xca_ca_certificate_expiry_seconds{ca_id=\"ca-b\"" "$R/m1" | sed 's/.* //')
[ "${a%.*}" -gt 0 ] 2> /dev/null && [ "${b%.*}" -gt "${a%.*}" ] 2> /dev/null ||
    fail "expiry of ca-a ($a) and ca-b ($b, one year longer)"
grep -q "^xca_certificate_expiry_seconds{ca_id=\"ca-a\",serial=\"$SERIAL\"} " "$R/m1" ||
    fail "no expiry of the issued certificate $SERIAL"
grep -q 'CN=\|Metrics CA\|device' "$R/m1" && fail "a subject or a name in the metrics: $(grep 'CN=\|Metrics CA\|device' "$R/m1" | head -2)"
ok "2. remaining lifetime of the CA certificates and the issued certificate"

# 3. access
send "$R/aud" auditor /v1/metrics
[ "$(status "$R/aud")" = 200 ] || fail "metrics as auditor: $(head -1 "$R/aud")"
send "$R/rdr" reader /v1/metrics
[ "$(status "$R/rdr")" = 403 ] || fail "metrics as reader: $(head -1 "$R/rdr")"
send "$R/scp" scoped /v1/metrics
[ "$(status "$R/scp")" = 403 ] || fail "metrics as ca_admin of ca-a: $(head -1 "$R/scp")"
ok "3. ca_admin and auditor read the metrics, reader and a limited role get 403"

# 4. the cache of the audit counters
denied='xca_errors_total{channel="rest",action="auth.denied"}'
send "$R/m2" admin /v1/metrics
d1=$(value "$R/m1" "$denied")
d2=$(value "$R/m2" "$denied")
[ "${d2:-0}" = "${d1:-0}" ] || fail "the audit counters were not cached: $d1, then $d2"
sleep 3
send "$R/m3" admin /v1/metrics
d3=$(value "$R/m3" "$denied")
[ "${d3:-0}" -ge $((${d1:-0} + 2)) ] 2> /dev/null ||
    fail "the 2 refusals are not counted after the cache time: $d1, then $d3"
for s in xca_db_queue_length xca_db_jobs_total 'xca_http_request_duration_seconds_count{operation_id="getStatus"}'; do
    grep -q "^$s" "$R/m3" || fail "no $s"
done
ok "4. audit counters cached for 2 s, then current; latency and queue"
stop

# 5. above certificates_max: per-CA aggregates only; the counters are kept
config 1 > "$WORK/xca-server.json" || die "no configuration"
start
send "$R/m5" admin /v1/metrics
grep -q '^xca_certificate_expiry_seconds{' "$R/m5" &&
    fail "per-certificate values above certificates_max"
[ "$(value "$R/m5" 'xca_metrics_certificates_limited')" = 1 ] || fail "no xca_metrics_certificates_limited 1"
[ "$(value "$R/m5" 'xca_certificates{ca_id="ca-a"}')" = 2 ] ||
    fail "xca_certificates of ca-a: $(value "$R/m5" 'xca_certificates{ca_id="ca-a"}'), expected 2"
for s in 'xca_certificate_min_expiry_seconds{ca_id="ca-a"}' \
         'xca_certificates_expiring{ca_id="ca-a",within="30d"}'; do
    [ -n "$(value "$R/m5" "$s")" ] || fail "no $s"
done
grep -qF 'xca_issuances_total{channel="cli"} 1' "$R/m5" || fail "the issuance counter after the restart"
sed -n '/^\r\{0,1\}$/,$p' "$R/m5" | tail -n +2 > "$WORK/metrics.txt"
ok "5. certificates_max 1: per-CA aggregates, counters kept"
stop

[ "$fails" -eq 0 ] || { log "FAIL: $fails check(s)"; exit 1; }
log "ok: xca-server metrics"
