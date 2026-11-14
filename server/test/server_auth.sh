#!/bin/sh
# xca-server authentication, roles and access rules (BTD-155), against a real
# database with two bootstrap CAs (ca-a, ca-b) and mTLS:
#  A. auth.api_keys false (the default): no client certificate, a certificate of
#     a foreign CA and a TLS 1.1 client get no HTTP answer, and auth.denied
#     names the peer address and the reason; a certificate with a role passes
#     (status 200, a stub 501), one without a role, the same subject under a
#     second trusted client CA and a wrong sha256 pin get 403 + auth.denied;
#     every operation of roles.json x every role is 403 or 501 (200 for the
#     real handlers getStatus and reloadConfiguration), never another 2xx; an
#     unknown path is 404, another method 405; a role with cas [ca-a] gets 403
#     for an operation that names ca-b and 501 for ca-a; auth.login is written
#     once per connection and identity (keep-alive); the TLS protocol and
#     cipher are recorded
#  B. auth.api_keys true, encrypted server key with tls.key_password: no
#     certificate and no key, a wrong key and a key in the query string are 401;
#     the right key (env: and file:) passes as apikey:<id>; certificates still
#     work and a foreign certificate still gets no answer
#  C. a key shorter than 32 bytes and a wrong tls.key_password refuse the start
#     (exit 2, invalid_config with the JSON pointer)
#  D. rate limit: more refusals than auth.denied_per_minute from one peer give
#     exactly denied_per_minute single entries and one summary entry with the
#     number left out (written at the stop at the latest)
#  E. POST /v1/reload (ca_admin only) re-reads the roles, an invalid file
#     changes nothing; one config.reload entry each
#  F. no key value in the server's output or the audit export; xca
#     --audit-verify is ok
# Environment: SERVER, BXC_PKI, XCA, SQL_EXEC, OPENSSL, WORK, ROLES_TSV (the
# operation table of server/roles.json, made by CMake). POSIX sh (dash).

set -u
for v in SERVER BXC_PKI XCA SQL_EXEC OPENSSL WORK ROLES_TSV; do
    eval "val=\${$v:-}"
    [ -n "$val" ] || { echo "FAIL: $v is not set" >&2; exit 1; }
done
[ -x "$SERVER" ] || { echo "FAIL: xca-server not built: $SERVER" >&2; exit 1; }
[ -s "$ROLES_TSV" ] || { echo "FAIL: no operation table: $ROLES_TSV" >&2; exit 1; }

rm -rf "$WORK"
mkdir -p "$WORK/home" "$WORK/pki" "$WORK/srv" "$WORK/r"
export HOME="$WORK/home"
unset QT_QPA_PLATFORM
cd "$WORK" || exit 1
P="$WORK/pki"
R="$WORK/r"
DB="$WORK/auth.xdb"
export XCA_SERVER_DB_PASSWORD="Server-Db-Pw-155"
BASE=$((20000 + $$ % 20000))
PORT=$BASE
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

# --- the test PKI -------------------------------------------------------------
o() { "$OPENSSL" "$@" > /dev/null 2>&1 || die "openssl $1 failed"; }
newca() {
    o req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$P/$1.key" \
        -out "$P/$1.pem" -subj "/CN=$2" -days 2
}
# leaf <name> <CN> <issuing ca> <ext>
leaf() {
    o req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$P/$1.key" \
        -out "$P/$1.csr" -subj "/CN=$2"
    o x509 -req -in "$P/$1.csr" -CA "$P/$3.pem" -CAkey "$P/$3.key" -CAcreateserial \
        -out "$P/$1.pem" -days 2 -extfile "$P/$4.ext"
}
fp() {
    "$OPENSSL" x509 -in "$P/$1.pem" -noout -fingerprint -sha256 | cut -d= -f2 |
        tr -d : | tr 'A-F' 'a-f'
}
newca ca "xca-server test CA"
newca ca2 "second client CA"
newca other "foreign CA"
cat "$P/ca.pem" "$P/ca2.pem" > "$P/clients.pem"
printf 'subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > "$P/server.ext"
printf 'extendedKeyUsage=clientAuth\n' > "$P/client.ext"
leaf server server ca server
for n in reader ra admin auditor norole pinned pinok scoped keepalive; do
    leaf "$n" "$n" ca client
done
leaf twin admin ca2 client
leaf foreign foreign other client
CA1="CN=xca-server test CA"
export XCA_TEST_TLS_KEY_PW="Tls-Key-Pw-155-0123"
export XCA_TEST_TLS_KEY_WRONG="Not-The-Tls-Key-Pw-1"
o pkey -in "$P/server.key" -out "$P/server-enc.key" -aes256 -passout env:XCA_TEST_TLS_KEY_PW

# --- the database: two CAs of a bootstrap file ----------------------------------
cat > "$WORK/bootstrap.json" <<EOF
{ "schema": "urn:bxc-pki:schema:bootstrap:v1",
  "database": { "type": "sqlite", "path": "$DB", "password": "env:XCA_SERVER_DB_PASSWORD" },
  "cas": [ { "id": "ca-a", "cn": "Scope CA A", "key": "ec-p256", "validity": "P1Y" },
           { "id": "ca-b", "cn": "Scope CA B", "key": "ec-p256", "validity": "P1Y" } ] }
EOF
"$BXC_PKI" bootstrap --file "$WORK/bootstrap.json" --db "$DB" > "$WORK/bootstrap.out" \
    2> "$WORK/bootstrap.err" || die "bxc-pki bootstrap failed: $(cat "$WORK/bootstrap.err")"
item() {
    "$SQL_EXEC" "$DB" -c "SELECT json_extract(value, '\$.item') FROM settings WHERE key_ LIKE 'bootstrap_%' AND json_extract(value, '\$.bootstrap_id') = '$1'"
}
ID_A=$(item ca-a)
ID_B=$(item ca-b)
[ -n "$ID_A" ] && [ -n "$ID_B" ] || die "no item ids of the bootstrap CAs: '$ID_A' '$ID_B'"

# --- keys -----------------------------------------------------------------------
KEY_READER=$("$OPENSSL" rand -hex 20)            # 40 bytes
KEY_ADMIN=$("$OPENSSL" rand -hex 24)             # 48 bytes
KEY_WRONG=$("$OPENSSL" rand -hex 20)
KEY_SHORT=$("$OPENSSL" rand -hex 16 | cut -c1-31) # 31 bytes
export XCA_TEST_READER_KEY="$KEY_READER"
export XCA_TEST_SHORT_KEY="$KEY_SHORT"
printf '%s\n' "$KEY_ADMIN" > "$WORK/admin-api.key"

# --- configuration ---------------------------------------------------------------
# config <port> <api_keys> <denied_per_minute> <roles JSON> [<tls key> <key_password>]
config() {
    if [ $# -ge 6 ]; then
        tlskey="\"key\": \"$5\", \"key_password\": \"$6\""
    else
        tlskey="\"key\": \"$P/server.key\""
    fi
    cat <<EOF
{
  "schema": "urn:bxc-pki:schema:xca-server:v1",
  "listen": { "address": "127.0.0.1", "port": $1 },
  "database": { "path": "$DB", "password": "env:XCA_SERVER_DB_PASSWORD" },
  "tls": { "cert": "$P/server.pem", $tlskey, "client_ca": "$P/clients.pem" },
  "limits": { "payload_max_bytes": 65536, "header_max_bytes": 8192,
              "read_timeout_s": 10, "write_timeout_s": 10, "keep_alive_max_count": 10,
              "job_timeout_s": 60, "queue_max": 64 },
  "auth": { "api_keys": $2, "denied_per_minute": $3 },
  "roles": $4
}
EOF
}
cc() { printf '{ "subject": "CN=%s", "issuer": "%s" }' "$1" "$CA1"; }
ROLES_A="[
  { \"name\": \"reader\", \"client_certs\": [ $(cc reader), $(cc keepalive) ] },
  { \"name\": \"ra-operator\", \"client_certs\": [ $(cc ra) ] },
  { \"name\": \"ca-admin\", \"client_certs\": [ $(cc admin),
      { \"subject\": \"CN=pinned\", \"issuer\": \"$CA1\", \"sha256\": \"$(printf '%064d' 0)\" },
      { \"subject\": \"CN=pinok\", \"issuer\": \"$CA1\", \"sha256\": \"$(fp pinok)\" } ] },
  { \"name\": \"auditor\", \"client_certs\": [ $(cc auditor) ] },
  { \"name\": \"ca-admin\", \"client_certs\": [ $(cc scoped) ], \"cas\": [ \"ca-a\" ] }
]"

# --- requests ---------------------------------------------------------------------
# send <out> <cert name or ""> <method> <target> [<body> [<header line>]]:
# one request over TLS, the raw answer in <out>
send() {
    out=$1; cert=$2; method=$3; target=$4; body=${5:-}; hdr=${6:-}
    auth=""
    [ -n "$cert" ] && auth="-cert $P/$cert.pem -key $P/$cert.key"
    {
        printf '%s %s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n' "$method" "$target"
        printf 'Content-Type: application/json\r\nContent-Length: %s\r\n' "${#body}"
        [ -n "$hdr" ] && printf '%s\r\n' "$hdr"
        printf '\r\n%s' "$body"
    } | {
        # shellcheck disable=SC2086
        timeout 30 "$OPENSSL" s_client -quiet -connect "127.0.0.1:$PORT" \
            -CAfile "$P/ca.pem" $auth > "$out" 2> "$out.tls"
    }
}
status() { head -1 "$1" 2> /dev/null | tr -d '\r' | cut -d' ' -f2; }
code_is() { grep -q "\"code\": *\"$2\"" "$1"; }
problem() { grep -qi '^content-type: application/problem+json' "$1"; }
# expect <label> <out> <status> [<code>]
expect() {
    s=$(status "$2")
    if [ "$s" != "$3" ]; then
        fail "$1: status '${s:-no answer}', expected $3: $(tail -1 "$2" 2> /dev/null)"
        return 1
    fi
    if [ $# -ge 4 ]; then
        problem "$2" || { fail "$1: not application/problem+json"; return 1; }
        code_is "$2" "$4" || { fail "$1: code is not $4: $(tail -1 "$2")"; return 1; }
    fi
    return 0
}
no_answer() {
    if grep -q '^HTTP/' "$2"; then
        fail "$1: an HTTP answer: $(head -1 "$2")"
        return 1
    fi
    return 0
}

# --- server start and stop ----------------------------------------------------------
# start <label> <config file>; sets PID and PORT (from the file)
start() {
    PORT=$(sed -n 's/.*"port": \([0-9]*\).*/\1/p' "$2" | head -1)
    "$SERVER" --config "$2" > "$WORK/srv/$1.out" 2> "$WORK/srv/$1.err" &
    PID=$!
    for _ in $(seq 1 60); do
        if ! kill -0 "$PID" 2> /dev/null; then
            fail "$1: xca-server exited at start: $(cat "$WORK/srv/$1.err")"
            PID=""
            return 1
        fi
        send "$R/$1-up" admin GET /v1/health
        [ "$(status "$R/$1-up")" = 200 ] && return 0
        sleep 1
    done
    fail "$1: xca-server does not answer /v1/health: $(cat "$WORK/srv/$1.err")"
    kill -KILL "$PID" 2> /dev/null
    PID=""
    return 1
}
# stop <label>: SIGTERM, exit 0; sets START, the seq of the run's server.start
stop() {
    START=0
    [ -n "$PID" ] || return 1
    kill -TERM "$PID"
    rc=0
    wait "$PID" || rc=$?
    PID=""
    [ "$rc" -eq 0 ] || fail "$1: xca-server exit $rc after SIGTERM: $(cat "$WORK/srv/$1.err")"
    START=$("$SQL_EXEC" "$DB" -c "SELECT MAX(seq) FROM audit_log WHERE action = 'server.start'")
    [ -n "$START" ] || START=0
}
# entries of the last run: count <where>
count() {
    "$SQL_EXEC" "$DB" -c "SELECT COUNT(*) FROM audit_log WHERE seq > $START AND $1" 2>&1
}
pj() { printf "json_extract(CAST(params AS TEXT), '\$.%s')" "$1"; }
# have <label> <expected count, or +N for at least N> <where>
have() {
    n=$(count "$3")
    case "$2" in
    +*) [ "$n" -ge "${2#+}" ] 2> /dev/null && return 0 ;;
    *) [ "$n" = "$2" ] && return 0 ;;
    esac
    fail "$1: $n audit entries, expected $2 ($3)"
    return 1
}

# === A. auth.api_keys false ==========================================================
PORT=$BASE
config "$PORT" false 1000 "$ROLES_A" > "$WORK/a.json"
if start a "$WORK/a.json"; then
    # A1: no answer without a certificate of the client CAs
    send "$R/a-nocert" "" GET /v1/status
    no_answer "no client certificate" "$R/a-nocert"
    send "$R/a-foreign" foreign GET /v1/status
    no_answer "certificate of a foreign CA" "$R/a-foreign"
    ok "A1 no answer without a certificate of the client CAs"

    # A2: a role passes
    send "$R/a-status" admin GET /v1/status
    expect "ca-admin status" "$R/a-status" 200 &&
        { grep -q "\"actor\": *\"cert:$(fp admin)\"" "$R/a-status" ||
            fail "ca-admin status: actor is not cert:$(fp admin)"; }
    send "$R/a-crl" admin POST /v1/crls '{"issuer":"Scope CA A"}'
    expect "ca-admin generateCrl" "$R/a-crl" 501 not_implemented
    ok "A2 a certificate with a role passes"

    # A3: no role, issuer mismatch, pin mismatch
    send "$R/a-norole" norole GET /v1/status
    expect "no role" "$R/a-norole" 403 forbidden
    send "$R/a-twin" twin GET /v1/status
    expect "same subject, second client CA" "$R/a-twin" 403 forbidden
    send "$R/a-pinned" pinned GET /v1/status
    expect "sha256 pin mismatch" "$R/a-pinned" 403 forbidden
    send "$R/a-pinok" pinok GET /v1/status
    expect "sha256 pin match" "$R/a-pinok" 200
    ok "A3 no role, other issuer, other pin: 403"

    # A4: every operation x every role
    table=0
    while read -r op method path roles caparam; do
        target=/v1$(printf '%s' "$path" | sed -e 's/{collection}/keys/' -e 's/{id}/1/' \
            -e 's/{profileId}/p1/' -e 's/{policyId}/p1/' -e 's/{slot}/0/' \
            -e 's/{tokenObjectId}/AB/' -e 's/{approvalId}/aaaaaaaaaaaaaaaaaaaaaaaaaa/')
        body=""
        case "$method" in POST|PUT|PATCH) body='{}' ;; esac
        for pair in reader:reader ra:ra_operator admin:ca_admin auditor:auditor; do
            cert=${pair%%:*}
            role=${pair#*:}
            out="$R/t-$op-$cert"
            send "$out" "$cert" "$method" "$target" "$body" 'If-Match: "1"'
            case ",$roles," in
            *",$role,"*)
                case "$op" in
                getStatus|reloadConfiguration) expect "$op as $role" "$out" 200 ;;
                *) expect "$op as $role" "$out" 501 not_implemented ;;
                esac
                ;;
            *) expect "$op as $role" "$out" 403 forbidden ;;
            esac
            table=$((table + 1))
        done
    done < "$ROLES_TSV"
    send "$R/a-404" admin GET /v1/nothing-here
    expect "unknown path" "$R/a-404" 404 not_found
    send "$R/a-405" admin DELETE /v1/profiles
    expect "other method" "$R/a-405" 405 method_not_allowed
    ok "A4 operation table: $table requests"

    # A5: CA scope (role ca-admin with cas [ca-a])
    send "$R/a-scope-b" scoped POST /v1/crls '{"issuer":"Scope CA B"}'
    expect "scoped generateCrl ca-b by name" "$R/a-scope-b" 403 forbidden
    send "$R/a-scope-a" scoped POST /v1/crls '{"issuer":"Scope CA A"}'
    expect "scoped generateCrl ca-a by name" "$R/a-scope-a" 501 not_implemented
    send "$R/a-scope-bid" scoped POST /v1/crls "{\"issuer\":$ID_B}"
    expect "scoped generateCrl ca-b by id" "$R/a-scope-bid" 403 forbidden
    send "$R/a-scope-aid" scoped POST /v1/crls "{\"issuer\":$ID_A}"
    expect "scoped generateCrl ca-a by id" "$R/a-scope-aid" 501 not_implemented
    send "$R/a-scope-rb" scoped PUT "/v1/certificates/$ID_B/revocations" '{}'
    expect "scoped setRevocations ca-b" "$R/a-scope-rb" 403 forbidden
    send "$R/a-scope-ra" scoped PUT "/v1/certificates/$ID_A/revocations" '{}'
    expect "scoped setRevocations ca-a" "$R/a-scope-ra" 501 not_implemented
    send "$R/a-scope-prof" scoped POST /v1/profiles '{}'
    expect "scoped createProfile (names no CA)" "$R/a-scope-prof" 403 forbidden
    send "$R/a-scope-status" scoped GET /v1/status
    expect "scoped status" "$R/a-scope-status" 200
    ok "A5 CA scope"

    # A6: keep-alive, one connection with two requests
    {
        printf 'GET /v1/status HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n'
        sleep 1
        printf 'GET /v1/status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n'
    } | timeout 30 "$OPENSSL" s_client -quiet -connect "127.0.0.1:$PORT" -CAfile "$P/ca.pem" \
        -cert "$P/keepalive.pem" -key "$P/keepalive.key" > "$R/a-ka" 2> /dev/null
    # the second status line follows the first body, which ends without a newline
    n=$(grep -o 'HTTP/1.1 200' "$R/a-ka" | wc -l | tr -d ' ')
    [ "$n" = 2 ] || fail "keep-alive: $n answers 200 on one connection, expected 2"
    send "$R/a-ka2" keepalive GET /v1/status
    expect "keep-alive, second connection" "$R/a-ka2" 200
    ok "A6 keep-alive"

    # A7: TLS protocol and cipher; TLS 1.1 is refused
    "$OPENSSL" s_client -connect "127.0.0.1:$PORT" -CAfile "$P/ca.pem" \
        -cert "$P/admin.pem" -key "$P/admin.key" < /dev/null > "$R/a-tls" 2>&1
    proto=$(sed -n 's/^ *Protocol *: *//p' "$R/a-tls" | head -1)
    cipher=$(sed -n 's/^ *Cipher *: *//p' "$R/a-tls" | head -1)
    case "$proto" in
    TLSv1.2|TLSv1.3) ok "A7 TLS: $proto, $cipher" ;;
    *) fail "TLS: protocol '$proto', cipher '$cipher'" ;;
    esac
    printf 'GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' |
        timeout 30 "$OPENSSL" s_client -connect "127.0.0.1:$PORT" -CAfile "$P/ca.pem" \
            -cert "$P/admin.pem" -key "$P/admin.key" -tls1_1 -cipher 'DEFAULT:@SECLEVEL=0' \
            > "$R/a-tls11" 2>&1
    no_answer "TLS 1.1 client" "$R/a-tls11"
    grep -q 'Cipher is (NONE)' "$R/a-tls11" ||
        fail "TLS 1.1 client: a cipher was negotiated: $(grep 'Cipher is' "$R/a-tls11")"
    ok "A7 TLS 1.1 refused"
    stop a

    # audit of run A
    w_peer="$(pj peer_address) = '127.0.0.1'"
    have "handshake refusals" +3 "action = 'auth.denied' AND error_code = 'tls_handshake_failed' AND $w_peer AND $(pj tls_alert) IS NOT NULL"
    have "foreign certificate refusal" +1 "action = 'auth.denied' AND error_code = 'tls_handshake_failed' AND $(pj subject) = 'CN=foreign' AND $(pj issuer) = 'CN=foreign CA'"
    have "TLS 1.1 refusal" +1 "action = 'auth.denied' AND error_code = 'tls_handshake_failed' AND $(pj tls_alert) LIKE '%protocol%'"
    have "no role" 1 "action = 'auth.denied' AND actor = 'cert:$(fp norole)' AND error_code = 'forbidden' AND $(pj reason) = 'role' AND $(pj operation_id) = 'getStatus' AND $(pj subject) = 'CN=norole' AND $(pj issuer) = '$CA1' AND $w_peer AND result = 'denied'"
    have "other issuer" 1 "action = 'auth.denied' AND actor = 'cert:$(fp twin)' AND $(pj issuer) = 'CN=second client CA'"
    have "pin mismatch" 1 "action = 'auth.denied' AND actor = 'cert:$(fp pinned)' AND $(pj reason) = 'role'"
    have "CA scope" 3 "action = 'auth.denied' AND actor = 'cert:$(fp scoped)' AND $(pj reason) = 'ca_scope' AND $(pj operation_id) IN ('generateCrl', 'setRevocations')"
    have "write without CA for a scoped role" 1 "action = 'auth.denied' AND actor = 'cert:$(fp scoped)' AND $(pj reason) = 'role' AND $(pj operation_id) = 'createProfile'"
    have "auth.login of ca-admin" +1 "action = 'auth.login' AND actor = 'cert:$(fp admin)' AND result = 'success' AND $(pj actor_kind) = 'cert' AND $(pj subject) = 'CN=admin' AND $(pj issuer) = '$CA1' AND $w_peer"
    have "auth.login once per connection" 2 "action = 'auth.login' AND actor = 'cert:$(fp keepalive)'"
    have "table refusals" +60 "action = 'auth.denied' AND error_code = 'forbidden'"
    ok "A audit entries"
fi

# === B. auth.api_keys true ===========================================================
PORT=$((BASE + 1))
ROLES_B="[
  { \"name\": \"reader\", \"api_keys\": [ { \"id\": \"reader-key\", \"secret\": \"env:XCA_TEST_READER_KEY\" } ] },
  { \"name\": \"ca-admin\", \"client_certs\": [ $(cc admin) ],
    \"api_keys\": [ { \"id\": \"admin-key\", \"secret\": \"file:$WORK/admin-api.key\" } ] }
]"
config "$PORT" true 1000 "$ROLES_B" "$P/server-enc.key" env:XCA_TEST_TLS_KEY_PW > "$WORK/b.json"
if start b "$WORK/b.json"; then
    send "$R/b-none" "" GET /v1/status
    expect "no certificate, no key" "$R/b-none" 401 unauthenticated
    send "$R/b-health" "" GET /v1/health
    expect "health without certificate and key" "$R/b-health" 401 unauthenticated
    send "$R/b-wrong" "" GET /v1/status "" "X-API-Key: $KEY_WRONG"
    expect "wrong key" "$R/b-wrong" 401 unauthenticated
    send "$R/b-query" "" GET "/v1/status?X-API-Key=$KEY_READER"
    expect "key in the query (X-API-Key)" "$R/b-query" 401 unauthenticated
    send "$R/b-query2" "" GET "/v1/status?api_key=$KEY_READER"
    expect "key in the query (api_key)" "$R/b-query2" 401 unauthenticated
    send "$R/b-reader" "" GET /v1/status "" "X-API-Key: $KEY_READER"
    expect "reader key" "$R/b-reader" 200 &&
        { grep -q '"actor": *"apikey:reader-key"' "$R/b-reader" ||
            fail "reader key: actor is not apikey:reader-key: $(tail -1 "$R/b-reader")"; }
    send "$R/b-reader-crl" "" POST /v1/crls '{"issuer":"Scope CA A"}' "X-API-Key: $KEY_READER"
    expect "reader key, generateCrl" "$R/b-reader-crl" 403 forbidden
    send "$R/b-reader-prof" "" GET /v1/profiles "" "X-API-Key: $KEY_READER"
    expect "reader key, listProfiles" "$R/b-reader-prof" 501 not_implemented
    send "$R/b-admin-key" "" POST /v1/crls '{"issuer":"Scope CA A"}' "X-API-Key: $KEY_ADMIN"
    expect "admin key from file:" "$R/b-admin-key" 501 not_implemented
    send "$R/b-admin-cert" admin GET /v1/status
    expect "admin certificate with API keys on" "$R/b-admin-cert" 200
    send "$R/b-foreign" foreign GET /v1/status
    no_answer "foreign certificate with API keys on" "$R/b-foreign"
    ok "B API keys"
    stop b
    w_peer="$(pj peer_address) = '127.0.0.1'"
    have "no credentials" 4 "action = 'auth.denied' AND error_code = 'unauthenticated' AND $(pj reason) = 'no_credentials' AND $w_peer"
    have "wrong key" 1 "action = 'auth.denied' AND error_code = 'unauthenticated' AND $(pj reason) = 'unknown_api_key' AND $w_peer"
    have "auth.login of a key" 3 "action = 'auth.login' AND actor = 'apikey:reader-key' AND $(pj actor_kind) = 'apikey' AND $(pj api_key_id) = 'reader-key' AND $w_peer"
    have "role refusal of a key" 1 "action = 'auth.denied' AND actor = 'apikey:reader-key' AND error_code = 'forbidden' AND $(pj operation_id) = 'generateCrl'"
    have "foreign certificate refusal with API keys on" +1 "action = 'auth.denied' AND error_code = 'tls_handshake_failed' AND $(pj subject) = 'CN=foreign'"
    ok "B audit entries"
fi

# === C. start refused ===============================================================
ROLES_C="[ { \"name\": \"reader\", \"api_keys\": [ { \"id\": \"short\", \"secret\": \"env:XCA_TEST_SHORT_KEY\" } ] } ]"
config $((BASE + 2)) true 10 "$ROLES_C" > "$WORK/c-short.json"
timeout 60 "$SERVER" --config "$WORK/c-short.json" > "$WORK/srv/c-short.out" 2> "$WORK/srv/c-short.err"
rc=$?
[ "$rc" = 2 ] && grep -q '"code": *"invalid_config"' "$WORK/srv/c-short.err" &&
    grep -q '/roles/0/api_keys/0/secret' "$WORK/srv/c-short.err" ||
    fail "a key of 31 bytes: exit $rc, $(cat "$WORK/srv/c-short.err")"
config $((BASE + 2)) false 10 "$ROLES_A" "$P/server-enc.key" env:XCA_TEST_TLS_KEY_WRONG > "$WORK/c-kpw.json"
timeout 60 "$SERVER" --config "$WORK/c-kpw.json" > "$WORK/srv/c-kpw.out" 2> "$WORK/srv/c-kpw.err"
rc=$?
[ "$rc" = 2 ] && grep -q '"code": *"invalid_config"' "$WORK/srv/c-kpw.err" &&
    grep -q '/tls/key_password' "$WORK/srv/c-kpw.err" ||
    fail "a wrong tls.key_password: exit $rc, $(cat "$WORK/srv/c-kpw.err")"
ok "C start refused for a short key and a wrong key password"

# === D. rate limit ==================================================================
PORT=$((BASE + 3))
config "$PORT" false 3 "$ROLES_A" > "$WORK/d.json"
if start d "$WORK/d.json"; then
    i=0
    while [ $i -lt 5 ]; do
        send "$R/d-$i" norole GET /v1/status
        expect "rate limit request $i" "$R/d-$i" 403 forbidden
        i=$((i + 1))
    done
    stop d
    have "single refusals" 3 "action = 'auth.denied' AND error_code = 'forbidden'"
    have "summary" 1 "action = 'auth.denied' AND error_code = 'rate_limited' AND result = 'denied' AND $(pj peer_address) = '127.0.0.1' AND $(pj suppressed) = 2"
    ok "D rate limit: 3 entries and a summary of 2"
fi

# === E. reload ======================================================================
PORT=$((BASE + 4))
ROLES_E1="[ { \"name\": \"ca-admin\", \"client_certs\": [ $(cc admin) ] },
  { \"name\": \"auditor\", \"client_certs\": [ $(cc auditor) ] } ]"
ROLES_E2="[ { \"name\": \"ca-admin\", \"client_certs\": [ $(cc admin) ] },
  { \"name\": \"auditor\", \"client_certs\": [ $(cc auditor) ] },
  { \"name\": \"reader\", \"client_certs\": [ $(cc norole) ] } ]"
ROLES_E3="[ { \"name\": \"boss\", \"client_certs\": [ $(cc admin) ] } ]"
config "$PORT" false 1000 "$ROLES_E1" > "$WORK/e.json"
if start e "$WORK/e.json"; then
    send "$R/e-before" norole GET /v1/status
    expect "before the reload" "$R/e-before" 403 forbidden
    config "$PORT" false 1000 "$ROLES_E2" > "$WORK/e.json"
    send "$R/e-auditor" auditor POST /v1/reload
    expect "reload as auditor" "$R/e-auditor" 403 forbidden
    send "$R/e-reload" admin POST /v1/reload
    expect "reload as ca-admin" "$R/e-reload" 200 &&
        { grep -q '"changed"' "$R/e-reload" || fail "reload: no member changed: $(tail -1 "$R/e-reload")"; }
    send "$R/e-after" norole GET /v1/status
    expect "after the reload" "$R/e-after" 200
    config "$PORT" false 1000 "$ROLES_E3" > "$WORK/e.json"
    send "$R/e-bad" admin POST /v1/reload
    expect "reload of an invalid file" "$R/e-bad" 422 invalid_config &&
        { grep -q '/roles/0/name' "$R/e-bad" || fail "invalid reload: no pointer: $(tail -1 "$R/e-bad")"; }
    send "$R/e-kept" norole GET /v1/status
    expect "roles kept after an invalid reload" "$R/e-kept" 200
    ok "E reload"
    stop e
    have "reload entries" 1 "action = 'config.reload' AND result = 'success' AND actor = 'cert:$(fp admin)'"
    have "failed reload entry" 1 "action = 'config.reload' AND result = 'failure' AND error_code = 'invalid_config'"
    ok "E audit entries"
fi

# === F. no secret anywhere; the audit log verifies ===================================
QT_QPA_PLATFORM=offscreen "$XCA" --no-gui --database="$DB" --password=env:XCA_SERVER_DB_PASSWORD \
    --audit-export="$WORK/audit-export.jsonl" > "$WORK/audit-export.out" 2>&1 ||
    fail "xca --audit-export: $(cat "$WORK/audit-export.out")"
[ -s "$WORK/audit-export.jsonl" ] || fail "xca --audit-export wrote nothing"
for k in "$KEY_READER" "$KEY_ADMIN" "$KEY_WRONG" "$KEY_SHORT" "$XCA_TEST_TLS_KEY_PW" \
    "$XCA_TEST_TLS_KEY_WRONG"; do
    if grep -rqF "$k" "$WORK/srv" "$WORK/audit-export.jsonl"; then
        fail "a secret appears in the server output or the audit export: $(grep -rlF "$k" "$WORK/srv" "$WORK/audit-export.jsonl")"
    fi
done
ok "F no key in the server output or the audit export"
QT_QPA_PLATFORM=offscreen "$XCA" --no-gui --database="$DB" --password=env:XCA_SERVER_DB_PASSWORD \
    --audit-verify > "$WORK/audit-verify.json" 2> "$WORK/audit-verify.err" ||
    fail "xca --audit-verify: $(cat "$WORK/audit-verify.json" "$WORK/audit-verify.err")"
ok "F audit verified"

[ "$fails" -eq 0 ] || { log "FAIL: $fails check(s)"; exit 1; }
log "ok: xca-server authentication and roles"
