#!/bin/sh
# The read resources of xca-server (BTD-156), against a real database with two
# bootstrap CAs (ca-a, ca-b), objects made with bxc-pki and mTLS:
#  A. every read with every CA: listObjects of keys, requests, certificates,
#     crls with keyset paging (limit, after, next; the pages joined are the
#     whole list in item id order; 400 invalid_value for a bad limit or
#     after), getObject of every object, a missing one 404 unknown_reference,
#     one of another collection 404 wrong_object_type; listProfiles/
#     getProfile, listPolicies/getPolicy, exportIndex flat and by issuer,
#     listTokens
#  B. no private key material in any answer: every key of every key type
#     (RSA, EC, Ed25519, Ed448, ML-DSA, SLH-DSA) read with getObject
#  C. the CA scope of a role limited to ca-a (BTD-311, decisions of
#     2026-11-19): exactly the certificates of ca-a, its CRL, the keys of its
#     certificates and the requests they were issued from; an object of ca-b
#     and the request no certificate was issued from are 404 unknown_reference;
#     the unbound profile and policy are seen, the ones bound to ca-b are not
#     (404 document_not_found); the index has only certificates of ca-a; the
#     tokens and the audit log stay refused (ca_scope_unfiltered)
#  D. GET /v1/audit/verify is the report of xca --audit-verify on the same
#     database, byte for byte; GET /v1/audit is the JSON Lines of
#     xca --audit-export, byte for byte (the export of the CLI signs a new
#     checkpoint at its end, the server's GET signs nothing), with
#     X-Unanchored-Entries; after limits it to the later entries; each export
#     writes one audit.export with its range and count, and no checkpoint
# Environment: SERVER, BXC_PKI, XCA, SQL_EXEC, OPENSSL, WORK, CMAKE,
# SERVER_TEST_DIR. POSIX sh (dash).

set -u
for v in SERVER BXC_PKI XCA SQL_EXEC OPENSSL WORK CMAKE SERVER_TEST_DIR; do
    eval "val=\${$v:-}"
    [ -n "$val" ] || { echo "FAIL: $v is not set" >&2; exit 1; }
done
[ -x "$SERVER" ] || { echo "FAIL: xca-server not built: $SERVER" >&2; exit 1; }

rm -rf "$WORK"
mkdir -p "$WORK/home" "$WORK/pki" "$WORK/srv" "$WORK/r"
export HOME="$WORK/home"
unset QT_QPA_PLATFORM
cd "$WORK" || exit 1
P="$WORK/pki"
R="$WORK/r"
DB="$WORK/read.xdb"
export XCA_SERVER_DB_PASSWORD="Server-Db-Pw-156"
PW="--password env:XCA_SERVER_DB_PASSWORD"
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
sql() { "$SQL_EXEC" "$DB" -c "$1" 2>&1; }

# --- the client PKI -------------------------------------------------------------
o() { "$OPENSSL" "$@" > /dev/null 2>&1 || die "openssl $1 failed"; }
o req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$P/ca.key" \
    -out "$P/ca.pem" -subj "/CN=read test CA" -days 2
printf 'subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > "$P/server.ext"
printf 'extendedKeyUsage=clientAuth\n' > "$P/client.ext"
for n in server admin scoped auditor; do
    o req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$P/$n.key" \
        -out "$P/$n.csr" -subj "/CN=$n"
    ext=client
    [ "$n" = server ] && ext=server
    o x509 -req -in "$P/$n.csr" -CA "$P/ca.pem" -CAkey "$P/ca.key" -CAcreateserial \
        -out "$P/$n.pem" -days 2 -extfile "$P/$ext.ext"
done
CA1="CN=read test CA"

# --- the database: two CAs, a profile and a policy bound to ca-b, one each free ---
D="$SERVER_TEST_DIR/../../cli/test/data/bootstrap"
sed -e 's/"id": "tls-server"/"id": "free-profile"/' "$D/profiles/tls-server.json" > "$WORK/free-profile.json"
sed -e 's/"id": "tls-server"/"id": "b-profile"/' "$D/profiles/tls-server.json" > "$WORK/b-profile.json"
sed -e 's/"id": "lab-names"/"id": "free-policy"/' "$D/policies/lab-names.json" > "$WORK/free-policy.json"
sed -e 's/"id": "lab-names"/"id": "b-policy"/' "$D/policies/lab-names.json" > "$WORK/b-policy.json"
cat > "$WORK/bootstrap.json" <<EOF
{ "schema": "urn:bxc-pki:schema:bootstrap:v1",
  "database": { "type": "sqlite", "path": "$DB", "password": "env:XCA_SERVER_DB_PASSWORD" },
  "profiles": [ "$WORK/free-profile.json", "$WORK/b-profile.json" ],
  "policies": [ "$WORK/free-policy.json", "$WORK/b-policy.json" ],
  "cas": [ { "id": "ca-a", "cn": "Scope CA A", "key": "ec-p256", "validity": "P1Y" },
           { "id": "ca-b", "cn": "Scope CA B", "key": "ec-p256", "validity": "P1Y",
             "profiles": [ "b-profile" ], "policies": [ "b-policy" ] } ] }
EOF
"$BXC_PKI" bootstrap --file "$WORK/bootstrap.json" --db "$DB" > "$WORK/bootstrap.out" \
    2> "$WORK/bootstrap.err" || die "bxc-pki bootstrap failed: $(cat "$WORK/bootstrap.err")"
item() {
    sql "SELECT json_extract(value, '\$.item') FROM settings WHERE key_ LIKE 'bootstrap_%' AND json_extract(value, '\$.bootstrap_id') = '$1'"
}
ID_A=$(item ca-a)
ID_B=$(item ca-b)
[ -n "$ID_A" ] && [ -n "$ID_B" ] || die "no item ids of the bootstrap CAs: '$ID_A' '$ID_B'"
# bxc <label> <arguments>: one bxc-pki command that must succeed
bxc() {
    label=$1
    shift
    # shellcheck disable=SC2086
    "$BXC_PKI" "$@" --db "$DB" $PW > "$WORK/bxc-$label.out" 2> "$WORK/bxc-$label.err" ||
        die "bxc-pki $label failed: $(cat "$WORK/bxc-$label.err")"
}
# certificates of ca-a with keys of every key type, one of ca-b, a request
# without certificate, a CRL of each CA
KEYTYPES="rsa-2048 ec-p256 ed25519 ed448 ml-dsa-44 slh-dsa-sha2-128f"
for kt in $KEYTYPES; do
    bxc "req-$kt" request-cert --cn "a-$kt" --key "$kt"
    bxc "sign-$kt" sign "a-$kt" --ca "Scope CA A"
done
bxc req-b request-cert --cn b-leaf --key ec-p256
bxc sign-b sign b-leaf --ca "Scope CA B"
bxc req-orphan request-cert --cn orphan --key ec-p256
bxc crl-a crl --ca "Scope CA A"
bxc crl-b crl --ca "Scope CA B"
ids_of() { sql "SELECT id FROM items WHERE del = 0 AND type IN ($1) ORDER BY id" | tr '\n' ' '; }
# the item types (lib/pki_base.h): asym_key 1, x509_req 2, x509 3, revocation 4, smartCard 6
ALL_KEYS=$(ids_of "1,6")
ALL_REQS=$(ids_of "2")
ALL_CERTS=$(ids_of "3")
ALL_CRLS=$(ids_of "4")
of_a="(c.item = $ID_A OR c.issuer = $ID_A)"
A_CERTS=$(sql "SELECT c.item FROM certs c JOIN items i ON i.id = c.item WHERE i.del = 0 AND $of_a ORDER BY c.item" | tr '\n' ' ')
A_KEYS=$(sql "SELECT DISTINCT x.pkey FROM x509super x JOIN certs c ON c.item = x.item WHERE $of_a ORDER BY x.pkey" | tr '\n' ' ')
A_REQS=$(sql "SELECT r.item FROM x509super r JOIN items i ON i.id = r.item WHERE i.type = 2 AND i.del = 0 AND r.pkey IN (SELECT x.pkey FROM x509super x JOIN certs c ON c.item = x.item WHERE $of_a) ORDER BY r.item" | tr '\n' ' ')
A_CRLS=$(sql "SELECT item FROM crls WHERE issuer = $ID_A ORDER BY item" | tr '\n' ' ')
ORPHAN=$(sql "SELECT id FROM items WHERE name = 'orphan' AND type = 2")
B_LEAF=$(sql "SELECT id FROM items WHERE name = 'b-leaf' AND type = 3")
[ -n "$ORPHAN" ] && [ -n "$B_LEAF" ] && [ -n "$A_REQS" ] || die "the test objects are missing"

# --- configuration ---------------------------------------------------------------
. "$SERVER_TEST_DIR/config/lib.sh"
cc() { printf '{ "subject": "CN=%s", "issuer": "%s" }' "$1" "$CA1"; }
xs_config listen/port "$PORT" database/path "$(xs_str "$DB")" \
    tls/cert "$(xs_str "$P/server.pem")" tls/key "$(xs_str "$P/server.key")" \
    tls/client_ca "$(xs_str "$P/ca.pem")" \
    roles "[ $(xs_role ca-admin "\"client_certs\": [ $(cc admin) ]"),
             $(xs_role ca-admin "\"client_certs\": [ $(cc scoped) ]" '[ "ca-a" ]'),
             $(xs_role auditor "\"client_certs\": [ $(cc auditor) ]") ]" > "$WORK/xca-server.json" ||
    die "no configuration"

# --- requests ---------------------------------------------------------------------
# get <out> <cert> <target>: one GET over TLS, the raw answer in <out>, the body
# in <out>.body
get() {
    {
        printf 'GET %s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' "$3"
    } | timeout 60 "$OPENSSL" s_client -quiet -connect "127.0.0.1:$PORT" \
        -CAfile "$P/ca.pem" -cert "$P/$2.pem" -key "$P/$2.key" > "$1" 2> "$1.tls"
    # the body: everything after the empty line of the head
    awk 'b { print } /^\r?$/ { b = 1 }' "$1" > "$1.body"
}
status() { head -1 "$1" 2> /dev/null | tr -d '\r' | cut -d' ' -f2; }
header() { grep -i "^$2:" "$1" | head -1 | cut -d: -f2- | tr -d ' \r'; }
code_is() { grep -q "\"code\": *\"$2\"" "$1"; }
# expect <label> <out> <status> [<code>]
expect() {
    s=$(status "$2")
    if [ "$s" != "$3" ]; then
        fail "$1: status '${s:-no answer}', expected $3: $(tail -c 300 "$2" 2> /dev/null)"
        return 1
    fi
    if [ $# -ge 4 ] && ! code_is "$2" "$4"; then
        fail "$1: code is not $4: $(tail -c 300 "$2")"
        return 1
    fi
    return 0
}
# list_ids <body>: the ids of an item list, in order
list_ids() { grep -o '"id": *[0-9]*' "$1" | sed 's/.*: *//' | tr '\n' ' '; }
# same <label> <got> <want>: two space separated lists are equal
same() {
    [ "$(echo $2)" = "$(echo $3)" ] || fail "$1: got [$2], expected [$3]"
}

start() {
    "$SERVER" --config "$WORK/xca-server.json" > "$WORK/srv/$1.out" 2> "$WORK/srv/$1.err" &
    PID=$!
    for _ in $(seq 1 60); do
        kill -0 "$PID" 2> /dev/null || die "xca-server exited at start: $(cat "$WORK/srv/$1.err")"
        get "$R/up" admin /v1/health
        [ "$(status "$R/up")" = 200 ] && return 0
        sleep 1
    done
    die "xca-server does not answer /v1/health: $(cat "$WORK/srv/$1.err")"
}
stop() {
    kill -TERM "$PID"
    rc=0
    wait "$PID" || rc=$?
    PID=""
    [ "$rc" -eq 0 ] || fail "xca-server exit $rc after SIGTERM: $(cat "$WORK/srv/$1.err")"
}

start read

# === A. every read with every CA =====================================================
for c in keys:$ALL_KEYS requests:$ALL_REQS certificates:$ALL_CERTS crls:$ALL_CRLS; do
    coll=${c%%:*}
    want=$(echo "${c#*:}" | tr -s ' ')
    want=$(printf '%s' "$c" | sed 's/^[a-z]*://')
    get "$R/l-$coll" admin "/v1/$coll"
    expect "list $coll" "$R/l-$coll" 200 && same "list $coll" "$(list_ids "$R/l-$coll.body")" "$want"
    grep -q '"next": *null' "$R/l-$coll.body" || fail "list $coll: next is not null: $(cat "$R/l-$coll.body")"
done
# paging of the certificates by 3: the pages joined are the list
after=0 pages=0 joined=""
while :; do
    get "$R/p-$pages" admin "/v1/certificates?limit=3&after=$after"
    expect "page $pages" "$R/p-$pages" 200 || break
    page=$(list_ids "$R/p-$pages.body")
    [ "$(echo $page | wc -w)" -le 3 ] || fail "page $pages: more than 3 items: $page"
    joined="$joined $page"
    pages=$((pages + 1))
    next=$(grep -o '"next": *[0-9]*' "$R/p-$((pages - 1)).body" | sed 's/.*: *//')
    [ -n "$next" ] || break
    after=$next
    [ "$pages" -lt 20 ] || { fail "paging does not end"; break; }
done
same "the pages joined" "$joined" "$ALL_CERTS"
[ "$pages" -ge 3 ] || fail "paging: $pages pages for $(echo $ALL_CERTS | wc -w) certificates by 3"
for q in "limit=0" "limit=1001" "limit=x" "after=-1"; do
    get "$R/bad-$q" admin "/v1/certificates?$q"
    expect "bad paging $q" "$R/bad-$q" 400 invalid_value
done
ok "A1 lists and keyset paging"
for id in $ALL_CERTS; do
    get "$R/g-$id" admin "/v1/certificates/$id"
    expect "certificate $id" "$R/g-$id" 200 &&
        { grep -q '"schema": *"urn:bxc-pki:schema:certificate:v1"' "$R/g-$id.body" ||
            fail "certificate $id: not a certificate document"; }
done
for id in $ALL_CRLS; do
    get "$R/g-$id" admin "/v1/crls/$id"
    expect "CRL $id" "$R/g-$id" 200
done
get "$R/g-none" admin /v1/certificates/999999
expect "missing object" "$R/g-none" 404 unknown_reference
get "$R/g-wrong" admin "/v1/keys/$B_LEAF"
expect "object of another collection" "$R/g-wrong" 404 wrong_object_type
get "$R/g-word" admin /v1/certificates/abc
expect "id that is no number" "$R/g-word" 404 unknown_reference
ok "A2 objects"
get "$R/prof" admin /v1/profiles
expect "profiles" "$R/prof" 200
for p in free-profile b-profile; do
    grep -q "\"id\": *\"$p\"" "$R/prof.body" || fail "profiles: no $p"
    get "$R/prof-$p" admin "/v1/profiles/$p"
    expect "profile $p" "$R/prof-$p" 200
done
get "$R/pol" admin /v1/policies
expect "policies" "$R/pol" 200
for p in free-policy b-policy; do
    grep -q "\"id\": *\"$p\"" "$R/pol.body" || fail "policies: no $p"
done
get "$R/prof-none" admin /v1/profiles/no-such-profile
expect "missing profile" "$R/prof-none" 404 document_not_found
get "$R/idx" admin /v1/export/index
expect "index" "$R/idx" 200 && { grep -q '"kind": *"index"' "$R/idx.body" || fail "index: kind"; }
n=$(grep -o '"serial"' "$R/idx.body" | wc -l)
[ "$n" = "$(echo $ALL_CERTS | wc -w)" ] || fail "index: $n entries for $(echo $ALL_CERTS | wc -w) certificates"
get "$R/hier" admin "/v1/export/index?hierarchy=true"
expect "hierarchy" "$R/hier" 200 && { grep -q '"kind": *"hierarchy"' "$R/hier.body" || fail "hierarchy: kind"; }
get "$R/idx-bad" admin "/v1/export/index?hierarchy=yes"
expect "hierarchy=yes" "$R/idx-bad" 400 invalid_value
get "$R/tok" admin /v1/tokens
expect "tokens" "$R/tok" 200 && { grep -q '^\[' "$R/tok.body" || fail "tokens: no array: $(cat "$R/tok.body")"; }
ok "A3 profiles, policies, index, tokens"

# === B. no private key material ========================================================
for id in $ALL_KEYS; do
    get "$R/k-$id" admin "/v1/keys/$id"
    expect "key $id" "$R/k-$id" 200 || continue
    if grep -qi 'PRIVATE KEY\|"private_key"\|"private_pem"' "$R/k-$id.body"; then
        fail "key $id: private key material in the answer"
    fi
done
for kt in $KEYTYPES; do
    grep -l "\"name\": *\"a-$kt\"" "$R"/k-*.body > /dev/null 2>&1 || fail "no key document of the key type $kt"
done
ok "B no private key material ($(echo $ALL_KEYS | wc -w) keys)"

# === C. the CA scope of a role limited to ca-a ==========================================
for c in "keys:$A_KEYS" "requests:$A_REQS" "certificates:$A_CERTS" "crls:$A_CRLS"; do
    coll=${c%%:*}
    get "$R/s-$coll" scoped "/v1/$coll"
    expect "scoped list $coll" "$R/s-$coll" 200 && same "scoped list $coll" "$(list_ids "$R/s-$coll.body")" "${c#*:}"
done
for id in $B_LEAF $ID_B $ORPHAN; do
    coll=certificates
    [ "$id" = "$ORPHAN" ] && coll=requests
    get "$R/s-g-$id" scoped "/v1/$coll/$id"
    expect "scoped $coll $id (not of ca-a)" "$R/s-g-$id" 404 unknown_reference
done
for id in $A_CERTS; do
    get "$R/s-ga-$id" scoped "/v1/certificates/$id"
    expect "scoped certificate $id of ca-a" "$R/s-ga-$id" 200
done
get "$R/s-prof" scoped /v1/profiles
expect "scoped profiles" "$R/s-prof" 200 && {
    grep -q '"id": *"free-profile"' "$R/s-prof.body" || fail "scoped profiles: the unbound profile is missing"
    grep -q '"id": *"b-profile"' "$R/s-prof.body" && fail "scoped profiles: the profile of ca-b is listed"
}
get "$R/s-prof-b" scoped /v1/profiles/b-profile
expect "scoped profile of ca-b" "$R/s-prof-b" 404 document_not_found
get "$R/s-prof-f" scoped /v1/profiles/free-profile
expect "scoped unbound profile" "$R/s-prof-f" 200
get "$R/s-pol" scoped /v1/policies
expect "scoped policies" "$R/s-pol" 200 && {
    grep -q '"id": *"free-policy"' "$R/s-pol.body" || fail "scoped policies: the unbound policy is missing"
    grep -q '"id": *"b-policy"' "$R/s-pol.body" && fail "scoped policies: the policy of ca-b is listed"
}
get "$R/s-pol-b" scoped /v1/policies/b-policy
expect "scoped policy of ca-b" "$R/s-pol-b" 404 document_not_found
get "$R/s-idx" scoped /v1/export/index
expect "scoped index" "$R/s-idx" 200 && {
    n=$(grep -o '"serial"' "$R/s-idx.body" | wc -l)
    [ "$n" = "$(echo $A_CERTS | wc -w)" ] || fail "scoped index: $n entries, expected $(echo $A_CERTS | wc -w) of ca-a"
    grep -q 'CN=b-leaf' "$R/s-idx.body" && fail "scoped index: a certificate of ca-b"
}
get "$R/s-hier" scoped "/v1/export/index?hierarchy=true"
expect "scoped hierarchy" "$R/s-hier" 200 && { grep -q 'Scope CA B' "$R/s-hier.body" && fail "scoped hierarchy: ca-b"; }
get "$R/s-tok" scoped /v1/tokens
expect "scoped tokens" "$R/s-tok" 403 forbidden
ok "C CA scope of ca-a"

# === D. the audit log ===================================================================
cli_db() {
    cp "$DB" "$WORK/$1.xdb" || die "copy of the database"
    printf '%s' "$WORK/$1.xdb"
}
get "$R/verify" auditor /v1/audit/verify
expect "audit verify" "$R/verify" 200
copy=$(cli_db verify)
QT_QPA_PLATFORM=offscreen "$XCA" --no-gui --database="$copy" $PW --audit-verify \
    > "$WORK/verify-cli.json" 2> "$WORK/verify-cli.err"
# the CLI writes one line with a newline, the server the same bytes
printf '%s\n' "$(cat "$R/verify.body")" | cmp -s - "$WORK/verify-cli.json" ||
    fail "audit verify differs from xca --audit-verify: $(cat "$R/verify.body") / $(cat "$WORK/verify-cli.json")"
grep -q '"ok":true' "$R/verify.body" || fail "audit verify: not ok: $(cat "$R/verify.body")"
ok "D1 /audit/verify is the report of --audit-verify"

checkpoints() { sql "SELECT COUNT(*) FROM audit_log WHERE action = 'audit.checkpoint'"; }
cp_before=$(checkpoints)
get "$R/export" auditor /v1/audit
expect "audit export" "$R/export" 200
case "$(header "$R/export" content-type)" in application/x-ndjson*) ;; *) fail "audit export: content type $(header "$R/export" content-type)" ;; esac
unanchored=$(header "$R/export" x-unanchored-entries)
[ -n "$unanchored" ] && [ "$unanchored" -ge 1 ] 2> /dev/null ||
    fail "audit export: X-Unanchored-Entries '$unanchored'"
[ "$(checkpoints)" = "$cp_before" ] || fail "audit export signed a checkpoint"
lines=$(wc -l < "$R/export.body")
copy=$(cli_db export)
QT_QPA_PLATFORM=offscreen "$XCA" --no-gui --database="$copy" $PW --audit-export="$WORK/export-cli.jsonl" \
    > "$WORK/export-cli.out" 2>&1 || fail "xca --audit-export: $(cat "$WORK/export-cli.out")"
# the CLI export: the server's lines, then audit.export and its own checkpoint
head -n "$lines" "$WORK/export-cli.jsonl" | cmp -s - "$R/export.body" ||
    fail "audit export: the $lines lines differ from xca --audit-export"
last=$(tail -1 "$R/export.body" | grep -o '"seq":[0-9]*' | cut -d: -f2)
get "$R/export-after" auditor "/v1/audit?after=$((last - 2))"
expect "audit export after" "$R/export-after" 200
n=$(wc -l < "$R/export-after.body")
# the last two of the first export, its audit.export and the auth.login of the connection
[ "$n" -ge 3 ] || fail "audit export after $((last - 2)): $n lines"
grep -q "\"seq\":$((last - 2))," "$R/export-after.body" && fail "audit export after: the entry after itself"
get "$R/export-bad" auditor "/v1/audit?after=x"
expect "audit export after=x" "$R/export-bad" 400 invalid_value
stop read
n=$(sql "SELECT COUNT(*) FROM audit_log WHERE action = 'audit.export' AND channel = 'rest' AND json_extract(CAST(params AS TEXT), '\$.count') > 0 AND json_extract(CAST(params AS TEXT), '\$.last_seq') >= json_extract(CAST(params AS TEXT), '\$.first_seq')")
[ "$n" = 2 ] || fail "audit.export entries: $n, expected 2"
n=$(sql "SELECT COUNT(*) FROM audit_log WHERE action = 'audit.export' AND json_extract(CAST(params AS TEXT), '\$.count') = $lines AND json_extract(CAST(params AS TEXT), '\$.after') = 0")
[ "$n" = 1 ] || fail "audit.export of the whole log: count $lines expected"
ok "D2 /audit is the export of --audit-export, audited, nothing signed"

[ "$fails" -eq 0 ] || { log "FAIL: $fails check(s)"; exit 1; }
log "ok: xca-server read resources"
