#!/bin/sh
# The database lock of xca-server (BTD-302, BTD-303), with the real
# binaries:
#  1. SIGKILL: after kill -9 of the server, bxc-pki and a new server open
#     the database without any cleanup
#  2. a recreated container: the same, with the lock file naming another
#     host (the server ran in a container that is gone)
#  3. PID 1: the same, with the lock file naming PID 1 on this host (the
#     server was the init process of its container)
#  4. a live server: db_hold (opens like the GUI and the CLI) and a second
#     server are refused with database_in_use
#  5. the other direction: while db_hold has the database open, the server
#     refuses to start with database_in_use
#  6. several GUI/CLI instances share the database: two db_hold and
#     bxc-pki list at the same time
# Environment: SERVER, BXC_PKI, DB_HOLD, OPENSSL, WORK.

set -u
for v in SERVER BXC_PKI DB_HOLD OPENSSL WORK; do
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
LOCK="$DB.lock"
export XCA_SERVER_DB_PASSWORD="Server-Db-Pw-302"
export XCA_DB_HOLD_PASSWORD="env:XCA_SERVER_DB_PASSWORD"
PORT=$((20000 + ($$ + 7) % 20000))
PID=""
HOLD=""
fails=0

log() { echo "$*" >&2; }
fail() { log "FAIL: $*"; fails=$((fails + 1)); }
ok() { log "ok $*"; }
cleanup() {
    [ -n "$PID" ] && kill -KILL "$PID" 2>/dev/null
    for h in $HOLD; do kill -KILL "$h" 2>/dev/null; done
}
die() {
    log "FAIL: $*"
    cleanup
    exit 1
}

o() { "$OPENSSL" "$@" > /dev/null 2>&1 || die "openssl $1 failed"; }
o req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$P/ca.key" \
    -out "$P/ca.pem" -subj "/CN=xca-server lock test CA" -days 2
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
    --cn "Lock Test CA" --validity P1Y > "$WORK/init.json" 2> "$WORK/init.err" ||
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
  "auth": { "api_keys": false }
}
EOF
}
config "$PORT" > "$WORK/xca-server.json"
config $((PORT + 1)) > "$WORK/second.json"

health() {
    printf 'GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' |
        timeout 30 "$OPENSSL" s_client -quiet -connect "127.0.0.1:$PORT" \
            -CAfile "$P/ca.pem" -cert "$P/client.pem" -key "$P/client.key" 2> /dev/null |
        grep -q '^HTTP/1.1 200'
}

# start_server <tag>: the server in the background, up and answering
start_server() {
    "$SERVER" --config "$WORK/xca-server.json" > "$WORK/server-$1.out" 2> "$WORK/server-$1.err" &
    PID=$!
    for _ in $(seq 1 60); do
        if ! kill -0 "$PID" 2> /dev/null; then
            PID=""
            return 1
        fi
        health && return 0
        sleep 1
    done
    return 1
}

stop_server() {
    kill -TERM "$PID" 2> /dev/null
    wait "$PID" 2> /dev/null
    PID=""
}

kill_server() {
    kill -KILL "$PID" 2> /dev/null
    wait "$PID" 2> /dev/null
    PID=""
}

# after_kill <tag>: bxc-pki list and a new server work without cleanup;
# after a failure the lock file is removed by hand, so that the later
# checks still run
after_kill() {
    before=$fails
    "$BXC_PKI" list --db "$DB" --password env:XCA_SERVER_DB_PASSWORD \
        > "$WORK/list-$1.out" 2> "$WORK/list-$1.err" ||
        fail "$1: bxc-pki list after kill -9: $(cat "$WORK/list-$1.err")"
    if start_server "$1-restart"; then
        stop_server
    else
        fail "$1: no new server after kill -9: $(cat "$WORK/server-$1-restart.err")"
    fi
    if [ "$fails" -eq "$before" ]; then
        ok "$1: bxc-pki list and a new server after kill -9"
    else
        rm -f "$LOCK"
    fi
}

# hold <tag>: db_hold in the background until "open" (0) or its exit (1)
hold() {
    "$DB_HOLD" "$DB" > "$WORK/hold-$1.out" 2> "$WORK/hold-$1.err" &
    h=$!
    for _ in $(seq 1 60); do
        if grep -q '^open$' "$WORK/hold-$1.out" 2> /dev/null; then
            HOLD="$HOLD $h"
            return 0
        fi
        kill -0 "$h" 2> /dev/null || return 1
        sleep 1
    done
    kill -KILL "$h" 2> /dev/null
    return 1
}

release_holds() {
    for h in $HOLD; do
        kill -KILL "$h" 2> /dev/null
        wait "$h" 2> /dev/null
    done
    HOLD=""
}

# 1. SIGKILL on this host
start_server kill9 || die "xca-server does not start: $(cat "$WORK/server-kill9.err")"
kill_server
after_kill kill9

# 2. a recreated container: the holder named in the lock file is a host
#    that no longer exists
start_server foreign || die "xca-server does not start: $(cat "$WORK/server-foreign.err")"
kill_server
printf '4242\nxca-server\nrecreated-container\n' > "$LOCK"
after_kill foreign-host

# 3. the server was PID 1 of its container, on this host name
start_server pid1 || die "xca-server does not start: $(cat "$WORK/server-pid1.err")"
kill_server
printf '1\nxca-server\n%s\n' "$(hostname)" > "$LOCK"
after_kill pid1

# 4. a live server keeps the database
start_server live || die "xca-server does not start: $(cat "$WORK/server-live.err")"
before=$fails
if hold live; then
    fail "db_hold opened the database of a running server"
    release_holds
else
    grep -q '^database_in_use$' "$WORK/hold-live.err" ||
        fail "db_hold while the server runs: $(cat "$WORK/hold-live.err")"
fi
timeout 60 "$SERVER" --config "$WORK/second.json" > "$WORK/second.out" 2> "$WORK/second.err"
rc=$?
[ "$rc" -ne 0 ] && grep -q '"code": *"database_in_use"' "$WORK/second.err" ||
    fail "a second server on the database: exit $rc, $(cat "$WORK/second.err")"
stop_server
[ "$fails" -eq "$before" ] && ok "a running server: db_hold and a second server refused"

# 5. the GUI or the CLI has the database open: the server does not start
hold gui || die "db_hold cannot open the database: $(cat "$WORK/hold-gui.err")"
before=$fails
if start_server while-open; then
    fail "xca-server started while db_hold has the database open"
    stop_server
else
    grep -q '"code": *"database_in_use"' "$WORK/server-while-open.err" ||
        fail "xca-server while db_hold has the database open: $(cat "$WORK/server-while-open.err")"
fi
[ "$fails" -eq "$before" ] &&
    ok "the server refuses a database that the GUI or the CLI has open"

# 6. GUI and CLI instances share the database
if hold second; then
    "$BXC_PKI" list --db "$DB" --password env:XCA_SERVER_DB_PASSWORD \
        > "$WORK/list-shared.out" 2> "$WORK/list-shared.err" ||
        fail "bxc-pki list next to two db_hold: $(cat "$WORK/list-shared.err")"
    ok "two db_hold and bxc-pki list share the database"
else
    fail "a second db_hold: $(cat "$WORK/hold-second.err")"
fi
release_holds

# released at the exit: the server starts again
if start_server final; then
    stop_server
    ok "the database is free once the holders are gone"
else
    fail "xca-server after the holders exited: $(cat "$WORK/server-final.err")"
fi

cleanup
[ "$fails" -eq 0 ] || { log "FAIL: $fails check(s)"; exit 1; }
log "ok: database lock"
