# The configuration of the server tests (BTD-320), sourced by them.
#
# Every test starts from the one base config server/test/config/base.json,
# which has every required member of xca-server.json, and sets only what it
# needs. A new required member goes into base.json (a member of a role into
# xs_role) and nowhere else.
#
# Environment: CMAKE (the cmake program), SERVER_TEST_DIR (server/test).

: "${CMAKE:?CMAKE is not set}" "${SERVER_TEST_DIR:?SERVER_TEST_DIR is not set}"

# xs_config [<pointer> <JSON value>]...: the configuration on stdout. A
# pointer has no leading / (listen/port, tls/key_password, roles); a value is
# JSON (a string in quotes, see xs_str) and may span lines.
xs_config() {
    xs_sets=$(mktemp) && xs_out=$(mktemp) || return 1
    while [ $# -ge 2 ]; do
        printf '%s\t%s\n' "$1" "$(printf '%s' "$2" | tr '\n' ' ')" >> "$xs_sets"
        shift 2
    done
    [ $# -eq 0 ] || { echo "xs_config: a pointer without a value: $1" >&2; return 1; }
    "$CMAKE" -DBASE="$SERVER_TEST_DIR/config/base.json" -DSETS="$xs_sets" \
        -DOUT="$xs_out" -P "$SERVER_TEST_DIR/config/set.cmake" >&2 &&
        cat "$xs_out"
    xs_rc=$?
    rm -f "$xs_sets" "$xs_out"
    return $xs_rc
}

# xs_str <text>: <text> as a JSON string (no quote or backslash in it)
xs_str() {
    printf '"%s"' "$1"
}

# xs_role <name> <members> [<cas>]: one role of "roles". <members> are its
# other members as JSON without the braces ("client_certs": [...],
# "api_keys": [...]); <cas> is a JSON array, every CA (["*"]) if left out.
xs_role() {
    printf '{ "name": "%s", %s, "cas": %s }' "$1" "$2" "${3:-[ \"*\" ]}"
}
