#!/bin/sh
# The config helper of the server tests (BTD-321): xs_str and the name of
# xs_role write any text as a JSON string, and xs_config writes a valid
# configuration that holds the exact text. The text has a quote, a
# backslash, a tab and a newline.
# Environment: SERVER, OPENSSL, WORK, CMAKE, SERVER_TEST_DIR (ServerShellTest).

set -u
for v in WORK CMAKE SERVER_TEST_DIR; do
    eval "val=\${$v:-}"
    [ -n "$val" ] || { echo "FAIL: $v is not set" >&2; exit 1; }
done
rm -rf "$WORK"
mkdir -p "$WORK"
. "$SERVER_TEST_DIR/config/lib.sh"

value=$(printf 'say "hi" \\ C:\\path\tend\nsecond line')
name=$(printf 'na"me\\x')
printf '%s' "$value" > "$WORK/value.txt"
printf '%s' "$name" > "$WORK/name.txt"

xs_config database/path "$(xs_str "$value")" \
    roles "[ $(xs_role "$name" '"client_certs": []') ]" > "$WORK/config.json" ||
    { echo "FAIL: xs_config did not write a configuration" >&2; exit 1; }

cat > "$WORK/check.cmake" <<'EOF'
file(READ "${DIR}/config.json" json)
string(JSON path ERROR_VARIABLE err GET "${json}" database path)
if(err)
  message(FATAL_ERROR "not valid JSON or no /database/path: ${err}")
endif()
string(JSON role ERROR_VARIABLE err GET "${json}" roles 0 name)
if(err)
  message(FATAL_ERROR "no /roles/0/name: ${err}")
endif()
file(READ "${DIR}/value.txt" value)
file(READ "${DIR}/name.txt" name)
if(NOT path STREQUAL value)
  message(FATAL_ERROR "/database/path is '${path}', expected '${value}'")
endif()
if(NOT role STREQUAL name)
  message(FATAL_ERROR "/roles/0/name is '${role}', expected '${name}'")
endif()
EOF
"$CMAKE" -DDIR="$WORK" -P "$WORK/check.cmake" ||
    { echo "FAIL: the configuration does not hold the exact text: $(cat "$WORK/config.json")" >&2; exit 1; }
echo "ok: xs_str and xs_role write quote, backslash, tab and newline exactly" >&2
