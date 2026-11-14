# xca-server.json (BTD-154): every member is required and explicit, the
# limits included; a secret is a reference (env:, file:, op://), never the
# secret itself; an op:// reference must be resolved at deployment; API keys
# stay off (BTD-155). xca-server --config <file> --check-config checks the
# file without starting; a refused file gives exit 2 and one error object
# with the code invalid_config and the JSON pointer of the member on stderr.
# cmake -DSERVER=<xca-server> -DWORK=<dir> -P server_config.cmake

cmake_minimum_required(VERSION 3.19)   # string(JSON)

if(NOT EXISTS "${SERVER}")
  message(FATAL_ERROR "xca-server not built: ${SERVER}")
endif()
file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}/home")
set(ENV{HOME} "${WORK}/home")

set(VALID [=[
{
  "schema": "urn:bxc-pki:schema:xca-server:v1",
  "listen": { "address": "127.0.0.1", "port": 8443 },
  "database": { "path": "/data/bxc-pki.xdb", "password": "env:XCA_SERVER_DB_PASSWORD" },
  "tls": { "cert": "/etc/xca-server/server.pem", "key": "/etc/xca-server/server.key",
           "client_ca": "/etc/xca-server/clients.pem" },
  "limits": { "payload_max_bytes": 1048576, "header_max_bytes": 8192,
              "read_timeout_s": 10, "write_timeout_s": 10, "keep_alive_max_count": 100,
              "job_timeout_s": 60, "queue_max": 64 },
  "auth": { "api_keys": false }
}
]=])

set(failures "")
# check(<label> <expected exit> <pointer or ""> <json>)
function(check label expected pointer json)
  set(f "${WORK}/${label}.json")
  file(WRITE "${f}" "${json}")
  execute_process(COMMAND "${SERVER}" --config "${f}" --check-config
    OUTPUT_VARIABLE out ERROR_VARIABLE err RESULT_VARIABLE rc TIMEOUT 60)
  file(WRITE "${WORK}/${label}.out" "exit ${rc}\nstdout:\n${out}\nstderr:\n${err}\n")
  if(NOT "${rc}" STREQUAL "${expected}")
    set(failures "${failures}\n${label}: exit ${rc}, expected ${expected}: ${err}" PARENT_SCOPE)
    return()
  endif()
  if(expected STREQUAL "0")
    message(STATUS "ok ${label}")
    return()
  endif()
  string(JSON code ERROR_VARIABLE jerr GET "${err}" code)
  string(JSON detail ERROR_VARIABLE derr GET "${err}" detail)
  if(jerr OR NOT code STREQUAL "invalid_config")
    set(failures "${failures}\n${label}: no error object with code invalid_config: ${err}" PARENT_SCOPE)
    return()
  endif()
  if(pointer AND NOT detail MATCHES "${pointer}")
    set(failures "${failures}\n${label}: detail does not name ${pointer}: ${detail}" PARENT_SCOPE)
    return()
  endif()
  message(STATUS "ok ${label}: ${detail}")
endfunction()

# the valid example
check(valid 0 "" "${VALID}")

check(not-json 2 "" "{ this is not json")
string(JSON j REMOVE "${VALID}" limits)
check(missing-limits 2 "/limits" "${j}")
string(JSON j REMOVE "${VALID}" limits read_timeout_s)
check(missing-read-timeout 2 "/limits/read_timeout_s" "${j}")
string(JSON j SET "${VALID}" listen extra "1")
check(unknown-member 2 "/listen/extra" "${j}")
string(JSON j SET "${VALID}" listen port "70000")
check(port-range 2 "/listen/port" "${j}")
string(JSON j SET "${VALID}" limits payload_max_bytes "\"1M\"")
check(limit-type 2 "/limits/payload_max_bytes" "${j}")
string(JSON j SET "${VALID}" limits header_max_bytes "0")
check(limit-zero 2 "/limits/header_max_bytes" "${j}")
# a literal secret is refused, whatever it looks like
string(JSON j SET "${VALID}" database password "\"hunter2\"")
check(literal-secret 2 "/database/password" "${j}")
string(JSON j SET "${VALID}" database password "\"pass:hunter2\"")
check(pass-source 2 "/database/password" "${j}")
# op:// is resolved at deployment (op inject, op run), not by the server
string(JSON j SET "${VALID}" database password "\"op://BxC-Lab/xca-server-db/password\"")
check(unresolved-op 2 "/database/password" "${j}")
# API keys come with BTD-155; until then they cannot be switched on
string(JSON j SET "${VALID}" auth api_keys "true")
check(api-keys-on 2 "/auth/api_keys" "${j}")
string(JSON j SET "${VALID}" schema "\"urn:bxc-pki:schema:xca-server:v2\"")
check(wrong-schema 2 "/schema" "${j}")

if(failures)
  message(FATAL_ERROR "${failures}")
endif()
