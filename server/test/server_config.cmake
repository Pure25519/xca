# xca-server.json (BTD-154): every member is required and explicit, the
# limits included; a secret is a reference (env:, file:, op://), never the
# secret itself; an op:// reference must be resolved at deployment; API keys
# are off unless switched on, the roles are checked member by member
# (BTD-155). xca-server --config <file> --check-config checks the
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
  "auth": { "api_keys": false, "denied_per_minute": 30 },
  "roles": [
    { "name": "ca-admin",
      "client_certs": [ { "subject": "CN=admin,O=BxC", "issuer": "CN=Lab Client CA" } ],
      "cas": [ "ot-rsa-issuing" ] },
    { "name": "auditor",
      "client_certs": [ { "subject": "CN=audit", "issuer": "CN=Lab Client CA",
        "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" } ] }
  ]
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
# API keys can be switched on since BTD-155 (they were refused before)
string(JSON j SET "${VALID}" auth api_keys "true")
check(api-keys-on 0 "" "${j}")
string(JSON j SET "${VALID}" schema "\"urn:bxc-pki:schema:xca-server:v2\"")
check(wrong-schema 2 "/schema" "${j}")

# BTD-155: auth.denied_per_minute, the roles and tls.key_password
string(JSON j REMOVE "${VALID}" roles)
check(missing-roles 2 "/roles" "${j}")
string(JSON j SET "${VALID}" roles "{}")
check(roles-not-array 2 "/roles" "${j}")
string(JSON j SET "${VALID}" roles "[]")
check(roles-empty 0 "" "${j}")
string(JSON j REMOVE "${VALID}" auth denied_per_minute)
check(missing-denied 2 "/auth/denied_per_minute" "${j}")
string(JSON j SET "${VALID}" auth denied_per_minute "0")
check(denied-zero 2 "/auth/denied_per_minute" "${j}")
string(JSON j SET "${VALID}" auth extra "1")
check(auth-unknown-member 2 "/auth/extra" "${j}")
# role names of the bootstrap schema, not those of the OpenAPI document
string(JSON j SET "${VALID}" roles 0 name "\"ca_admin\"")
check(role-openapi-name 2 "/roles/0/name" "${j}")
string(JSON j SET "${VALID}" roles 0 name "\"boss\"")
check(role-unknown-name 2 "/roles/0/name" "${j}")
string(JSON j REMOVE "${VALID}" roles 0 name)
check(role-missing-name 2 "/roles/0/name" "${j}")
string(JSON j SET "${VALID}" roles 0 extra "1")
check(role-unknown-member 2 "/roles/0/extra" "${j}")
string(JSON j SET "${VALID}" roles 0 client_cert_subjects "[\"CN=admin\"]")
check(role-subject-only 2 "/roles/0/client_cert_subjects" "${j}")
string(JSON j REMOVE "${VALID}" roles 0 client_certs 0 issuer)
check(cert-missing-issuer 2 "/roles/0/client_certs/0/issuer" "${j}")
string(JSON j SET "${VALID}" roles 0 client_certs 0 subject "\"\"")
check(cert-empty-subject 2 "/roles/0/client_certs/0/subject" "${j}")
string(JSON j SET "${VALID}" roles 1 client_certs 0 sha256 "\"0123\"")
check(cert-bad-sha256 2 "/roles/1/client_certs/0/sha256" "${j}")
string(JSON j SET "${VALID}" roles 0 client_certs 0 extra "1")
check(cert-unknown-member 2 "/roles/0/client_certs/0/extra" "${j}")
string(JSON j SET "${VALID}" roles 0 cas 0 "\"Not An Id\"")
check(cas-bad-id 2 "/roles/0/cas/0" "${j}")
# API keys only when they are switched on; secrets are references
string(JSON j SET "${VALID}" roles 0 api_keys "[{\"id\":\"deploy\",\"secret\":\"env:XCA_KEY\"}]")
check(api-key-while-off 2 "/roles/0/api_keys" "${j}")
string(JSON j SET "${j}" auth api_keys "true")
check(api-key-on 0 "" "${j}")
set(on "${j}")
string(JSON j SET "${on}" roles 0 api_keys 0 secret "\"hunter2-hunter2-hunter2-hunter2-1\"")
check(api-key-literal 2 "/roles/0/api_keys/0/secret" "${j}")
string(JSON j SET "${on}" roles 0 api_keys 0 secret "\"op://BxC-Lab/xca-server-key/credential\"")
check(api-key-op 2 "/roles/0/api_keys/0/secret" "${j}")
string(JSON j SET "${on}" roles 0 api_keys 0 id "\"\"")
check(api-key-empty-id 2 "/roles/0/api_keys/0/id" "${j}")
string(JSON j REMOVE "${on}" roles 0 api_keys 0 id)
check(api-key-missing-id 2 "/roles/0/api_keys/0/id" "${j}")
# one key id, two different secrets: which one is meant?
string(JSON j SET "${on}" roles 1 api_keys "[{\"id\":\"deploy\",\"secret\":\"env:OTHER_KEY\"}]")
check(api-key-id-twice 2 "/roles/1/api_keys/0" "${j}")
string(JSON j SET "${VALID}" tls key_password "\"env:XCA_SERVER_KEY_PASSWORD\"")
check(key-password 0 "" "${j}")
string(JSON j SET "${VALID}" tls key_password "\"hunter2\"")
check(key-password-literal 2 "/tls/key_password" "${j}")

if(failures)
  message(FATAL_ERROR "${failures}")
endif()
