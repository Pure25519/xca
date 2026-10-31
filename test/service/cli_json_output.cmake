# xca --no-gui --json (BTD-39): --print, --list-items, --issuers, --index
# and --hierarchy write JSON Lines to stdout, one document per line with
# its schema; "-" sends --index/--hierarchy to stdout, another name writes
# one JSON file; errors are an error object on stderr with exit code 1.
# No output names private key material or a password: the database holds
# keys encrypted with the database password and one with its own password.
# cmake -DXCA=<xca> -DDATA=<test/service/data> [-DOPENSSL=<openssl>]
#       [-DSQL_EXEC=<sql_exec>] -DWORK=<scratch dir> -P cli_json_output.cmake

cmake_minimum_required(VERSION 3.19)   # string(JSON)

# the fixtures of the JSON tests (BTD-256: DATA is the common data directory)
set(DATA "${DATA}/json")
file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}/home")
set(ENV{HOME} "${WORK}/home")
set(ENV{XDG_CONFIG_HOME} "${WORK}/home/.config")
set(ENV{XDG_DATA_HOME} "${WORK}/home/.local/share")
set(ENV{QT_QPA_PLATFORM} offscreen)

set(DB_PW "Cli-Json-Db-5")
set(OWN_PW "Own-Secret-77")
set(WRONG_PW "Wrong-Json-Pw-9")
set(db --database "${WORK}/json.xdb")

function(fail msg)
  file(REMOVE_RECURSE "${WORK}")
  message(FATAL_ERROR "${msg}")
endfunction()

# run(<label> <expected exit code> <args>...): xca --no-gui; stdout in
# ${out}, stderr in ${err}; both are kept for the secret check at the end
set(ALL "")
function(run label code)
  execute_process(COMMAND "${XCA}" --no-gui ${db} ${ARGN}
    WORKING_DIRECTORY "${WORK}"
    RESULT_VARIABLE rc OUTPUT_VARIABLE o ERROR_VARIABLE e TIMEOUT 30)
  if(NOT rc EQUAL code)
    fail("${label}: expected exit code ${code}, got '${rc}':\n${o}\n${e}")
  endif()
  set(out "${o}" PARENT_SCOPE)
  set(err "${e}" PARENT_SCOPE)
  set(ALL "${ALL}\n${o}\n${e}" PARENT_SCOPE)
endfunction()

# json_lines(<label> <text> <expected schema kinds>...): every line of
# text is a JSON document; their schema URNs in this order
function(json_lines label text)
  string(REGEX MATCHALL "[^\n]+" lines "${text}")
  list(LENGTH lines n)
  list(LENGTH ARGN expected)
  if(NOT n EQUAL expected)
    fail("${label}: ${n} lines, expected ${expected}:\n${text}")
  endif()
  if(NOT text MATCHES "\n$")
    fail("${label}: the last line has no line end")
  endif()
  set(i 0)
  foreach(line IN LISTS lines)
    list(GET ARGN ${i} kind)
    string(JSON schema ERROR_VARIABLE jerr GET "${line}" schema)
    if(jerr)
      fail("${label}: line ${i} is no JSON document (${jerr}):\n${line}")
    endif()
    if(NOT schema STREQUAL "urn:bxc-pki:schema:${kind}:v1")
      fail("${label}: line ${i} has schema '${schema}', expected ${kind}")
    endif()
    math(EXPR i "${i} + 1")
  endforeach()
endfunction()

# The database: a CA, its key, a revoked device certificate, its request
# (with a challenge password), the CRL, the device public key, two keys
foreach(f ca.crt ca.key device.crt device.csr ca.crl device.pub ec.key own.key)
  list(APPEND fixtures "${DATA}/${f}")
endforeach()
run("import" 0 --password "pass:${DB_PW}" --import ${fixtures})

# The key "own" gets a password of its own, as the GUI would store it
if(OPENSSL AND EXISTS "${OPENSSL}" AND SQL_EXEC AND EXISTS "${SQL_EXEC}")
  execute_process(COMMAND "${OPENSSL}" pkcs8 -topk8 -v2 aes-256-cbc
      -in "${DATA}/own.key" -passout "pass:${OWN_PW}" -outform DER
      -out "${WORK}/own.p8"
    RESULT_VARIABLE rc ERROR_VARIABLE e)
  execute_process(COMMAND "${OPENSSL}" base64 -A -in "${WORK}/own.p8"
    RESULT_VARIABLE rc2 OUTPUT_VARIABLE b64 ERROR_VARIABLE e2)
  if(NOT rc EQUAL 0 OR NOT rc2 EQUAL 0)
    fail("openssl pkcs8: ${e}${e2}")
  endif()
  execute_process(COMMAND "${SQL_EXEC}" "${WORK}/json.xdb" -c
      "UPDATE private_keys SET ownPass=1, private='${b64}' WHERE item=(SELECT id FROM items WHERE name='own')"
    RESULT_VARIABLE rc ERROR_VARIABLE e)
  if(NOT rc EQUAL 0)
    fail("sql_exec: ${e}")
  endif()
  set(own_password TRUE)
else()
  message(STATUS "openssl or sql_exec not given: no key with its own password")
endif()

set(pw --password "pass:${DB_PW}")

# The four list outputs in one stream; "-" for index and hierarchy
run("lists" 0 ${pw} --json --list-items --issuers --index - --hierarchy -)
json_lines("lists" "${out}" list list list list)
string(REGEX MATCHALL "[^\n]+" lines "${out}")
set(i 0)
foreach(kind items index hierarchy issuers)
  list(GET lines ${i} line)
  string(JSON k GET "${line}" kind)
  if(NOT k STREQUAL kind)
    fail("lists: line ${i} is kind '${k}', expected ${kind}")
  endif()
  math(EXPR i "${i} + 1")
endforeach()
list(GET lines 0 items)
string(JSON n LENGTH "${items}" items)
if(NOT n EQUAL 8)
  fail("--list-items: ${n} items, expected 8:\n${items}")
endif()
list(GET lines 3 issuers)
string(JSON t GET "${issuers}" items 0 key_type)
if(NOT t STREQUAL "EC")
  fail("--issuers: key_type '${t}':\n${issuers}")
endif()
list(GET lines 1 index)
string(JSON status GET "${index}" items 1 status)
string(JSON reason GET "${index}" items 1 reason)
if(NOT status STREQUAL "revoked" OR NOT reason STREQUAL "keyCompromise")
  fail("--index: the device certificate is '${status}' '${reason}':\n${index}")
endif()
if(err MATCHES "Information")
  fail("lists: a message for '-':\n${err}")
endif()

# --print of every item: one document each, in --select order
run("print" 0 ${pw} --json --print --select 1,2,3,4,5,6,7,8)
json_lines("print" "${out}" certificate key certificate csr crl key key key)
string(REGEX MATCHALL "[^\n]+" lines "${out}")
list(GET lines 7 own)
string(JSON protection GET "${own}" protection)
if(own_password AND NOT protection STREQUAL "own")
  fail("--print: the key 'own' has protection '${protection}':\n${own}")
endif()
list(GET lines 3 csr)
if(csr MATCHES "1\\.2\\.840\\.113549\\.1\\.9\\.7")
  fail("--print: the request lists its challenge password:\n${csr}")
endif()
# The signed request contains the challenge password: no pem, no der
string(JSON challenge GET "${csr}" challenge_password_present)
string(JSON csr_pem ERROR_VARIABLE no_pem GET "${csr}" pem)
string(JSON csr_der ERROR_VARIABLE no_der GET "${csr}" der)
if(NOT challenge OR NOT no_pem OR NOT no_der)
  fail("--print: the request with a challenge password embeds its raw data:\n${csr}")
endif()

# Without a database password: public objects, the same documents
run("print without password" 0 --json --print --select 1,6)
json_lines("print without password" "${out}" certificate key)

# Files instead of "-": one JSON document each; stdout stays empty, the
# messages go to stderr
run("files" 0 ${pw} --json --index "${WORK}/index.json"
    --hierarchy "${WORK}/hierarchy.json")
if(NOT out STREQUAL "")
  fail("files: stdout is not empty:\n${out}")
endif()
if(NOT err MATCHES "Index file written to")
  fail("files: the message is missing on stderr:\n${err}")
endif()
foreach(f index hierarchy)
  file(READ "${WORK}/${f}.json" doc)
  json_lines("${f} file" "${doc}" list)
  set(ALL "${ALL}\n${doc}")
endforeach()
if(IS_DIRECTORY "${WORK}/hierarchy.json")
  fail("--hierarchy --json made a directory")
endif()

# Items read from files have no id and no creation date
run("print files" 0 --json --print "${DATA}/ca.crt" "${DATA}/device.csr"
    "${DATA}/ca.crl" "${DATA}/device.pub")
json_lines("print files" "${out}" certificate csr crl key)
string(REGEX MATCHALL "[^\n]+" lines "${out}")
foreach(line IN LISTS lines)
  string(JSON id TYPE "${line}" id)
  string(JSON created TYPE "${line}" created)
  if(NOT id STREQUAL "NULL" OR NOT created STREQUAL "NULL")
    fail("print files: id ${id}, created ${created}:\n${line}")
  endif()
endforeach()

# error_object(<label> <code>): stderr holds one JSON document, the error
# object of code (besides messages such as warnings); stdout no error
function(error_object label code)
  string(REGEX MATCHALL "(^|\n)\\{[^\n]*" lines "${err}")
  list(LENGTH lines n)
  if(NOT n EQUAL 1)
    fail("${label}: ${n} JSON lines on stderr, expected one error object:\n${err}")
  endif()
  string(STRIP "${lines}" doc)
  string(JSON schema ERROR_VARIABLE jerr GET "${doc}" schema)
  string(JSON c GET "${doc}" code)
  string(JSON type GET "${doc}" type)
  if(jerr OR NOT schema STREQUAL "urn:bxc-pki:schema:error:v1" OR
     NOT c STREQUAL code OR NOT type STREQUAL "urn:bxc-pki:error:${code}")
    fail("${label}: not the error object of ${code}:\n${err}")
  endif()
  if(out MATCHES "error")
    fail("${label}: an error on stdout:\n${out}")
  endif()
endfunction()

run("unknown CA" 1 ${pw} --json --crlgen no-such-ca)
error_object("unknown CA" unknown_issuer)
# the failure does not stop the other options
run("unknown CA and list" 1 ${pw} --json --crlgen no-such-ca --list-items)
error_object("unknown CA and list" unknown_issuer)
json_lines("unknown CA and list" "${out}" list)

run("wrong password" 1 --password "pass:${WRONG_PW}" --json --list-items)
error_object("wrong password" password_rejected)
if(NOT out STREQUAL "")
  fail("wrong password: output on stdout:\n${out}")
endif()

run("index write error" 1 ${pw} --json --index "${WORK}/no-such-dir/i.json")
error_object("index write error" internal_error)

# Acceptance criterion 4: no key material and no secret anywhere
foreach(secret "PRIVATE KEY" "ENCRYPTED" "${DB_PW}" "${OWN_PW}"
               "${WRONG_PW}" "Chall-Secret-42" "Import-Secret-11")
  string(FIND "${ALL}" "${secret}" pos)
  if(NOT pos EQUAL -1)
    fail("secret '${secret}' in the output")
  endif()
endforeach()

file(REMOVE_RECURSE "${WORK}")
message(STATUS "xca --no-gui --json: JSON Lines, error objects, no secrets")
