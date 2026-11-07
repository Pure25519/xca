# A write request of xca --no-gui that fails before its service function
# while the database is open writes a failure entry with the intended
# action and a reason code (BTD-106): --keygen with an unknown key type
# (key.generate, invalid_key_type, also with a size that would otherwise
# ask the key-size question) and --crlgen with an unknown CA
# (crl.generate, unknown_issuer). The exit code stays 1 and the message
# names the request.
# cmake -DXCA=<xca> -DWORK=<scratch dir> -P cli_precheck_audit.cmake

file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}/home")
set(ENV{HOME} "${WORK}/home")
set(ENV{XDG_CONFIG_HOME} "${WORK}/home/.config")
set(ENV{XDG_DATA_HOME} "${WORK}/home/.local/share")
set(ENV{QT_QPA_PLATFORM} offscreen)

function(fail msg)
  file(REMOVE_RECURSE "${WORK}")
  message(FATAL_ERROR "${msg}")
endfunction()

set(db --database "${WORK}/precheck.xdb" --password pass:precheck-test)
function(expect code label)
  execute_process(COMMAND "${XCA}" --no-gui ${db} ${ARGN}
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE out
    TIMEOUT 30)
  if(NOT rc EQUAL code)
    fail("${label}: expected exit code ${code}, got '${rc}':\n${out}")
  endif()
  set(out "${out}" PARENT_SCOPE)
endfunction()

# audit_count(<var> <regex>): entries of the audit export matching regex
function(audit_count var regex)
  expect(0 "audit export" --audit-export "${WORK}/audit.jsonl")
  file(STRINGS "${WORK}/audit.jsonl" lines)
  set(n 0)
  foreach(line IN LISTS lines)
    if(line MATCHES "${regex}")
      math(EXPR n "${n} + 1")
    endif()
  endforeach()
  set(${var} ${n} PARENT_SCOPE)
endfunction()

expect(0 "create the database" --list-items)

expect(1 "unknown key type" --keygen FOO:1 --name precheck-key)
if(NOT out MATCHES "Unknown key type FOO:1")
  fail("unknown key type: the message does not name the type:\n${out}")
endif()
# 100000 bits would ask the key-size question of a known type first
expect(1 "unknown key type, large size" --keygen FOO:100000)
if(NOT out MATCHES "Unknown key type FOO:100000")
  fail("unknown key type with a large size: the message does not name the type:\n${out}")
endif()
audit_count(n "\"action\":\"key\\.generate\".*\"error_code\":\"invalid_key_type\".*\"result\":\"failure\"")
if(NOT n EQUAL 2)
  fail("expected two key.generate failure entries with invalid_key_type, got ${n}")
endif()
audit_count(n "\"action\":\"key\\.generate\".*\"confirmation_required\"")
if(NOT n EQUAL 0)
  fail("an unknown key type must not ask the key-size question (${n} entries)")
endif()

expect(1 "unknown CA" --crlgen no-such-ca)
if(NOT out MATCHES "no-such-ca")
  fail("unknown CA: the message does not name the CA:\n${out}")
endif()
audit_count(n "\"action\":\"crl\\.generate\".*\"error_code\":\"unknown_issuer\".*\"issuer\":\"no-such-ca\".*\"result\":\"failure\"")
if(NOT n EQUAL 1)
  fail("expected one crl.generate failure entry with unknown_issuer, got ${n}")
endif()

# without an open database there is nothing to audit: message and exit 1
execute_process(COMMAND "${XCA}" --no-gui --database "${WORK}/no-such-dir/x.xdb"
    --password pass:precheck-test --crlgen no-such-ca
  RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE out TIMEOUT 30)
if(rc EQUAL 0)
  fail("--crlgen without a database must fail:\n${out}")
endif()

file(REMOVE_RECURSE "${WORK}")
message(STATUS "write requests refused before the service are audited")
