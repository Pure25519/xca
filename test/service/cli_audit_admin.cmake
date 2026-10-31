# The audit controls on the command line (BTD-100): --audit-checkpoint-interval
# shows (current) or sets the interval, with a settings.update entry and the
# range 1..1000; --audit-rotate-key rotates the audit key. Setting and
# rotating need the database password. After the rotation --audit-verify
# reports two keys, and the rotation checkpoint of the export verifies with
# the OpenSSL commands of doc/audit-checkpoints.md.
# cmake -DXCA=<xca> -DSQL_EXEC=<sql_exec> -DOPENSSL=<openssl or empty> -DWORK=<scratch dir> -P cli_audit_admin.cmake

file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}/home")
set(ENV{HOME} "${WORK}/home")
set(ENV{XDG_CONFIG_HOME} "${WORK}/home/.config")
set(ENV{XDG_DATA_HOME} "${WORK}/home/.local/share")
set(ENV{QT_QPA_PLATFORM} offscreen)
set(db "${WORK}/admin.xdb")
set(pw --password pass:btd100-db-pass)

function(fail msg)
  message(FATAL_ERROR "${msg}")
endfunction()

function(run_xca result output error)
  execute_process(COMMAND "${XCA}" --no-gui --database "${db}" ${ARGN}
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err TIMEOUT 60)
  set(${result} "${rc}" PARENT_SCOPE)
  set(${output} "${out}" PARENT_SCOPE)
  set(${error} "${err}" PARENT_SCOPE)
endfunction()

function(sql output)
  execute_process(COMMAND "${SQL_EXEC}" "${db}" ${ARGN}
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err)
  if(NOT rc EQUAL 0)
    fail("sql_exec ${ARGN}: exit ${rc}: ${err}")
  endif()
  string(STRIP "${out}" out)
  set(${output} "${out}" PARENT_SCOPE)
endfunction()

function(current expected)
  run_xca(rc out err --audit-checkpoint-interval current)
  string(JSON value ERROR_VARIABLE jerr GET "${out}" value)
  if(NOT rc EQUAL 0 OR NOT value STREQUAL expected)
    fail("current interval: exit ${rc}, value '${value}', expected ${expected}:\n${out}${err}")
  endif()
endfunction()

run_xca(rc out err ${pw} --keygen EC:prime256v1 --name admin-1)
if(NOT rc EQUAL 0)
  fail("keygen admin-1: exit ${rc}:\n${out}${err}")
endif()

# Showing needs no password; the default is 100
current(100)

# Setting needs the password: without it exit 1, nothing changed
run_xca(rc out err --audit-checkpoint-interval 2)
if(rc EQUAL 0 OR NOT "${out}${err}" MATCHES "password")
  fail("set without password: exit ${rc}:\n${out}${err}")
endif()
current(100)

# With the password: old and new value, one settings.update entry
run_xca(rc out err ${pw} --audit-checkpoint-interval 2)
string(JSON old ERROR_VARIABLE jerr GET "${out}" old_value)
string(JSON new ERROR_VARIABLE jerr GET "${out}" new_value)
if(NOT rc EQUAL 0 OR NOT old STREQUAL "100" OR NOT new STREQUAL "2")
  fail("set 2: exit ${rc}, old '${old}', new '${new}':\n${out}${err}")
endif()
current(2)
sql(updates -c "SELECT COUNT(*) FROM audit_log WHERE action='settings.update' AND params LIKE '%\"setting\":\"audit_checkpoint_interval\"%' AND params LIKE '%\"new_value\":\"2\"%'")
if(NOT updates EQUAL 1)
  fail("settings.update entries for the interval: ${updates}")
endif()

# Out of range or not a number: exit 1, unchanged
foreach(bad 0 1001 abc -5)
  run_xca(rc out err ${pw} --audit-checkpoint-interval ${bad})
  if(rc EQUAL 0)
    fail("interval ${bad} accepted:\n${out}${err}")
  endif()
endforeach()
current(2)

# The new interval decides when the next checkpoint is written
sql(before -c "SELECT COUNT(*) FROM audit_log WHERE action='audit.checkpoint'")
foreach(n 2 3)
  run_xca(rc out err ${pw} --keygen EC:prime256v1 --name admin-${n})
endforeach()
sql(after -c "SELECT COUNT(*) FROM audit_log WHERE action='audit.checkpoint'")
if(NOT after GREATER before)
  fail("no checkpoint after two entries at interval 2 (${before} -> ${after})")
endif()

# Rotation: needs the password
run_xca(rc out err --audit-rotate-key)
if(rc EQUAL 0 OR NOT "${out}${err}" MATCHES "password")
  fail("rotate without password: exit ${rc}:\n${out}${err}")
endif()
run_xca(rc out err ${pw} --audit-rotate-key)
if(NOT rc EQUAL 0)
  fail("rotate: exit ${rc}:\n${out}${err}")
endif()
run_xca(rc out err --audit-verify)
string(JSON ok ERROR_VARIABLE jerr GET "${out}" ok)
string(JSON keys ERROR_VARIABLE jerr LENGTH "${out}" audit_keys)
if(NOT rc EQUAL 0 OR NOT ok STREQUAL "ON" OR NOT keys EQUAL 2)
  fail("verify after the rotation: exit ${rc}, ok ${ok}, ${keys} keys:\n${out}")
endif()

# The rotation checkpoint, checked with the openssl program as the doc does:
# the payload is the params without signature (the last member in RFC 8785
# order), the key the public key announced for its key_id
if(OPENSSL)
  run_xca(rc out err ${pw} --audit-export "${WORK}/audit.jsonl")
  file(STRINGS "${WORK}/audit.jsonl" lines)
  set(verified 0)
  foreach(line IN LISTS lines)
    string(JSON action GET "${line}" action)
    if(action STREQUAL "audit.key_create")
      string(JSON id GET "${line}" params key_id)
      string(JSON pem GET "${line}" params public_key)
      file(WRITE "${WORK}/key-${id}.pem" "${pem}")
    elseif(action STREQUAL "audit.checkpoint")
      string(JSON next ERROR_VARIABLE nerr GET "${line}" params next_key_id)
      if(nerr)
        continue()
      endif()
      string(JSON id GET "${line}" params key_id)
      string(JSON sig GET "${line}" params signature)
      # the params as exported, RFC 8785: string(JSON GET) would print
      # the object in its own layout; prev_hash follows params
      if(NOT line MATCHES "\"params\":(\\{.*\\}),\"prev_hash\":")
        fail("no params in the checkpoint line:\n${line}")
      endif()
      string(REGEX REPLACE ",\"signature\":\"[^\"]*\"" "" payload "${CMAKE_MATCH_1}")
      file(WRITE "${WORK}/payload.json" "${payload}")
      file(WRITE "${WORK}/sig.b64" "${sig}")
      execute_process(COMMAND "${OPENSSL}" base64 -d -A -in "${WORK}/sig.b64"
        -out "${WORK}/sig.bin" RESULT_VARIABLE rc)
      execute_process(COMMAND "${OPENSSL}" pkeyutl -verify -pubin
        -inkey "${WORK}/key-${id}.pem" -rawin -in "${WORK}/payload.json"
        -sigfile "${WORK}/sig.bin" RESULT_VARIABLE rc OUTPUT_VARIABLE vout
        ERROR_VARIABLE verr)
      if(NOT rc EQUAL 0 OR NOT vout MATCHES "Signature Verified Successfully")
        fail("openssl verify of the rotation checkpoint: exit ${rc}:\n${vout}${verr}")
      endif()
      math(EXPR verified "${verified} + 1")
    endif()
  endforeach()
  if(NOT verified EQUAL 1)
    fail("${verified} rotation checkpoints verified with openssl, expected 1")
  endif()
endif()

file(REMOVE_RECURSE "${WORK}")
message(STATUS "xca --no-gui: audit interval and key rotation on the command line")
