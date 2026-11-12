# xca --no-gui --import with files that cannot be read (BTD-270): every such
# file has one object.import failure entry (object type object, the file,
# the error code), the readable files are imported and audited as before,
# and the command exits 1. With --json each failed file is an error object
# on stderr. Boss decisions of 2026-11-04.
# cmake -DXCA=<xca> -DDATA=<test/service/data> -DWORK=<scratch dir>
#   -P cli_import_failed_files.cmake

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

set(db --database "${WORK}/import.xdb" --password pass:import-test)
function(run code label)
  execute_process(COMMAND "${XCA}" --no-gui ${db} ${ARGN}
    RESULT_VARIABLE rc OUTPUT_VARIABLE o ERROR_VARIABLE e TIMEOUT 30)
  if(NOT rc EQUAL code)
    fail("${label}: expected exit code ${code}, got '${rc}':\n${o}\n${e}")
  endif()
  set(out "${o}" PARENT_SCOPE)
  set(err "${e}" PARENT_SCOPE)
endfunction()

# audit_count(<var> <regex>): entries of the audit export matching regex
function(audit_count var regex)
  run(0 "audit export" --audit-export "${WORK}/audit.jsonl")
  file(STRINGS "${WORK}/audit.jsonl" lines)
  set(n 0)
  foreach(line IN LISTS lines)
    if(line MATCHES "${regex}")
      math(EXPR n "${n} + 1")
    endif()
  endforeach()
  set(${var} ${n} PARENT_SCOPE)
endfunction()

set(good "${DATA}/json/ca.crt")
set(bad "${WORK}/no-pki.txt")
set(missing "${WORK}/no-such-file.pem")
file(WRITE "${bad}" "this is no certificate\n")
run(0 "create the database" --list-items)

# --- a mixed import: the good file is stored, the bad one audited --------
run(1 "mixed import" --import "${good}" "${bad}")
if(NOT "${out}${err}" MATCHES "no-pki\\.txt")
  fail("mixed import: the failed file is not named:\n${out}\n${err}")
endif()
audit_count(n "\"action\":\"object\\.import\".*\"object_type\":\"certificate\".*\"result\":\"success\"")
if(NOT n EQUAL 1)
  fail("mixed import: expected one object.import success entry, got ${n}")
endif()
audit_count(n "\"action\":\"object\\.import\".*\"error_code\":\"no_pki_data\".*\"object_type\":\"object\".*\"file\":\"[^\"]*no-pki\\.txt\".*\"result\":\"failure\"")
if(NOT n EQUAL 1)
  fail("mixed import: expected one failure entry for no-pki.txt, got ${n}")
endif()
run(0 "list after the mixed import" --list-items)
if(NOT out MATCHES "JSON Test CA")
  fail("mixed import: the good certificate was not stored:\n${out}")
endif()

# --- --json: one error object per failed file on stderr -----------------
run(1 "json import" --json --import "${good}" "${bad}")
string(REGEX MATCHALL "\\{[^\n]*\"code\":\"no_pki_data\"[^\n]*" docs "${err}")
list(LENGTH docs n)
if(NOT n EQUAL 1 OR NOT docs MATCHES "no-pki\\.txt")
  fail("json import: expected one no_pki_data error object naming the file:\n${err}")
endif()

# --- every file fails: one entry per file, nothing stored ----------------
run(0 "count before" --list-items)
string(REGEX MATCHALL "\n" before "${out}")
list(LENGTH before nbefore)
run(1 "all files fail" --import "${bad}" "${missing}")
audit_count(n "\"action\":\"object\\.import\".*\"file\":\"[^\"]*no-such-file\\.pem\".*\"result\":\"failure\"")
if(NOT n EQUAL 1)
  fail("all files fail: expected one failure entry for the missing file, got ${n}")
endif()
audit_count(n "\"action\":\"object\\.import\".*\"error_code\":\"unreadable_input\".*\"file\":\"[^\"]*no-such-file\\.pem\"")
if(NOT n EQUAL 1)
  fail("all files fail: the missing file is not unreadable_input (${n})")
endif()
audit_count(n "\"action\":\"object\\.import\".*\"file\":\"[^\"]*no-pki\\.txt\".*\"result\":\"failure\"")
if(NOT n EQUAL 3)
  fail("all files fail: expected the third failure entry for no-pki.txt, got ${n}")
endif()
audit_count(n "\"action\":\"object\\.import\".*\"file\":\"[^\"]*, [^\"]*\"")
if(NOT n EQUAL 0)
  fail("a failure entry names several files instead of one each (${n})")
endif()
run(0 "count after" --list-items)
string(REGEX MATCHALL "\n" after "${out}")
list(LENGTH after nafter)
if(NOT nbefore EQUAL nafter)
  fail("all files fail: the item list changed (${nbefore} -> ${nafter})")
endif()
run(0 "audit verify" --audit-verify)

file(REMOVE_RECURSE "${WORK}")
message(STATUS "unreadable import files are audited and fail the command")
