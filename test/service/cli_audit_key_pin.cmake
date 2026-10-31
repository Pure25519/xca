# xca --no-gui --audit-verify with a trust anchor (BTD-101): --audit-key
# pins the audit key id of an earlier export, --audit-min-checkpoint the
# newest checkpoint seen then. A mismatch exits 1 and the JSON report
# names the pinned and the found key ids.
# cmake -DXCA=<xca> -DSQL_EXEC=<sql_exec> -DWORK=<scratch dir> -P cli_audit_key_pin.cmake

file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}/home")
set(ENV{HOME} "${WORK}/home")
set(ENV{XDG_CONFIG_HOME} "${WORK}/home/.config")
set(ENV{XDG_DATA_HOME} "${WORK}/home/.local/share")
set(ENV{QT_QPA_PLATFORM} offscreen)
set(db "${WORK}/pin.xdb")
set(pw --password pass:btd101-db-pass)

function(fail msg)
  file(REMOVE_RECURSE "${WORK}")
  message(FATAL_ERROR "${msg}")
endfunction()

function(run_xca result output)
  execute_process(COMMAND "${XCA}" --no-gui --database "${db}" ${ARGN}
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err TIMEOUT 60)
  set(${result} "${rc}" PARENT_SCOPE)
  set(${output} "${out}" PARENT_SCOPE)
endfunction()

# A log with an audit key and checkpoints
run_xca(rc out ${pw} --keygen EC:prime256v1 --name pin-1)
execute_process(COMMAND "${SQL_EXEC}" "${db}"
  -c "INSERT INTO settings (key_, value) VALUES ('audit_checkpoint_interval', '1')"
  RESULT_VARIABLE rc)
foreach(n 2 3)
  run_xca(rc out ${pw} --keygen EC:prime256v1 --name pin-${n})
  if(NOT rc EQUAL 0)
    fail("keygen pin-${n}: exit ${rc}:\n${out}")
  endif()
endforeach()
run_xca(rc out --audit-verify)
string(JSON key ERROR_VARIABLE jerr GET "${out}" audit_keys 0)
string(JSON last ERROR_VARIABLE jerr GET "${out}" last_checkpoint_seq)
if(NOT rc EQUAL 0 OR key STREQUAL "" OR last STREQUAL "")
  fail("unpinned verify: exit ${rc}:\n${out}")
endif()

# The right key and checkpoint: exit 0, both named in the report
run_xca(rc out --audit-verify --audit-key ${key} --audit-min-checkpoint ${last})
string(JSON pinned ERROR_VARIABLE jerr GET "${out}" pinned_keys 0)
string(JSON ok ERROR_VARIABLE jerr GET "${out}" ok)
if(NOT rc EQUAL 0 OR NOT ok STREQUAL "ON" OR NOT pinned STREQUAL key)
  fail("pinned verify: exit ${rc}, ok ${ok}, pinned ${pinned}:\n${out}")
endif()

# Another key: exit 1, untrusted_key, the found key in the report
set(other 0000000000000000000000000000000000000000000000000000000000000000)
run_xca(rc out --audit-verify --audit-key ${other})
string(JSON reason ERROR_VARIABLE jerr GET "${out}" reason)
string(JSON found ERROR_VARIABLE jerr GET "${out}" audit_keys 0)
string(JSON pinned ERROR_VARIABLE jerr GET "${out}" pinned_keys 0)
if(NOT rc EQUAL 1 OR NOT reason STREQUAL "untrusted_key" OR
   NOT found STREQUAL key OR NOT pinned STREQUAL other)
  fail("wrong key: exit ${rc}, reason ${reason}:\n${out}")
endif()

# A checkpoint newer than the log has: exit 1, checkpoint_truncated
math(EXPR later "${last} + 100")
run_xca(rc out --audit-verify --audit-min-checkpoint ${later})
string(JSON reason ERROR_VARIABLE jerr GET "${out}" reason)
if(NOT rc EQUAL 1 OR NOT reason STREQUAL "checkpoint_truncated")
  fail("truncated: exit ${rc}, reason ${reason}:\n${out}")
endif()

file(REMOVE_RECURSE "${WORK}")
message(STATUS "xca --no-gui --audit-verify: the pinned key and checkpoint are checked")
