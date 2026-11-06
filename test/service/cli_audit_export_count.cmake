# xca --no-gui --audit-export without --password names the number of
# unsigned entries; it is unanchored_entries of --audit-verify, the
# checkpoint row included (BTD-134). A signed export does not warn.
# cmake -DXCA=<xca> -DSQL_EXEC=<sql_exec> -DWORK=<scratch dir> -P cli_audit_export_count.cmake

file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}/home")
set(ENV{HOME} "${WORK}/home")
set(ENV{XDG_CONFIG_HOME} "${WORK}/home/.config")
set(ENV{XDG_DATA_HOME} "${WORK}/home/.local/share")
set(ENV{QT_QPA_PLATFORM} offscreen)
set(db "${WORK}/count.xdb")
set(pw --password pass:btd134-db-pass)

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

# A checkpoint, then two unsigned entries
run_xca(rc out err ${pw} --keygen EC:prime256v1 --name count-1)
execute_process(COMMAND "${SQL_EXEC}" "${db}"
  -c "INSERT INTO settings (key_, value) VALUES ('audit_checkpoint_interval', '1')")
run_xca(rc out err ${pw} --keygen EC:prime256v1 --name count-2)
execute_process(COMMAND "${SQL_EXEC}" "${db}"
  -c "UPDATE settings SET value='100' WHERE key_='audit_checkpoint_interval'")
foreach(n 3 4)
  run_xca(rc out err ${pw} --keygen EC:prime256v1 --name count-${n})
  if(NOT rc EQUAL 0)
    fail("keygen count-${n}: exit ${rc}:\n${out}${err}")
  endif()
endforeach()

run_xca(rc out err --audit-verify)
string(JSON unanchored ERROR_VARIABLE jerr GET "${out}" unanchored_entries)
string(JSON checkpoints ERROR_VARIABLE jerr GET "${out}" checkpoints)
if(NOT rc EQUAL 0 OR checkpoints LESS 1 OR unanchored LESS 2)
  fail("verify: exit ${rc}, ${checkpoints} checkpoints, unanchored ${unanchored}:\n${out}")
endif()

# Without a password: read only, the count of verify
run_xca(rc out err --audit-export -)
if(NOT rc EQUAL 0)
  fail("export without password: exit ${rc}:\n${err}")
endif()
if(NOT err MATCHES "the newest ([0-9]+) audit entries are not covered")
  fail("export without password: no count in the warning:\n${err}")
endif()
if(NOT CMAKE_MATCH_1 EQUAL unanchored)
  fail("export warns about ${CMAKE_MATCH_1} entries, verify reports unanchored_entries ${unanchored}")
endif()

# With the password: signed, no warning
run_xca(rc out err ${pw} --audit-export -)
if(NOT rc EQUAL 0 OR err MATCHES "Warning")
  fail("signed export: exit ${rc}, warning:\n${err}")
endif()

file(REMOVE_RECURSE "${WORK}")
message(STATUS "xca --no-gui --audit-export: the warning names unanchored_entries of --audit-verify")
