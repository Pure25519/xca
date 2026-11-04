# xca --no-gui tells the user about a skipped automatic audit checkpoint
# (BTD-148): one notice on stderr with the error code and the next step,
# once per command, nothing on stdout; the command still succeeds.
# cmake -DXCA=<xca> -DSQL_EXEC=<sql_exec> -DWORK=<scratch dir>
#       -P cli_checkpoint_notice.cmake

file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}/home")
set(ENV{HOME} "${WORK}/home")
set(ENV{XDG_CONFIG_HOME} "${WORK}/home/.config")
set(ENV{XDG_DATA_HOME} "${WORK}/home/.local/share")
set(ENV{QT_QPA_PLATFORM} offscreen)
set(db "${WORK}/notice.xdb")

function(fail msg)
  file(REMOVE_RECURSE "${WORK}")
  message(FATAL_ERROR "${msg}")
endfunction()

function(keygen name)
  execute_process(COMMAND "${XCA}" --no-gui --database "${db}"
      --password pass:btd148-db-pass --keygen EC:prime256v1 --name ${name}
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err TIMEOUT 60)
  if(NOT rc EQUAL 0)
    fail("keygen ${name}: exit '${rc}':\n${out}\n${err}")
  endif()
  set(stdout "${out}" PARENT_SCOPE)
  set(stderr "${err}" PARENT_SCOPE)
endfunction()

function(sql)
  execute_process(COMMAND "${SQL_EXEC}" "${db}" ${ARGN}
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err)
  if(NOT rc EQUAL 0)
    fail("sql_exec ${ARGN}: exit '${rc}': ${err}")
  endif()
endfunction()

# A checkpoint after every entry, so the audit key is created and named
keygen(k1)
sql(-c "DELETE FROM settings WHERE key_='audit_checkpoint_interval'"
    -c "INSERT INTO settings (key_, value) VALUES ('audit_checkpoint_interval', '1')")
keygen(k2)
if(stderr MATCHES "Notice:")
  fail("a notice while the checkpoints work:\n${stderr}")
endif()

# The announced key is gone: every later checkpoint is skipped
sql(-c "DELETE FROM audit_keys")
foreach(name k3 k4)
  keygen(${name})
  string(REGEX MATCHALL "Notice:[^\n]*audit_key_missing" notices "${stderr}")
  list(LENGTH notices count)
  if(NOT count EQUAL 1)
    fail("${name}: expected one notice with audit_key_missing, got ${count}:\n${stderr}")
  endif()
  if(NOT stderr MATCHES "--audit-verify")
    fail("${name}: the notice names no next step:\n${stderr}")
  endif()
  if(stdout MATCHES "Notice:|audit_key_missing")
    fail("${name}: the notice is on stdout:\n${stdout}")
  endif()
endforeach()

file(REMOVE_RECURSE "${WORK}")
message(STATUS "xca --no-gui: a skipped automatic checkpoint is one notice per command on stderr")
