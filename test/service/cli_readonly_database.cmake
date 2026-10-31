# xca --no-gui on a database it may not write (BTD-50): a write command ends
# with exit code 1 and the error object read_only_database naming the
# command (since BTD-214, refused before any work); reading commands keep
# working.
# cmake -DXCA=<xca> [-DSETPRIV=<setpriv>] -DWORK=<scratch dir>
#       -P cli_readonly_database.cmake

file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}/home")
set(ENV{HOME} "${WORK}/home")
set(ENV{XDG_CONFIG_HOME} "${WORK}/home/.config")
set(ENV{XDG_DATA_HOME} "${WORK}/home/.local/share")
set(ENV{QT_QPA_PLATFORM} offscreen)
set(DB "${WORK}/ro.xdb")
set(db --database "${DB}" --password pass:readonly-test)

function(fail msg)
  message(FATAL_ERROR "${msg}")
endfunction()

execute_process(COMMAND "${XCA}" --no-gui ${db} --keygen EC:prime256v1
    --name writable RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE out
    TIMEOUT 60)
if(NOT rc EQUAL 0)
  fail("setup: --keygen on a new database: exit ${rc}\n${out}")
endif()

# root ignores file modes: then run as nobody on a database owned by root
execute_process(COMMAND id -u OUTPUT_VARIABLE uid)
string(STRIP "${uid}" uid)
set(as_user "")
if(uid STREQUAL "0")
  if(NOT SETPRIV OR NOT EXISTS "${SETPRIV}")
    message(STATUS "root without setpriv: read-only database not tested")
    return()
  endif()
  set(as_user "${SETPRIV}" --reuid=65534 --regid=65534 --clear-groups)
  file(CHMOD "${WORK}" "${WORK}/home" DIRECTORY_PERMISSIONS OWNER_READ
    OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ
    WORLD_WRITE WORLD_EXECUTE)
  file(CHMOD "${DB}" PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
else()
  file(CHMOD "${DB}" PERMISSIONS OWNER_READ GROUP_READ WORLD_READ)
endif()

# run(<exit code> <args>...): xca --no-gui as the reader; sets out and err
function(run expected)
  execute_process(COMMAND ${as_user} "${XCA}" --no-gui ${db} ${ARGN}
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err TIMEOUT 60
    INPUT_FILE /dev/null)
  if(NOT rc EQUAL expected)
    fail("${ARGN}: exit ${rc}, expected ${expected}\nstdout: ${out}\nstderr: ${err}")
  endif()
  set(out "${out}" PARENT_SCOPE)
  set(err "${err}" PARENT_SCOPE)
endfunction()

run(1 --json --keygen EC:prime256v1 --name refused)
# the error object is the line that starts with {"code"
string(REGEX MATCH "{\"code\"[^\n]*}" obj "${err}")
string(JSON code ERROR_VARIABLE jerr GET "${obj}" code)
if(jerr OR NOT code STREQUAL "read_only_database")
  fail("--keygen: error code '${code}', expected read_only_database:\n${err}")
endif()
string(JSON detail GET "${obj}" detail)
# Since BTD-214 the write probe of the open finds the read-only file and
# the command is refused before the key is generated; the store path of
# BTD-50 behind it is tested by test_service_sql_errors
if(NOT detail MATCHES "--keygen" OR NOT detail MATCHES "read-only")
  fail("--keygen: the detail names neither the command nor the cause: ${detail}")
endif()
if(detail MATCHES "INSERT INTO|private_keys")
  fail("--keygen: the error shows the SQL statement: ${detail}")
endif()

# reading still works, and the refused key is not there
run(0 --list-items)
if(NOT out MATCHES "writable" OR out MATCHES "refused")
  fail("--list-items after the refused write:\n${out}")
endif()

file(REMOVE_RECURSE "${WORK}")
