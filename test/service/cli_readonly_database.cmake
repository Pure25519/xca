# xca --no-gui on a database it may not write (BTD-50): a write command ends
# with exit code 1 and the error object read_only_database naming the
# object; reading commands keep working.
# cmake -DXCA=<xca> [-DSETPRIV=<setpriv>] -DSOURCE=<source dir>
#       -DWORK=<scratch dir>
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

# a template for the profile store write below
execute_process(COMMAND "${XCA}" --no-gui ${db} --import
    "${SOURCE}/misc/TLS_server.xca" RESULT_VARIABLE rc OUTPUT_VARIABLE out
    ERROR_VARIABLE out TIMEOUT 60)
if(NOT rc EQUAL 0)
  fail("setup: importing the template: exit ${rc}\n${out}")
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
if(NOT detail MATCHES "refused" OR NOT detail MATCHES "readonly")
  fail("--keygen: the detail names neither the key nor the cause: ${detail}")
endif()
if(detail MATCHES "INSERT INTO|private_keys")
  fail("--keygen: the error shows the SQL statement: ${detail}")
endif()

# A write through another helper than the item store (BTD-189): the
# profile store. The detail names the cause, not the statement, its
# bound values or the source location of the query.
run(1 --json --migrate-template TLS_server --name ro-profile)
string(REGEX MATCH "{\"code\"[^\n]*}" obj "${err}")
string(JSON detail ERROR_VARIABLE jerr GET "${obj}" detail)
if(jerr OR NOT detail MATCHES "readonly")
  fail("--migrate-template: the detail does not name the cause:\n${err}")
endif()
# Nothing on stderr shows them either, the log line of a lost audit
# entry included
if(err MATCHES "INSERT|UPDATE|VALUES|\\.cpp:[0-9]+ \\(")
  fail("--migrate-template: the error shows the SQL statement:\n${err}")
endif()

# reading still works, and the refused key is not there
run(0 --list-items)
if(NOT out MATCHES "writable" OR out MATCHES "refused")
  fail("--list-items after the refused write:\n${out}")
endif()

file(REMOVE_RECURSE "${WORK}")
