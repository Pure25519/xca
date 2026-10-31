# A database with an unreadable row that the reader may not write
# (BTD-209, condition of the review of xca#75): open and read work, the
# skipped row is named on stderr, --audit-verify reports ok, and no entry
# (and no part of one) is left: the entry of the skipped rows is best
# effort.
# cmake -DXCA=<xca> -DSQL_EXEC=<sql_exec> [-DSETPRIV=<setpriv>]
#       -DWORK=<scratch dir> -P cli_skipped_rows_readonly.cmake

file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}/home")
set(ENV{HOME} "${WORK}/home")
set(ENV{XDG_CONFIG_HOME} "${WORK}/home/.config")
set(ENV{XDG_DATA_HOME} "${WORK}/home/.local/share")
set(ENV{QT_QPA_PLATFORM} offscreen)
set(DB "${WORK}/rows.xdb")
set(db --database "${DB}" --password pass:rows-test)

function(fail msg)
  message(FATAL_ERROR "${msg}")
endfunction()

foreach(name broken kept)
  execute_process(COMMAND "${XCA}" --no-gui ${db} --keygen EC:prime256v1
      --name ${name} RESULT_VARIABLE rc OUTPUT_VARIABLE out
      ERROR_VARIABLE out TIMEOUT 60)
  if(NOT rc EQUAL 0)
    fail("setup: --keygen ${name}: exit ${rc}\n${out}")
  endif()
endforeach()
execute_process(COMMAND "${SQL_EXEC}" "${DB}" -c
    "UPDATE public_keys SET \"public\"='/////w==' WHERE item=(SELECT id FROM items WHERE name='broken')"
    -c "SELECT COUNT(*) FROM audit_log"
  RESULT_VARIABLE rc OUTPUT_VARIABLE before ERROR_VARIABLE e)
if(NOT rc EQUAL 0)
  fail("sql_exec: ${e}")
endif()
string(STRIP "${before}" before)

# root ignores file modes: then read as nobody a database owned by root
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

execute_process(COMMAND ${as_user} "${XCA}" --no-gui ${db} --list-items
  RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err TIMEOUT 60
  INPUT_FILE /dev/null)
if(NOT rc EQUAL 0)
  fail("--list-items on the read-only database: exit ${rc}\n${out}${err}")
endif()
if(NOT out MATCHES "kept" OR out MATCHES "broken")
  fail("--list-items lists the wrong keys:\n${out}")
endif()
if(NOT err MATCHES "left out" OR NOT err MATCHES "key [0-9]+: The key 'broken'")
  fail("the skipped row is not named on stderr:\n${err}")
endif()

execute_process(COMMAND ${as_user} "${XCA}" --no-gui ${db} --audit-verify
  RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err TIMEOUT 60
  INPUT_FILE /dev/null)
if(NOT rc EQUAL 0 OR NOT out MATCHES "\"ok\":true")
  fail("--audit-verify on the read-only database: exit ${rc}\n${out}${err}")
endif()

execute_process(COMMAND "${SQL_EXEC}" "${DB}" -c "SELECT COUNT(*) FROM audit_log"
  RESULT_VARIABLE rc OUTPUT_VARIABLE after ERROR_VARIABLE e)
string(STRIP "${after}" after)
if(NOT rc EQUAL 0 OR NOT after STREQUAL before)
  fail("audit entries: ${before} before, ${after} after the read-only opens ${e}")
endif()

file(REMOVE_RECURSE "${WORK}")
