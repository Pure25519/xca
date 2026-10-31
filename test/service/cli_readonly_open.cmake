# xca --no-gui detects a read-only database when it opens it (BTD-214): a
# write probe after the unlock. Reading commands work, writing commands
# are refused with read_only_database before any work, an export does not
# try to sign a checkpoint, and a database that needs a schema upgrade is
# not opened. A database locked by another process is not read-only, and
# the probe changes nothing on a writable database.
# cmake -DXCA=<xca> -DSQL_EXEC=<sql_exec> [-DSETPRIV=<setpriv>] -DDATA=<data>
#       -DWORK=<scratch dir> -P cli_readonly_open.cmake

file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}/home")
set(ENV{HOME} "${WORK}/home")
set(ENV{XDG_CONFIG_HOME} "${WORK}/home/.config")
set(ENV{XDG_DATA_HOME} "${WORK}/home/.local/share")
set(ENV{QT_QPA_PLATFORM} offscreen)
set(DB "${WORK}/ro.xdb")
set(pw --password pass:readonly-open)

function(fail msg)
  message(FATAL_ERROR "${msg}")
endfunction()

# run(<exit code> <db> <args>...): xca --no-gui as the reader; sets out, err
function(run expected db)
  execute_process(COMMAND ${as_user} "${XCA}" --no-gui --database "${db}"
      ${ARGN}
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err TIMEOUT 60
    INPUT_FILE /dev/null)
  if(NOT rc EQUAL expected)
    fail("${ARGN}: exit ${rc}, expected ${expected}\nstdout: ${out}\nstderr: ${err}")
  endif()
  set(out "${out}" PARENT_SCOPE)
  set(err "${err}" PARENT_SCOPE)
endfunction()

# A writable database first: the probe of a reading command changes nothing
set(as_user "")
run(0 "${DB}" ${pw} --keygen EC:prime256v1 --name writable)
file(SHA256 "${DB}" before)
run(0 "${DB}" ${pw} --list-items)
file(SHA256 "${DB}" after)
if(NOT before STREQUAL after)
  fail("the probe changed a writable database")
endif()

# A lock another process holds is not read-only: the reading command waits
# for the busy timeout and lists the items
execute_process(COMMAND sh -c "\"$0\" \"$1\" -c 'BEGIN EXCLUSIVE' --sleep 3 >/dev/null 2>&1 &"
    "${SQL_EXEC}" "${DB}" RESULT_VARIABLE rc)
execute_process(COMMAND sh -c "sleep 0.5")
run(0 "${DB}" ${pw} --list-items)
if(err MATCHES "read-only" OR NOT out MATCHES "writable")
  fail("a locked database counted as read-only:\nstdout: ${out}\nstderr: ${err}")
endif()
execute_process(COMMAND sh -c "sleep 3")

# An old database that needs the schema upgrade, made read-only below
set(OLD "${WORK}/old.xdb")
execute_process(COMMAND "${SQL_EXEC}" "${OLD}" "${DATA}/schema8-fork.sql"
  RESULT_VARIABLE rc ERROR_VARIABLE e)
if(NOT rc EQUAL 0)
  fail("loading schema8-fork.sql: ${e}")
endif()

# root ignores file modes: then run as nobody on databases owned by root
execute_process(COMMAND id -u OUTPUT_VARIABLE uid)
string(STRIP "${uid}" uid)
if(uid STREQUAL "0")
  if(NOT SETPRIV OR NOT EXISTS "${SETPRIV}")
    message(STATUS "root without setpriv: read-only database not tested")
    return()
  endif()
  set(as_user "${SETPRIV}" --reuid=65534 --regid=65534 --clear-groups)
  file(CHMOD "${WORK}" "${WORK}/home" DIRECTORY_PERMISSIONS OWNER_READ
    OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ
    WORLD_WRITE WORLD_EXECUTE)
  file(CHMOD "${DB}" "${OLD}" PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ
    WORLD_READ)
else()
  file(CHMOD "${DB}" "${OLD}" PERMISSIONS OWNER_READ GROUP_READ WORLD_READ)
endif()
file(SHA256 "${DB}" before)

# Reading works and says the database is read-only
run(0 "${DB}" ${pw} --list-items)
if(NOT out MATCHES "writable" OR NOT err MATCHES "read-only")
  fail("--list-items on the read-only database:\nstdout: ${out}\nstderr: ${err}")
endif()

# Each writing command is refused before any work: no key generated, no
# template looked up, nothing imported
foreach(cmd "--keygen;EC:prime256v1;--name;refused"
            "--migrate-template;TLS_server"
            "--crlgen;writable"
            "--audit-adopt")
  run(1 "${DB}" ${pw} --json ${cmd})
  string(REGEX MATCH "{\"code\"[^\n]*}" obj "${err}")
  string(JSON code ERROR_VARIABLE jerr GET "${obj}" code)
  if(jerr OR NOT code STREQUAL "read_only_database")
    fail("${cmd}: error code '${code}', expected read_only_database:\n${err}")
  endif()
  if(err MATCHES "Successfully created|not found|unknown")
    fail("${cmd}: work was done before the refusal:\n${err}")
  endif()
endforeach()

# An export does not try to sign a checkpoint on it
run(0 "${DB}" ${pw} --audit-export "${WORK}/ro-export.jsonl")
if(NOT err MATCHES "read-only")
  fail("--audit-export does not say why no checkpoint was signed:\n${err}")
endif()

file(SHA256 "${DB}" after)
if(NOT before STREQUAL after)
  fail("the read-only database changed")
endif()

# The old database needs its upgrade: not opened, nothing written
file(SHA256 "${OLD}" before)
run(1 "${OLD}" --password pass:service-test-db-pass --json --list-items)
string(REGEX MATCH "{\"code\"[^\n]*}" obj "${err}")
string(JSON code ERROR_VARIABLE jerr GET "${obj}" code)
if(jerr OR NOT code STREQUAL "read_only_database" OR NOT obj MATCHES "upgrade")
  fail("old read-only database: expected read_only_database naming the upgrade:\n${err}")
endif()
file(SHA256 "${OLD}" after)
if(NOT before STREQUAL after)
  fail("the old read-only database changed")
endif()

file(REMOVE_RECURSE "${WORK}")
