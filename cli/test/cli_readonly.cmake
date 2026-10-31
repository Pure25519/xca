# A read-only command leaves the database file byte-identical (BTD-225):
# every close ran VACUUM, which rewrote the file after list, show,
# --list-items or --audit-verify too, so its SHA-256 and mtime changed and
# a read-only file failed the VACUUM silently. A write still leaves a
# consistent, compact file.

include("${LIB}")

bxc("init" 0 init --db "${DB}" ${PW} --cn "RO Root" --key ec-p256)
# the first opens may write (schema, settings); the checks start after one
bxc("settle" 0 list --db "${DB}" ${PW})

# state(<var>): SHA-256 and mtime (seconds) of the database file
function(state var)
  file(SHA256 "${DB}" hash)
  file(TIMESTAMP "${DB}" time "%s" UTC)
  set(${var} "${hash}@${time}" PARENT_SCOPE)
endfunction()

# unchanged(<label> <command> <args>...): the command (bxc-pki or xca)
# succeeds and leaves the file as it was; the second in between makes a
# rewrite visible in the mtime too
function(unchanged label tool)
  state(before)
  execute_process(COMMAND sleep 1.1)
  if(tool STREQUAL "xca")
    execute_process(COMMAND ${as_user} "${XCA}" --no-gui --database "${DB}"
        ${PW} ${ARGN} WORKING_DIRECTORY "${WORK}" INPUT_FILE /dev/null
        RESULT_VARIABLE r OUTPUT_VARIABLE o ERROR_VARIABLE e TIMEOUT 60)
  else()
    execute_process(COMMAND ${as_user} "${BXC_PKI}" ${ARGN}
        WORKING_DIRECTORY "${WORK}" INPUT_FILE /dev/null
        RESULT_VARIABLE r OUTPUT_VARIABLE o ERROR_VARIABLE e TIMEOUT 60)
  endif()
  file(APPEND "${TRANSCRIPT}" "### ${label}\nexit ${r}\n${o}${e}\n")
  if(NOT r EQUAL 0)
    fail("${label}: exit ${r}\n${o}${e}")
  endif()
  if(e MATCHES "VACUUM")
    fail("${label}: a VACUUM was tried:\n${e}")
  endif()
  state(after)
  if(NOT before STREQUAL after)
    fail("${label} changed the database file: ${before} -> ${after}")
  endif()
endfunction()

set(as_user "")
unchanged("bxc-pki list" bxc list --db "${DB}" ${PW})
unchanged("bxc-pki show" bxc show "RO Root" --type certificate --db "${DB}"
    ${PW})
unchanged("xca --list-items" xca --list-items)
unchanged("xca --index" xca --index "${WORK}/index.txt")
unchanged("xca --hierarchy" xca --hierarchy "${WORK}/hierarchy")
unchanged("xca --audit-verify" xca --audit-verify)
# --audit-export with the password writes a checkpoint when one is due
# (BTD-37, BTD-111); the next export, with none due, is a read
execute_process(COMMAND "${XCA}" --no-gui --database "${DB}" ${PW}
    --audit-export "${WORK}/audit0.json" INPUT_FILE /dev/null
    RESULT_VARIABLE r OUTPUT_VARIABLE o ERROR_VARIABLE e TIMEOUT 60)
if(NOT r EQUAL 0)
  fail("first --audit-export: exit ${r}\n${o}${e}")
endif()
unchanged("xca --audit-export" xca --audit-export "${WORK}/audit.json")

# a plan run is audited (cli.plan), so it writes: that entry and nothing
# else
function(count var table)
  execute_process(COMMAND "${SQL_EXEC}" "${DB}" -c "SELECT COUNT(*) FROM ${table}"
    OUTPUT_VARIABLE n)
  string(STRIP "${n}" n)
  set(${var} "${n}" PARENT_SCOPE)
endfunction()
count(audit_before audit_log)
count(items_before items)
bxc("plan" 0 init --plan --db "${DB}" ${PW} --cn "Plan Root" --key ec-p256)
count(audit_after audit_log)
count(items_after items)
math(EXPR audit_expected "${audit_before} + 1")
if(NOT audit_after EQUAL audit_expected OR NOT items_after EQUAL items_before)
  fail("plan: audit ${audit_before} -> ${audit_after}, items ${items_before} -> ${items_after}")
endif()

# a write still leaves a consistent, compact file
bxc("write" 0 init --db "${DB}" ${PW} --cn "RO Second" --key ec-p256)
execute_process(COMMAND "${SQL_EXEC}" "${DB}" -c "PRAGMA integrity_check"
    -c "PRAGMA freelist_count"
  RESULT_VARIABLE rc OUTPUT_VARIABLE sql ERROR_VARIABLE e)
string(REPLACE "\n" ";" sql "${sql}")
if(NOT rc EQUAL 0 OR NOT sql MATCHES "^ok;0")
  fail("after a write: integrity_check, freelist_count = ${sql} ${e}")
endif()

# a read-only file: open, read and close without error and without a
# VACUUM attempt; root ignores file modes, so read as nobody
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
  file(CHMOD "${DB}" PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
else()
  file(CHMOD "${DB}" PERMISSIONS OWNER_READ GROUP_READ WORLD_READ)
endif()
unchanged("read-only bxc-pki list" bxc list --db "${DB}" ${PW})
unchanged("read-only xca --list-items" xca --list-items)
