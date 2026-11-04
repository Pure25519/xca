# An audit check does not change what it checks (BTD-70): --audit-verify
# and --audit-export on a database of an older schema (the schema 8 fork
# fixture) report schema_upgrade_required and exit 1, and the file stays
# byte-identical; they used to migrate it and write the audit baseline.
# A normal open of the same database migrates it, after a backup copy of
# the old file.
# cmake -DXCA=<xca> -DSQL_EXEC=<sql_exec> [-DDUMP=<schema8-fork.sql>] -DDATA=<test/service/data>
#       -DWORK=<scratch dir> -P cli_audit_no_upgrade.cmake

if(NOT DUMP)
  set(DUMP "${DATA}/schema8-fork.sql")
endif()
file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}/home")
set(ENV{HOME} "${WORK}/home")
set(ENV{XDG_CONFIG_HOME} "${WORK}/home/.config")
set(ENV{XDG_DATA_HOME} "${WORK}/home/.local/share")
set(ENV{QT_QPA_PLATFORM} offscreen)
set(db "${WORK}/old.xdb")
set(pw --password pass:service-test-db-pass)

function(fail msg)
  message(FATAL_ERROR "${msg}")
endfunction()

execute_process(COMMAND "${SQL_EXEC}" "${db}" "${DUMP}"
  RESULT_VARIABLE rc ERROR_VARIABLE err)
if(NOT rc EQUAL 0)
  fail("sql_exec ${DUMP}: exit '${rc}': ${err}")
endif()
file(SHA256 "${db}" before)

foreach(check --audit-verify --audit-export)
  if(check STREQUAL "--audit-export")
    set(args --audit-export "${WORK}/audit.jsonl")
  else()
    set(args --audit-verify)
  endif()
  execute_process(COMMAND "${XCA}" --no-gui --database "${db}" ${pw} ${args}
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err TIMEOUT 60)
  file(SHA256 "${db}" after)
  if(NOT after STREQUAL before)
    fail("${check} changed the database of an older schema (sha256 ${before} -> ${after}), exit ${rc}:\n${out}${err}")
  endif()
  if(NOT rc EQUAL 1 OR NOT out MATCHES "\"schema_upgrade_required\":true")
    fail("${check}: expected exit 1 and schema_upgrade_required, got '${rc}':\n${out}${err}")
  endif()
  file(GLOB backups "${db}.bak-*")
  if(backups)
    fail("${check} wrote a backup: ${backups}")
  endif()
endforeach()

# A normal open (a read command too) migrates, after a backup of the old
# file
execute_process(COMMAND "${XCA}" --no-gui --database "${db}" ${pw} --list-items
  RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err TIMEOUT 60)
if(NOT rc EQUAL 0)
  fail("--list-items: exit ${rc}:\n${out}${err}")
endif()
file(GLOB backups "${db}.bak-*")
list(LENGTH backups n)
if(NOT n EQUAL 1)
  fail("expected one backup before the migration, found: ${backups}")
endif()
file(SHA256 "${backups}" saved)
if(NOT saved STREQUAL before)
  fail("the backup is not the old file (${saved} != ${before})")
endif()
execute_process(COMMAND "${SQL_EXEC}" "${db}" -c "SELECT count(*) FROM settings WHERE key_='bxc_schema'"
  OUTPUT_VARIABLE migrated)
if(NOT migrated STREQUAL "1\n")
  fail("the normal open did not migrate: bxc_schema rows ${migrated}")
endif()

# Now current: the audit check works and exits 0
execute_process(COMMAND "${XCA}" --no-gui --database "${db}" ${pw} --audit-verify
  RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err TIMEOUT 60)
if(NOT rc EQUAL 0 OR NOT out MATCHES "\"ok\":true")
  fail("--audit-verify on the migrated database: exit ${rc}:\n${out}${err}")
endif()

file(REMOVE_RECURSE "${WORK}")
