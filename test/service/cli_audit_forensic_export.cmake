# xca --no-gui --audit-export --password on a log that no checkpoint may
# sign (BTD-112): a broken chain (audit_chain_broken), a deleted audit key
# (audit_key_missing) and an unsigned tail longer than the interval allows
# (audit_checkpoint_missing). Each export writes every entry, warns on
# stderr with the code, writes nothing to the database and exits 1.
# cmake -DXCA=<xca> -DSQL_EXEC=<sql_exec> -DWORK=<scratch dir> -P cli_audit_forensic_export.cmake

file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}/home")
set(ENV{HOME} "${WORK}/home")
set(ENV{XDG_CONFIG_HOME} "${WORK}/home/.config")
set(ENV{XDG_DATA_HOME} "${WORK}/home/.local/share")
set(ENV{QT_QPA_PLATFORM} offscreen)
set(pw --password pass:btd112-db-pass)

function(fail msg)
  message(FATAL_ERROR "${msg}")
endfunction()

function(run_xca db result output error)
  execute_process(COMMAND "${XCA}" --no-gui --database "${db}" ${ARGN}
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err TIMEOUT 60)
  set(${result} "${rc}" PARENT_SCOPE)
  set(${output} "${out}" PARENT_SCOPE)
  set(${error} "${err}" PARENT_SCOPE)
endfunction()

function(sql db output)
  execute_process(COMMAND "${SQL_EXEC}" "${db}" ${ARGN}
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err)
  if(NOT rc EQUAL 0)
    fail("sql_exec ${ARGN}: exit ${rc}: ${err}")
  endif()
  string(STRIP "${out}" out)
  set(${output} "${out}" PARENT_SCOPE)
endfunction()

# Three keys, without any checkpoint yet (the default interval is longer)
set(tail "${WORK}/tail.xdb")
foreach(n 1 2 3)
  run_xca("${tail}" rc out err ${pw} --keygen EC:prime256v1 --name fx-${n})
  if(NOT rc EQUAL 0)
    fail("keygen fx-${n}: exit ${rc}:\n${out}${err}")
  endif()
endforeach()
sql("${tail}" checkpoints -c "SELECT COUNT(*) FROM audit_log WHERE action='audit.checkpoint'")
if(NOT checkpoints EQUAL 0)
  fail("the base log has ${checkpoints} checkpoints already")
endif()

# A signed log: a key and a checkpoint, then one unsigned entry
set(signed "${WORK}/signed.xdb")
run_xca("${signed}" rc out err ${pw} --keygen EC:prime256v1 --name fx-s1)
sql("${signed}" out -c "INSERT INTO settings (key_, value) VALUES ('audit_checkpoint_interval', '1')")
run_xca("${signed}" rc out err ${pw} --keygen EC:prime256v1 --name fx-s2)
sql("${signed}" out -c "UPDATE settings SET value='100' WHERE key_='audit_checkpoint_interval'")
run_xca("${signed}" rc out err ${pw} --keygen EC:prime256v1 --name fx-s3)
sql("${signed}" checkpoints -c "SELECT COUNT(*) FROM audit_log WHERE action='audit.checkpoint'")
sql("${signed}" last -c "SELECT action FROM audit_log ORDER BY seq DESC LIMIT 1")
if(NOT rc EQUAL 0 OR checkpoints EQUAL 0 OR last STREQUAL "audit.checkpoint")
  fail("signed log: exit ${rc}, ${checkpoints} checkpoints, newest entry ${last}:\n${out}${err}")
endif()

# chain: the newest entry changed without recomputing the chain
set(chain "${WORK}/chain.xdb")
file(COPY_FILE "${signed}" "${chain}")
sql("${chain}" out -c "UPDATE audit_log SET actor='os:mallory' WHERE seq=(SELECT MAX(seq) FROM audit_log)")
# key: the audit key deleted
set(key "${WORK}/key.xdb")
file(COPY_FILE "${signed}" "${key}")
sql("${key}" out -c "DELETE FROM audit_keys")
# tail: more unsigned entries than the interval allows, no key yet
sql("${tail}" out -c "INSERT INTO settings (key_, value) VALUES ('audit_checkpoint_interval', '1')")

foreach(case chain:audit_chain_broken key:audit_key_missing
             tail:audit_checkpoint_missing)
  string(REPLACE ":" ";" parts "${case}")
  list(GET parts 0 name)
  list(GET parts 1 code)
  set(db "${WORK}/${name}.xdb")
  file(SHA256 "${db}" before)
  sql("${db}" entries -c "SELECT COUNT(*) FROM audit_log")
  set(file "${WORK}/${name}.jsonl")

  run_xca("${db}" rc out err ${pw} --audit-export "${file}")
  if(NOT rc EQUAL 1)
    fail("${name}: exit ${rc}, expected 1:\n${out}${err}")
  endif()
  if(NOT EXISTS "${file}")
    fail("${name}: no export file:\n${err}")
  endif()
  file(STRINGS "${file}" lines)
  list(LENGTH lines n)
  if(NOT n EQUAL entries)
    fail("${name}: ${n} lines exported, the log has ${entries}")
  endif()
  if(NOT err MATCHES "${code}")
    fail("${name}: the warning does not name ${code}:\n${err}")
  endif()
  if(err MATCHES "no database password given")
    fail("${name}: the warning claims a missing password:\n${err}")
  endif()
  file(SHA256 "${db}" after)
  if(NOT before STREQUAL after)
    fail("${name}: the export changed the database")
  endif()

  # Standard output: the same lines, the same exit code
  run_xca("${db}" rc out err ${pw} --audit-export -)
  file(READ "${file}" content)
  if(NOT rc EQUAL 1 OR NOT out STREQUAL content)
    fail("${name}: export to stdout: exit ${rc}:\n${err}")
  endif()
endforeach()

file(REMOVE_RECURSE "${WORK}")
message(STATUS "xca --no-gui --audit-export: a log in a broken state is exported read-only, exit 1")
