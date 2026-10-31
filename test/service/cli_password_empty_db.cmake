# xca --no-gui on a database whose password is empty (BTD-117): a given
# --password is read and compared, so every source is rejected (no source
# delivers an empty password), nothing is generated and the old database
# is neither upgraded nor given an audit baseline. Without --password the
# old database is refused as well: an upgrade needs the verified password
# (BTD-137, Variante A).
# The xca command line cannot create such a database (the GUI can): the
# schema 8 fixture gets the stored hash of the empty password.
# cmake -DXCA=<xca> -DSQL_EXEC=<sql_exec> [-DDUMP=<schema8-fork.sql>] -DDATA=<test/service/data>
#       -DWORK=<scratch dir> -P cli_password_empty_db.cmake

if(NOT DUMP)
  set(DUMP "${DATA}/schema8-fork.sql")
endif()
file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}/home")
set(ENV{HOME} "${WORK}/home")
set(ENV{XDG_CONFIG_HOME} "${WORK}/home/.config")
set(ENV{XDG_DATA_HOME} "${WORK}/home/.local/share")
set(ENV{QT_QPA_PLATFORM} offscreen)
set(db "${WORK}/empty.xdb")

function(fail msg)
  file(REMOVE_RECURSE "${WORK}")
  message(FATAL_ERROR "${msg}")
endfunction()

function(run_xca result output)
  execute_process(COMMAND "${XCA}" --no-gui --database "${db}" ${ARGN}
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE out
    TIMEOUT 30)
  set(${result} "${rc}" PARENT_SCOPE)
  set(${output} "${out}" PARENT_SCOPE)
endfunction()

function(sql output)
  execute_process(COMMAND "${SQL_EXEC}" "${db}" ${ARGN}
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err)
  if(NOT rc EQUAL 0)
    fail("sql_exec ${ARGN}: exit '${rc}': ${err}")
  endif()
  set(${output} "${out}" PARENT_SCOPE)
endfunction()

# sha512passwT("", "T0123456789abcdef"): the salt followed by 8000 rounds
# of SHA-512 over salt + password, as pki_evp::sha512passwT() stores it
set(empty_hash "T0123456789abcdef8EF9BC55FA465F6AADA783D3C85FC941974678C904A4385043F74E91A2EA048CB8A23031393670890D4BA787BA8CE307B1DA88DCECE5DE8764E09F16C820DCD4")
sql(out "${DUMP}" -c "UPDATE settings SET value='${empty_hash}' WHERE key_='pwhash'")

file(WRITE "${WORK}/pw.txt" "wrong-file-pw\n")
set(ENV{XCA_EMPTY_DB_WRONG} "wrong-env-pw")

# Every source is read and rejected; keygen would write a key and an
# audit entry with db_unlock_verified=true if it got through
foreach(source "pass:wrong-pass-pw" "env:XCA_EMPTY_DB_WRONG"
               "file:${WORK}/pw.txt" "stdin" "fd:3")
  set(args --password "${source}" --keygen EC:prime256v1 --name intruder-key)
  if(source STREQUAL "stdin")
    execute_process(COMMAND "${XCA}" --no-gui --database "${db}" ${args}
      INPUT_FILE "${WORK}/pw.txt"
      RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE out TIMEOUT 30)
  elseif(source STREQUAL "fd:3")
    execute_process(COMMAND sh -c "exec \"$0\" \"$@\" 3<\"${WORK}/pw.txt\""
        "${XCA}" --no-gui --database "${db}" ${args}
      RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE out TIMEOUT 30)
  else()
    run_xca(rc out ${args})
  endif()
  if(NOT rc EQUAL 1 OR NOT out MATCHES "was not accepted")
    fail("${source}: expected exit 1 and 'was not accepted', got '${rc}':\n${out}")
  endif()
  if(out MATCHES "wrong-[a-z]+-pw")
    fail("${source}: the message shows the password:\n${out}")
  endif()
endforeach()

# The rejected opens left the old database as it was: no fork schema,
# no audit log, no baseline, no key
sql(out -c "SELECT count(*) FROM sqlite_master WHERE name='audit_log'"
        -c "SELECT count(*) FROM settings WHERE key_='bxc_schema'"
        -c "SELECT count(*) FROM items WHERE name='intruder-key'")
if(NOT out STREQUAL "0\n0\n0\n")
  fail("a rejected open wrote to the database (audit_log, bxc_schema, key):\n${out}")
endif()

# Without --password: the empty password is the database's password, so
# the open counts as verified (BTD-246, boss 2026-10-31): the old
# database is upgraded and its baseline records db_unlock_verified=true.
# Before, the open counted as unverified and was refused (BTD-137).
run_xca(rc out --list-items)
if(NOT rc EQUAL 0 OR NOT out MATCHES "fixture-rsa")
  fail("no password: expected exit 0 and the fixture items, got '${rc}':\n${out}")
endif()
run_xca(rc out --audit-export -)
file(REMOVE_RECURSE "${WORK}")
if(NOT rc EQUAL 0 OR NOT out MATCHES "\"action\":\"audit.init\"")
  message(FATAL_ERROR "no password: expected the baseline in the export, got '${rc}':\n${out}")
endif()
if(out MATCHES "\"db_unlock_verified\":false" OR out MATCHES "intruder-key")
  message(FATAL_ERROR "the export records an unverified open or the key:\n${out}")
endif()
if(NOT out MATCHES "\"db_unlock_verified\":true")
  message(FATAL_ERROR "no password: no entry records the verified open:\n${out}")
endif()
message(STATUS "xca --no-gui: empty-password database rejects every given source; without one it opens verified")
