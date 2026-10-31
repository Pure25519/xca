# xca --no-gui with an explicitly empty --password "" (BTD-136, option C):
# the value most likely comes from an unset variable, so the command ends
# with exit code 1 and a message before any database is opened or created.
# Without the option the open of BTD-78/BTD-246 stays as it is.
# cmake -DXCA=<path to xca> -DWORK=<scratch dir> -P cli_password_empty_option.cmake

file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}/home")
set(ENV{HOME} "${WORK}/home")
set(ENV{XDG_CONFIG_HOME} "${WORK}/home/.config")
set(ENV{XDG_DATA_HOME} "${WORK}/home/.local/share")
set(ENV{QT_QPA_PLATFORM} offscreen)
set(db "${WORK}/empty-option.xdb")

function(fail msg)
  file(REMOVE_RECURSE "${WORK}")
  message(FATAL_ERROR "${msg}")
endfunction()

function(run_xca result output)
  execute_process(COMMAND "${XCA}" --no-gui ${ARGN}
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE out
    TIMEOUT 30)
  set(${result} "${rc}" PARENT_SCOPE)
  set(${output} "${out}" PARENT_SCOPE)
endfunction()

# exit 1 and the message that names the option, for both spellings:
# "--password" "" as two arguments and "--password=". The empty argument
# is written out here, a list such as ARGN would drop it.
function(expect_refused label)
  foreach(form split joined)
    if(form STREQUAL "split")
      execute_process(COMMAND "${XCA}" --no-gui --password "" ${ARGN}
        RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE out
        TIMEOUT 30)
    else()
      execute_process(COMMAND "${XCA}" --no-gui --password= ${ARGN}
        RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE out
        TIMEOUT 30)
    endif()
    if(NOT rc EQUAL 1 OR NOT out MATCHES "--password is empty")
      fail("${label} (${form}): expected exit 1 and '--password is empty', got '${rc}':\n${out}")
    endif()
  endforeach()
  set(out "${out}" PARENT_SCOPE)
endfunction()

run_xca(rc out --database "${db}" --password pass:right-pw
  --keygen EC:prime256v1 --name option-key)
if(NOT rc EQUAL 0)
  fail("creating the database: exit '${rc}':\n${out}")
endif()
file(SHA256 "${db}" before)

# An existing database: nothing listed, nothing written
expect_refused("existing database" --database "${db}" --list-items)
if(out MATCHES "option-key")
  fail("existing database: the items were listed:\n${out}")
endif()
expect_refused("existing database, keygen" --database "${db}"
  --keygen EC:prime256v1 --name empty-option-key)
file(SHA256 "${db}" after)
if(NOT before STREQUAL after)
  fail("existing database: the file changed")
endif()

# A new path: no database is created
expect_refused("new database" --database "${WORK}/new.xdb"
  --keygen EC:prime256v1 --name new-key)
if(EXISTS "${WORK}/new.xdb")
  fail("new database: the file was created")
endif()

# A command that needs no database is refused as well
expect_refused("no database" --list-curves)

# With --json the error is the JSON error form with missing_password
execute_process(COMMAND "${XCA}" --no-gui --json --database "${db}"
    --password "" --list-items
  RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE out TIMEOUT 30)
if(NOT rc EQUAL 1 OR NOT out MATCHES "\"code\":\"missing_password\""
    OR NOT out MATCHES "--password is empty")
  fail("--json: expected exit 1 and missing_password, got '${rc}':\n${out}")
endif()

# Without the option the public objects are still listed (BTD-78)
run_xca(rc out --database "${db}" --list-items)
if(NOT rc EQUAL 0 OR NOT out MATCHES "option-key")
  fail("no option: expected exit 0 and the key, got '${rc}':\n${out}")
endif()

# --help says that an empty value is an error
execute_process(COMMAND "${XCA}" --no-gui --help
  OUTPUT_VARIABLE out ERROR_VARIABLE out TIMEOUT 30)
string(REGEX REPLACE "[ \t\r\n]+" " " out "${out}")
if(NOT out MATCHES "An empty value \\(--password \"\"\\) is an error")
  fail("--help does not say that an empty --password is an error:\n${out}")
endif()

file(REMOVE_RECURSE "${WORK}")
