# xca --no-gui checks a given database password on open (BTD-78):
# the right one works, a wrong one ends the command with exit code 1
# before anything is listed, no password still lists the public objects.
# cmake -DXCA=<path to xca> -DWORK=<scratch dir> -P cli_password_verify.cmake

file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}/home")
set(ENV{HOME} "${WORK}/home")
set(ENV{XDG_CONFIG_HOME} "${WORK}/home/.config")
set(ENV{XDG_DATA_HOME} "${WORK}/home/.local/share")
set(ENV{QT_QPA_PLATFORM} offscreen)
set(DB --database "${WORK}/verify.xdb")

function(run_xca result output)
  execute_process(COMMAND "${XCA}" --no-gui ${DB} ${ARGN}
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE out
    TIMEOUT 30)
  set(${result} "${rc}" PARENT_SCOPE)
  set(${output} "${out}" PARENT_SCOPE)
endfunction()

# run_xca with --password <source>: stdin reads WORK/<name>.txt on
# standard input, fd:3 the same file on file descriptor 3
function(run_source result output source name)
  set(args ${DB} --password "${source}" ${ARGN})
  if(source STREQUAL "stdin")
    execute_process(COMMAND "${XCA}" --no-gui ${args}
      INPUT_FILE "${WORK}/${name}.txt"
      RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE out TIMEOUT 30)
  elseif(source STREQUAL "fd:3")
    execute_process(COMMAND sh -c "exec \"$0\" \"$@\" 3<\"${WORK}/${name}.txt\""
        "${XCA}" --no-gui ${args}
      RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE out TIMEOUT 30)
  else()
    run_xca(rc out --password "${source}" ${ARGN})
  endif()
  set(${result} "${rc}" PARENT_SCOPE)
  set(${output} "${out}" PARENT_SCOPE)
endfunction()

function(fail msg)
  file(REMOVE_RECURSE "${WORK}")
  message(FATAL_ERROR "${msg}")
endfunction()

run_xca(rc out --password pass:right-pw --keygen EC:prime256v1 --name verify-key)
if(NOT rc EQUAL 0)
  fail("creating the database: exit '${rc}':\n${out}")
endif()

file(WRITE "${WORK}/right.txt" "right-pw\n")
file(WRITE "${WORK}/wrong.txt" "WRONG-pw\n")
set(ENV{XCA_VERIFY_RIGHT} "right-pw")
set(ENV{XCA_VERIFY_WRONG} "WRONG-pw")

# Right password from every kind of source: listed (file:, fd: and
# stdin since BTD-117)
foreach(source "pass:right-pw" "env:XCA_VERIFY_RIGHT"
               "file:${WORK}/right.txt" "stdin" "fd:3")
  run_source(rc out "${source}" right --list-items)
  if(NOT rc EQUAL 0 OR NOT out MATCHES "verify-key")
    fail("right password from ${source}: expected exit 0 and the key, got '${rc}':\n${out}")
  endif()
endforeach()

# Wrong password: rejected on open, nothing listed, password not shown
foreach(source "pass:WRONG-pw" "env:XCA_VERIFY_WRONG"
               "file:${WORK}/wrong.txt" "stdin" "fd:3")
  run_source(rc out "${source}" wrong --list-items)
  if(NOT rc EQUAL 1)
    fail("${source}: expected exit code 1, got '${rc}':\n${out}")
  endif()
  if(NOT out MATCHES "was not accepted: Please enter the password for unlocking the database")
    fail("${source}: missing error message:\n${out}")
  endif()
  if(out MATCHES "verify-key" OR out MATCHES "WRONG-pw")
    fail("${source}: listed items or showed the password:\n${out}")
  endif()
endforeach()

# No password source: the public objects are listed as upstream allows
run_xca(rc out --list-items)
if(NOT rc EQUAL 0 OR NOT out MATCHES "verify-key")
  fail("no password: expected exit 0 and the key, got '${rc}':\n${out}")
endif()

# --help explains the empty --password (BTD-117)
execute_process(COMMAND "${XCA}" --no-gui --help
  OUTPUT_VARIABLE out ERROR_VARIABLE out TIMEOUT 30)
string(REGEX REPLACE "[ \t\r\n]+" " " out "${out}")
if(NOT out MATCHES "An empty value \\(--password \"\"\\) counts as no option")
  fail("--help does not explain the empty --password:\n${out}")
endif()

# The audit context says whether the password was checked: the key was
# generated with a checked password, the attempt without one was not
run_xca(rc out --keygen EC:prime256v1 --name unchecked-key)
run_xca(rc out --audit-export -)
file(REMOVE_RECURSE "${WORK}")
if(NOT out MATCHES "\"db_unlock_verified\":true[^\n]*\"name\":\"verify-key\"")
  message(FATAL_ERROR "checked password missing in the audit log:\n${out}")
endif()
if(NOT out MATCHES "\"db_unlock_verified\":false[^\n]*\"name\":\"unchecked-key\"")
  message(FATAL_ERROR "unchecked open missing in the audit log:\n${out}")
endif()
message(STATUS "xca --no-gui: right password lists, wrong password fails on open, none lists")
