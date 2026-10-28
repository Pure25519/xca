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

function(fail msg)
  file(REMOVE_RECURSE "${WORK}")
  message(FATAL_ERROR "${msg}")
endfunction()

run_xca(rc out --password pass:right-pw --keygen EC:prime256v1 --name verify-key)
if(NOT rc EQUAL 0)
  fail("creating the database: exit '${rc}':\n${out}")
endif()

# Right password: listed
run_xca(rc out --password pass:right-pw --list-items)
if(NOT rc EQUAL 0 OR NOT out MATCHES "verify-key")
  fail("right password: expected exit 0 and the key, got '${rc}':\n${out}")
endif()

# Wrong password: rejected on open, nothing listed, password not shown
foreach(source "pass:WRONG-pw" "env:XCA_VERIFY_WRONG")
  set(ENV{XCA_VERIFY_WRONG} "WRONG-pw")
  run_xca(rc out --password ${source} --list-items)
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
