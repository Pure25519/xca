# xca --no-gui without a password source (BTD-30): the command ends with
# an error instead of waiting for terminal input.
# cmake -DXCA=<path to xca> -DWORK=<scratch dir> -P cli_missing_password.cmake

file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}/home")
set(ENV{HOME} "${WORK}/home")
set(ENV{XDG_CONFIG_HOME} "${WORK}/home/.config")
set(ENV{XDG_DATA_HOME} "${WORK}/home/.local/share")
set(ENV{QT_QPA_PLATFORM} offscreen)

function(run_xca result output)
  execute_process(COMMAND "${XCA}" --no-gui ${ARGN}
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE out
    TIMEOUT 30)
  set(${result} "${rc}" PARENT_SCOPE)
  set(${output} "${out}" PARENT_SCOPE)
endfunction()

# A new database needs a password: no source -> error, exit code 1
run_xca(rc out --database "${WORK}/missing.xdb" --list-items)
if(NOT rc EQUAL 1)
  file(REMOVE_RECURSE "${WORK}")
  message(FATAL_ERROR "expected exit code 1, got '${rc}':\n${out}")
endif()
if(NOT out MATCHES "Password required, but no source is given")
  file(REMOVE_RECURSE "${WORK}")
  message(FATAL_ERROR "missing error message:\n${out}")
endif()

# Control: with a source the same command succeeds
run_xca(rc out --database "${WORK}/given.xdb" --password pass:cli-test --list-items)
file(REMOVE_RECURSE "${WORK}")
if(NOT rc EQUAL 0)
  message(FATAL_ERROR "with --password: expected exit code 0, got '${rc}':\n${out}")
endif()
message(STATUS "xca --no-gui: missing password fails, given password works")
