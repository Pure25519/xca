# xca --no-gui with debug output (XCA_DEBUG=all, --verbose) never writes a
# password to the log (BTD-68): main() dumps the command line, the values of
# --password and --sqlpass are masked; env: and file: sources show their name,
# not their content.
# cmake -DXCA=<path to xca> -DWORK=<scratch dir> -P cli_debug_secrets.cmake

file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}/home")
set(ENV{HOME} "${WORK}/home")
set(ENV{XDG_CONFIG_HOME} "${WORK}/home/.config")
set(ENV{XDG_DATA_HOME} "${WORK}/home/.local/share")
set(ENV{QT_QPA_PLATFORM} offscreen)

function(fail msg)
  file(REMOVE_RECURSE "${WORK}")
  message(FATAL_ERROR "${msg}")
endfunction()

# Runs xca --no-gui <args>; fails on a non-zero exit or a secret in the output
set(secrets PwSecret-1 SqlSecret-2 EnvSecret-3 FileSecret-4)
function(run_xca label)
  execute_process(COMMAND "${XCA}" --no-gui ${ARGN}
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE out
    TIMEOUT 30)
  if(NOT rc EQUAL 0)
    fail("${label}: expected exit code 0, got '${rc}':\n${out}")
  endif()
  foreach(secret ${secrets})
    string(FIND "${out}" "${secret}" pos)
    if(NOT pos EQUAL -1)
      fail("${label}: the debug output shows '${secret}':\n${out}")
    endif()
  endforeach()
  set(out "${out}" PARENT_SCOPE)
endfunction()

set(ENV{XCA_DEBUG} all)
run_xca("pass: and plain value" --database "${WORK}/pass.xdb"
  --password pass:PwSecret-1 --sqlpass=SqlSecret-2 --list-items)
# The dump ran (the test sees the log at all) and shows the mask
if(NOT out MATCHES "wargv [0-9]+ [0-9]+ pass:\\*\\*\\*" OR
   NOT out MATCHES "--sqlpass=\\*\\*\\*")
  fail("pass: and plain value: no masked command line in the debug output:\n${out}")
endif()

set(ENV{XCA_CLI_DEBUG_PW} EnvSecret-3)
file(WRITE "${WORK}/pw.txt" "FileSecret-4\n")
run_xca("env: and file:" --database "${WORK}/env.xdb"
  --password env:XCA_CLI_DEBUG_PW --sqlpass "file:${WORK}/pw.txt" --list-items)
if(NOT out MATCHES "env:XCA_CLI_DEBUG_PW")
  fail("env: and file:: the source name is missing in the debug output:\n${out}")
endif()

unset(ENV{XCA_DEBUG})
run_xca("--verbose" --verbose --database "${WORK}/pass.xdb"
  --password=pass:PwSecret-1 --sqlpass SqlSecret-2 --list-items)

file(REMOVE_RECURSE "${WORK}")
message(STATUS "xca --no-gui: debug output masks --password and --sqlpass")
