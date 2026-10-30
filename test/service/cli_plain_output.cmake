# xca --no-gui writes plain text when the output is not a terminal and no
# false QCommandLineParser warning (BTD-21): ANSI colours only on a terminal
# and without NO_COLOR; options without value (--no-gui, --pem, --version, ...)
# do not trigger "option not expecting values".
# cmake -DXCA=<path to xca> -DWORK=<scratch dir> -P cli_plain_output.cmake

file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}/home")
set(ENV{HOME} "${WORK}/home")
set(ENV{XDG_CONFIG_HOME} "${WORK}/home/.config")
set(ENV{XDG_DATA_HOME} "${WORK}/home/.local/share")
set(ENV{QT_QPA_PLATFORM} offscreen)
unset(ENV{NO_COLOR})
string(ASCII 27 esc)

function(fail msg)
  file(REMOVE_RECURSE "${WORK}")
  message(FATAL_ERROR "${msg}")
endfunction()

# plain(<label> <args>...): runs xca --no-gui with stdout and stderr to a
# pipe; fails on an escape character or a parser warning in either
set(db --database "${WORK}/plain.xdb" --password pass:plain-test)
function(plain label)
  execute_process(COMMAND "${XCA}" --no-gui ${ARGN}
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err
    TIMEOUT 30)
  foreach(stream out err)
    string(FIND "${${stream}}" "${esc}" pos)
    if(NOT pos EQUAL -1)
      fail("${label}: escape sequence in std${stream}:\n${${stream}}")
    endif()
    if("${${stream}}" MATCHES "QCommandLineParser|not expecting values")
      fail("${label}: parser warning in std${stream}:\n${${stream}}")
    endif()
  endforeach()
  set(out "${out}" PARENT_SCOPE)
  set(err "${err}" PARENT_SCOPE)
endfunction()

plain("--version --list-curves --help" --version --list-curves --help)
if(NOT out MATCHES "prime256v1")
  fail("--list-curves printed no curves:\n${out}")
endif()
plain("--keygen" ${db} --keygen EC:prime256v1 --name plain-key)
plain("--list-items" ${db} --list-items)
plain("--print and --pem" ${db} --select 1 --print --pem)
if(NOT out MATCHES "BEGIN PUBLIC KEY" OR NOT out MATCHES "plain-key")
  fail("--print and --pem: key missing in the output:\n${out}")
endif()
plain("error message" ${db} --crlgen no-such-ca)
# messages go to stderr, stdout carries only results (BTD-41)
if(NOT err MATCHES "Issuer 'no-such-ca' not found" OR NOT out STREQUAL "")
  fail("error message: missing on stderr or not only there:\n${out}\n${err}")
endif()
set(ENV{XCA_DEBUG} all)
plain("debug output" --version)
unset(ENV{XCA_DEBUG})

# On a terminal the colours stay, unless NO_COLOR is set (needs script(1))
find_program(SCRIPT script)
if(SCRIPT)
  set(cmd "'${XCA}' --no-gui --list-curves")
  execute_process(COMMAND "${SCRIPT}" -qec "${cmd}" /dev/null
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE out TIMEOUT 30)
  string(FIND "${out}" "${esc}[" pos)
  if(NOT rc EQUAL 0 OR pos EQUAL -1)
    fail("terminal: expected coloured output, got '${rc}':\n${out}")
  endif()
  set(ENV{NO_COLOR} 1)
  execute_process(COMMAND "${SCRIPT}" -qec "${cmd}" /dev/null
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE out TIMEOUT 30)
  unset(ENV{NO_COLOR})
  string(FIND "${out}" "${esc}" pos)
  if(NOT rc EQUAL 0 OR NOT pos EQUAL -1)
    fail("terminal with NO_COLOR: expected plain output, got '${rc}':\n${out}")
  endif()
else()
  message(STATUS "script(1) not found: terminal colours not checked")
endif()

file(REMOVE_RECURSE "${WORK}")
message(STATUS "xca --no-gui: plain output off a terminal, no parser warning")
