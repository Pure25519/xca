# The challengePassword of a request never leaves it in clear text
# (BTD-168): --print and --text show a marker, --list-items and the debug
# output do not name it, and with --json the options that write plain
# text are refused with the error object "usage".
# cmake -DXCA=<xca> -DDATA=<test/service/data> -DWORK=<scratch dir>
#       -P cli_challenge_password.cmake

cmake_minimum_required(VERSION 3.19)   # string(JSON)

# the fixtures of the JSON tests (BTD-256: DATA is the common data directory)
set(DATA "${DATA}/json")
file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}/home")
set(ENV{HOME} "${WORK}/home")
set(ENV{XDG_CONFIG_HOME} "${WORK}/home/.config")
set(ENV{XDG_DATA_HOME} "${WORK}/home/.local/share")
set(ENV{QT_QPA_PLATFORM} offscreen)

# the challengePassword of data/json/device.csr (gen.sh)
set(SECRET "Chall-Secret-42")
set(MARKER "present, not shown")
set(DB_PW "Cli-Chall-Db-3")
set(db --database "${WORK}/chall.xdb")
set(pw --password "pass:${DB_PW}")
set(csr "${DATA}/device.csr")

function(fail msg)
  file(REMOVE_RECURSE "${WORK}")
  message(FATAL_ERROR "${msg}")
endfunction()

# run(<label> <expected exit code> <args>...): xca --no-gui; stdout in
# ${out}, stderr in ${err}; both are kept for the secret check at the end
set(ALL "")
function(run label code)
  execute_process(COMMAND "${XCA}" --no-gui ${ARGN}
    WORKING_DIRECTORY "${WORK}"
    RESULT_VARIABLE rc OUTPUT_VARIABLE o ERROR_VARIABLE e TIMEOUT 30)
  if(NOT rc EQUAL code)
    fail("${label}: expected exit code ${code}, got '${rc}':\n${o}\n${e}")
  endif()
  string(FIND "${o}\n${e}" "${SECRET}" pos)
  if(NOT pos EQUAL -1)
    fail("${label}: the challengePassword is in the output:\n${o}\n${e}")
  endif()
  set(out "${o}" PARENT_SCOPE)
  set(err "${e}" PARENT_SCOPE)
  set(ALL "${ALL}\n${o}\n${e}" PARENT_SCOPE)
endfunction()

function(has_marker label text)
  string(FIND "${text}" "${MARKER}" pos)
  if(pos EQUAL -1)
    fail("${label}: no marker '${MARKER}':\n${text}")
  endif()
endfunction()

# --print and --text of the file: the marker, the other attribute as before
run("print" 0 --print "${csr}")
has_marker("print" "${out}")
run("text" 0 --text "${csr}")
has_marker("text" "${out}")
if(NOT out MATCHES "Subject: ")
  fail("text: the OpenSSL text lost the request fields:\n${out}")
endif()
run("print, debug output" 0 --verbose --print "${csr}")

# stored in a database: --list-items and --print of the item
run("import" 0 ${db} ${pw} --import "${csr}")
run("list" 0 ${db} ${pw} --list-items)
run("print stored" 0 ${db} ${pw} --print --select 1)
has_marker("print stored" "${out}")
run("json print" 0 ${db} ${pw} --json --print --select 1)

# with --json only JSON on stdout: the plain text options are refused
foreach(opt --text --pem --list-curves --help --version)
  run("json ${opt}" 1 ${db} ${pw} --json --print --select 1 ${opt})
  if(NOT out STREQUAL "")
    fail("json ${opt}: stdout is not empty:\n${out}")
  endif()
  string(JSON code ERROR_VARIABLE jerr GET "${err}" code)
  if(jerr OR NOT code STREQUAL "usage")
    fail("json ${opt}: no error object 'usage' on stderr:\n${err}")
  endif()
endforeach()

file(REMOVE_RECURSE "${WORK}")
message(STATUS "challengePassword: marker only, --json refuses plain text")
