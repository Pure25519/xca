# xca --no-gui answers every database password request from --password
# (BTD-30): importing two keys into an existing database encrypts each with
# the database password, so the source is used twice in one run.
# cmake -DXCA=<xca> -DOPENSSL=<openssl> -DWORK=<scratch dir> -P cli_password_sources.cmake

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

function(run_xca result output)
  execute_process(COMMAND "${XCA}" --no-gui ${ARGN}
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE out
    TIMEOUT 30)
  set(${result} "${rc}" PARENT_SCOPE)
  set(${output} "${out}" PARENT_SCOPE)
endfunction()

foreach(k k1 k2 k3)
  execute_process(COMMAND "${OPENSSL}" genpkey -algorithm EC
      -pkeyopt ec_paramgen_curve:P-256 -out "${WORK}/${k}.pem"
    RESULT_VARIABLE rc OUTPUT_QUIET ERROR_VARIABLE err)
  if(NOT rc EQUAL 0)
    fail("openssl genpkey failed: ${err}")
  endif()
endforeach()

set(ENV{XCA_CLI_TEST_PW} "cli-env-pass")
file(WRITE "${WORK}/pw.txt" "cli-file-pass\n")

foreach(source "env:XCA_CLI_TEST_PW" "file:${WORK}/pw.txt")
  string(REGEX REPLACE ":.*" "" kind "${source}")
  set(db "${WORK}/${kind}.xdb")

  run_xca(rc out --database "${db}" --password "${source}" --list-items)
  if(NOT rc EQUAL 0)
    fail("${kind}: creating the database: exit '${rc}':\n${out}")
  endif()
  run_xca(rc out --database "${db}" --password "${source}" --import
    "${WORK}/k1.pem" "${WORK}/k2.pem")
  if(NOT rc EQUAL 0)
    fail("${kind}: importing two keys: exit '${rc}':\n${out}")
  endif()
  run_xca(rc out --database "${db}" --list-items)
  string(REGEX MATCHALL "k[12]" names "${out}")
  list(LENGTH names n)
  if(NOT rc EQUAL 0 OR NOT n EQUAL 2)
    fail("${kind}: expected the keys k1 and k2 in the database:\n${out}")
  endif()
endforeach()

# A wrong password is rejected after one try, not asked again
run_xca(rc out --database "${WORK}/env.xdb" --password pass:never-shown-pw
  --import "${WORK}/k3.pem")
if(NOT rc EQUAL 1 OR NOT out MATCHES "was not accepted")
  fail("wrong password: expected exit 1 and 'was not accepted', got '${rc}':\n${out}")
endif()
string(FIND "${out}" "never-shown-pw" pos)
if(NOT pos EQUAL -1)
  fail("the message shows the password:\n${out}")
endif()

# No password: the import ends instead of prompting
run_xca(rc out --database "${WORK}/env.xdb" --import "${WORK}/k3.pem")
if(NOT rc EQUAL 1 OR NOT out MATCHES "no source is given")
  fail("no password: expected exit 1 and 'no source is given', got '${rc}':\n${out}")
endif()

file(REMOVE_RECURSE "${WORK}")
message(STATUS "xca --no-gui: --password from env: and file: serves two keys")
