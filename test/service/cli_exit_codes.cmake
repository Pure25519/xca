# xca --no-gui exits non-zero when a command fails (BTD-69): an exception
# ends the command in main(), a failure reported inside read_cmdline() sets
# the exit code and the remaining options still run. Successful commands
# exit 0, the audit options keep their exit codes from BTD-29.
# cmake -DXCA=<xca> [-DOPENSSL=<openssl>] -DWORK=<scratch dir> -P cli_exit_codes.cmake

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

# expect(<exit code> <label> <args>...): runs xca --no-gui on the test
# database and checks the exit code; the output is left in ${out}
set(db --database "${WORK}/exit.xdb" --password pass:exit-test)
function(expect code label)
  execute_process(COMMAND "${XCA}" --no-gui ${db} ${ARGN}
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE out
    TIMEOUT 30)
  if(NOT rc EQUAL code)
    fail("${label}: expected exit code ${code}, got '${rc}':\n${out}")
  endif()
  set(out "${out}" PARENT_SCOPE)
endfunction()

set(missing "${WORK}/no-such-dir")

expect(0 "new key" --keygen EC:prime256v1 --name exit-key)
expect(1 "unknown key type" --keygen FOO:1)
expect(1 "unknown CA for --crlgen" --crlgen no-such-ca)
if(NOT out MATCHES "Issuer 'no-such-ca' not found")
  fail("unknown CA for --crlgen: missing error message:\n${out}")
endif()
# The failure does not stop the other options
expect(1 "unknown CA with --list-items" --crlgen no-such-ca --list-items)
if(NOT out MATCHES "exit-key")
  fail("unknown CA with --list-items: the item list is missing:\n${out}")
endif()
expect(1 "index write error" --index "${missing}/index.txt")
expect(1 "PEM write error" --select 1 --pem-file "${missing}/key.pem")
expect(0 "index" --index "${WORK}/index.txt")

# Audit options (BTD-29) unchanged
expect(0 "audit verify" --audit-verify)
expect(0 "audit export" --audit-export "${WORK}/audit.jsonl")
expect(1 "audit export write error" --audit-export "${missing}/audit.jsonl")

# --crlgen with a known CA succeeds (needs openssl for the CA)
if(OPENSSL AND EXISTS "${OPENSSL}")
  execute_process(COMMAND "${OPENSSL}" req -x509 -newkey EC
      -pkeyopt ec_paramgen_curve:P-256 -noenc -subj "/CN=Exit Test CA"
      -addext basicConstraints=critical,CA:TRUE
      -keyout "${WORK}/ca.key" -out "${WORK}/ca.crt"
    RESULT_VARIABLE rc OUTPUT_QUIET ERROR_VARIABLE err)
  if(NOT rc EQUAL 0)
    fail("openssl req failed: ${err}")
  endif()
  # --import-names names the items in command line order
  expect(0 "CA import" --import "${WORK}/ca.crt" "${WORK}/ca.key"
    --import-names exit-ca)
  expect(0 "known CA for --crlgen" --crlgen exit-ca)
else()
  message(STATUS "openssl not given: --crlgen with a known CA not checked")
endif()

file(REMOVE_RECURSE "${WORK}")
message(STATUS "xca --no-gui: failing commands exit 1, successful ones 0")
