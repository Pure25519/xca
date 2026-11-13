# A missing password names its purpose and only an option that serves it
# (BTD-196): xca --password gives the database and key passwords, nothing
# gives an import password. Without a terminal on stdin (BTD-145) and
# without --interactive the error says how to give the secret: the option
# of that purpose, or that no option gives it.
# cmake -DXCA=<path to xca> -DOPENSSL=<openssl> -DWORK=<scratch dir>
#   -P cli_password_purpose_hint.cmake

file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}/home")
set(ENV{HOME} "${WORK}/home")
set(ENV{XDG_CONFIG_HOME} "${WORK}/home/.config")
set(ENV{XDG_DATA_HOME} "${WORK}/home/.local/share")
set(ENV{QT_QPA_PLATFORM} offscreen)
# stdin is a regular file, never a terminal
file(WRITE "${WORK}/stdin.txt" "")

function(fail msg)
  file(REMOVE_RECURSE "${WORK}")
  message(FATAL_ERROR "${msg}")
endfunction()

function(run_xca label)
  execute_process(COMMAND "${XCA}" --no-gui ${ARGN}
    INPUT_FILE "${WORK}/stdin.txt" WORKING_DIRECTORY "${WORK}"
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE out
    TIMEOUT 30)
  if(rc EQUAL 0)
    fail("${label}: expected an error, got exit 0:\n${out}")
  endif()
  set(out "${out}" PARENT_SCOPE)
endfunction()

# expect(<label> <text> <must match> <must not match>)
function(expect label text want unwanted)
  if(NOT text MATCHES "${want}")
    fail("${label}: the error does not match '${want}':\n${text}")
  endif()
  if(unwanted AND text MATCHES "${unwanted}")
    fail("${label}: the error names '${unwanted}', which does not serve it:\n${text}")
  endif()
endfunction()

# Database password: --password serves it, also without --interactive
run_xca("database" --database "${WORK}/new.xdb" --list-items)
expect("database" "${out}" "Give it with --password \\(pass:" "--sqlpass")
run_xca("database, interactive" --interactive --database "${WORK}/new.xdb"
  --list-items)
expect("database, interactive" "${out}" "Give it with --password \\(pass:"
  "--sqlpass")

# Import password of an encrypted key: no option of xca gives it
execute_process(COMMAND "${OPENSSL}" genpkey -algorithm EC
    -pkeyopt ec_paramgen_curve:P-256 -out "${WORK}/k.pem"
  RESULT_VARIABLE r1 ERROR_VARIABLE e1)
execute_process(COMMAND "${OPENSSL}" pkcs8 -topk8 -v2 aes-256-cbc
    -in "${WORK}/k.pem" -out "${WORK}/enc.pem" -passout pass:import-secret
  RESULT_VARIABLE r2 ERROR_VARIABLE e2)
if(NOT r1 EQUAL 0 OR NOT r2 EQUAL 0)
  fail("openssl could not write the encrypted key: ${e1}${e2}")
endif()
run_xca("import" --database "${WORK}/db.xdb" --password pass:db-secret
  --import "${WORK}/enc.pem")
expect("import" "${out}" "No option of this program gives it" "--password")
run_xca("import, interactive" --interactive --database "${WORK}/db.xdb"
  --password pass:db-secret --import "${WORK}/enc.pem")
expect("import, interactive" "${out}" "No option of this program gives it"
  "--password")

file(REMOVE_RECURSE "${WORK}")
message(STATUS "missing passwords name their purpose and the option that serves it")
