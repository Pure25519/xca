# xca --no-gui answers a question only with --yes or --confirm <id>
# (BTD-71); without them the command fails and changes nothing.
# cmake -DXCA=<path to xca> -DWORK=<scratch dir> -P cli_confirmations.cmake

file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}/home")
set(ENV{HOME} "${WORK}/home")
set(ENV{XDG_CONFIG_HOME} "${WORK}/home/.config")
set(ENV{XDG_DATA_HOME} "${WORK}/home/.local/share")
set(ENV{QT_QPA_PLATFORM} offscreen)
set(DB --database "${WORK}/confirm.xdb" --password pass:cli-test)

function(run_xca result output)
  execute_process(COMMAND "${XCA}" --no-gui ${DB} ${ARGN}
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE out
    TIMEOUT 60)
  set(${result} "${rc}" PARENT_SCOPE)
  set(${output} "${out}" PARENT_SCOPE)
endfunction()

function(fail msg)
  file(REMOVE_RECURSE "${WORK}")
  message(FATAL_ERROR "${msg}")
endfunction()

# The keys in the database
function(key_names result)
  run_xca(rc out --list-items)
  if(NOT rc EQUAL 0)
    fail("--list-items: exit code '${rc}':\n${out}")
  endif()
  string(REGEX MATCHALL "Asymmetric Key +[^\n]+" keys "${out}")
  set(${result} "${keys}" PARENT_SCOPE)
endfunction()

# An RSA key below 1024 bit asks the question "key.size"
foreach(answer "" "--confirm;item.delete")
  run_xca(rc out ${answer} --keygen RSA:768 --name refused)
  if(NOT rc EQUAL 1)
    fail("'${answer}': expected exit code 1, got '${rc}':\n${out}")
  endif()
  if(NOT out MATCHES "The question 'key.size' was not confirmed")
    fail("'${answer}': missing error message:\n${out}")
  endif()
endforeach()
key_names(keys)
if(NOT keys STREQUAL "")
  fail("an unconfirmed question generated keys: ${keys}")
endif()

foreach(answer "--yes" "--confirm;key.size")
  string(REPLACE ";" "-" name "confirmed${answer}")
  run_xca(rc out ${answer} --keygen RSA:768 --name ${name})
  if(NOT rc EQUAL 0)
    fail("'${answer}': expected exit code 0, got '${rc}':\n${out}")
  endif()
  if(NOT out MATCHES "\\[key\\.size\\][^\n]* yes \\(--")
    fail("'${answer}': the answer is not shown:\n${out}")
  endif()
endforeach()
key_names(keys)
if(NOT keys MATCHES "confirmed--yes" OR
   NOT keys MATCHES "confirmed--confirm-key.size")
  fail("confirmed keys missing: ${keys}")
endif()

# The audit log names the question of every refusal and confirmation
run_xca(rc out --audit-export -)
file(REMOVE_RECURSE "${WORK}")
string(REGEX MATCHALL "\"question\":\"key\\.size\"[^\n]*\"result\":\"denied\""
  denied "${out}")
list(LENGTH denied n)
if(NOT n EQUAL 2)
  message(FATAL_ERROR "expected 2 denied entries, got ${n}:\n${out}")
endif()
if(NOT out MATCHES "\"confirmed\":\"key\\.size:--yes\"" OR
   NOT out MATCHES "\"confirmed\":\"key\\.size:--confirm\"")
  message(FATAL_ERROR "confirmations missing in the audit log:\n${out}")
endif()
message(STATUS "xca --no-gui: unconfirmed question fails, --yes and --confirm proceed")
