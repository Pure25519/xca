# Parallel writers on one database (BTD-274): two processes at a time
# generate keys (xca --keygen) and create requests with new keys (bxc-pki
# request-cert). Every outermost write transaction takes the write lock
# at BEGIN, so the second process waits for the first instead of failing
# with "database is locked" after its reads; both succeed one after the
# other. The audit log has no sequence number twice and verifies.

include("${LIB}")

bxc("root" 0 init --db "${DB}" ${PW} --cn "Parallel Root" --key ec-p256)

# parallel(<label> <command a> <command b>): both shell commands at once;
# sets a_rc, b_rc, a_err, b_err
function(parallel label cmd_a cmd_b)
  set(run "")
  foreach(side a b)
    string(APPEND run "${cmd_${side}} </dev/null >'${WORK}/${side}.out' 2>'${WORK}/${side}.err' & p${side}=$!; ")
  endforeach()
  string(APPEND run "wait $pa; echo a=$?; wait $pb; echo b=$?")
  execute_process(COMMAND sh -c "${run}" WORKING_DIRECTORY "${WORK}"
    OUTPUT_VARIABLE codes ERROR_VARIABLE e TIMEOUT ${T120})
  foreach(side a b)
    file(READ "${WORK}/${side}.err" err_text)
    string(REGEX MATCH "${side}=([0-9]+)" m "${codes}")
    file(APPEND "${TRANSCRIPT}"
      "### ${label} ${side} (parallel)\n$ ${cmd_${side}}\nexit ${CMAKE_MATCH_1}\n--- stderr\n${err_text}\n")
    set(${side}_rc "${CMAKE_MATCH_1}" PARENT_SCOPE)
    set(${side}_err "${err_text}" PARENT_SCOPE)
  endforeach()
endfunction()

# both_ok(<label>): both processes exited 0, and no "Audit entry lost"
macro(both_ok label)
  if(NOT a_rc STREQUAL "0" OR NOT b_rc STREQUAL "0")
    fail("${label}: expected both to succeed, got exit codes '${a_rc}' and '${b_rc}':\n${a_err}\n${b_err}")
  endif()
  if("${a_err}${b_err}" MATCHES "Audit entry lost")
    fail("${label}: an audit entry was lost:\n${a_err}\n${b_err}")
  endif()
endmacro()

set(xca_db "--database '${DB}' --password env:BXC_DB_PW")
foreach(round 1 2 3)
  parallel("round ${round} keygen"
    "'${XCA}' --no-gui ${xca_db} --keygen EC:prime256v1 --name key-a-${round}"
    "'${XCA}' --no-gui ${xca_db} --keygen EC:prime256v1 --name key-b-${round}")
  both_ok("round ${round} keygen")
  parallel("round ${round} request-cert"
    "'${BXC_PKI}' request-cert --db '${DB}' --password env:BXC_DB_PW --cn req-a-${round} --key ec-p256"
    "'${BXC_PKI}' request-cert --db '${DB}' --password env:BXC_DB_PW --cn req-b-${round} --key ec-p256")
  both_ok("round ${round} request-cert")
  message(STATUS "round ${round}: both keygens and both requests stored")
endforeach()

sql("keys" "SELECT COUNT(*) FROM items WHERE del=0 AND (name LIKE 'key-%' OR name LIKE 'req-%') AND id IN (SELECT item FROM private_keys)")
if(NOT out MATCHES "^12")
  fail("expected 12 keys (6 keygen, 6 request keys), got '${out}'")
endif()
sql("audit seq" "SELECT COUNT(*) FROM (SELECT seq FROM audit_log GROUP BY seq HAVING COUNT(*) > 1)")
if(NOT out MATCHES "^0")
  fail("audit log: '${out}' sequence numbers used twice")
endif()
xca_run("audit verify" 0 --database "${DB}" ${PW} --audit-verify)
if(NOT out MATCHES "\"chain_ok\":true")
  fail("audit verify: the chain is broken:\n${out}")
endif()
