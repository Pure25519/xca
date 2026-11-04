# Uniqueness under parallel issuance (BTD-201): two bxc-pki processes
# sign a request with the same subject at the same time, under a CA whose
# assigned policy allows one valid certificate per subject DN. Each
# process has loaded the database before the other stored its
# certificate, so the check must read the database under the write lock,
# not its own store. In every round exactly one process succeeds, the
# other exits 1 with policy_not_unique, and the database holds one
# certificate of the subject. The requests are created beforehand: only
# the issuance runs in parallel.

include("${LIB}")

bxc("root" 0 init --db "${DB}" ${PW} --cn "Unique Root" --key ec-p256)
sql("root id" "SELECT c.item FROM certs c JOIN items i ON i.id=c.item WHERE i.name='Unique Root'")
string(STRIP "${out}" root_id)

# a policy with a uniqueness rule only, assigned to the root
set(policy "{\"schema\":\"urn:bxc-pki:schema:policy:v1\",\"id\":\"unique-dn\",\"description\":\"One valid certificate per subject DN for each issuing CA.\",\"uniqueness\":{\"fields\":[\"subject_dn\"],\"scope\":\"issuer\",\"status\":[\"valid\"]}}")
sql("policy" "INSERT INTO policies (name, version, document, created, retired) VALUES ('unique-dn', 1, '${policy}', '2026-11-04T00:00:00Z', 0)")
sql("assignment" "INSERT INTO assignments (owner_type, owner, kind, name) VALUES ('ca', '${root_id}', 'policy', 'unique-dn')")

foreach(round 1 2 3)
  set(cn "Parallel Sub ${round}")
  foreach(side a b)
    bxc("round ${round} request ${side}" 0 request-cert --db "${DB}" ${PW}
        --cn "${cn}" --name "req-${side}-${round}" --key ec-p256)
  endforeach()
  # both processes started at once by one shell, each with its own files
  set(run "")
  foreach(side a b)
    string(APPEND run "'${BXC_PKI}' sign 'req-${side}-${round}' --db '${DB}' --password env:BXC_DB_PW --ca 'Unique Root' </dev/null >'${WORK}/${side}.out' 2>'${WORK}/${side}.err' & p${side}=$!; ")
  endforeach()
  string(APPEND run "wait $pa; echo a=$?; wait $pb; echo b=$?")
  execute_process(COMMAND sh -c "${run}" WORKING_DIRECTORY "${WORK}"
    RESULT_VARIABLE r OUTPUT_VARIABLE codes ERROR_VARIABLE e
    TIMEOUT ${T120})
  set(refused "")
  foreach(side a b)
    file(READ "${WORK}/${side}.err" ${side}_err)
    string(REGEX MATCH "${side}=([0-9]+)" m "${codes}")
    set(${side}_rc "${CMAKE_MATCH_1}")
    file(APPEND "${TRANSCRIPT}"
      "### round ${round}: sign req-${side}-${round} (parallel)\nexit ${${side}_rc}\n--- stderr\n${${side}_err}\n")
    if(${side}_rc STREQUAL "1")
      set(refused "${${side}_err}")
    endif()
  endforeach()
  set(got "${a_rc};${b_rc}")
  list(SORT got)
  if(NOT got STREQUAL "0;1")
    fail("round ${round}: expected one success and one failure, got exit codes '${a_rc}' and '${b_rc}'")
  endif()
  if(NOT refused MATCHES "\"code\":\"policy_not_unique\"")
    fail("round ${round}: the refused issuance is not policy_not_unique: ${refused}")
  endif()
  sql("round ${round} count" "SELECT COUNT(*) FROM certs c JOIN items i ON i.id=c.item WHERE i.del=0 AND c.issuer=${root_id} AND i.name LIKE 'req-%-${round}'")
  if(NOT out MATCHES "^1")
    fail("round ${round}: expected one certificate of '${cn}', got '${out}'")
  endif()
  message(STATUS "round ${round}: one certificate, the other refused")
endforeach()
