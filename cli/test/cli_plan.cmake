# --plan of bxc-pki (BTD-41, review of xca#54): nothing is generated,
# signed or stored; the result lists the objects that would be written
# with id and document null (no PEM, serial, signature or fingerprint);
# one audit entry cli.plan records the run, also a failed one, after the
# failure entries of service calls; only init without --plan creates a
# database.

include("${LIB}")

# no_signed_output(<label>): stdout of a plan run carries nothing signed
function(no_signed_output label)
  foreach(bad "BEGIN" "\"pem\"" "\"serial\"" "fingerprint" "signature")
    string(FIND "${out}" "${bad}" pos)
    if(NOT pos EQUAL -1)
      fail("${label}: --plan printed ${bad}:\n${out}")
    endif()
  endforeach()
endfunction()

# plan_objects(<label> <expected type:name list>): every object of the
# plan result has id null and document null
function(plan_objects label expected)
  one_doc("${label}" "${out}" cli-result r)
  string(JSON p GET "${r}" plan)
  if(NOT p)
    fail("${label}: plan is '${p}'")
  endif()
  result_objects("${r}" objs)
  if(NOT objs STREQUAL "${expected}")
    fail("${label}: planned '${objs}', expected '${expected}'")
  endif()
  string(JSON n LENGTH "${r}" objects)
  math(EXPR last "${n} - 1")
  foreach(i RANGE ${last})
    string(JSON t1 TYPE "${r}" objects ${i} id)
    string(JSON t2 TYPE "${r}" objects ${i} document)
    if(NOT t1 STREQUAL "NULL" OR NOT t2 STREQUAL "NULL")
      fail("${label}: object ${i} has id ${t1}, document ${t2}")
    endif()
  endforeach()
  no_signed_output("${label}")
  set(plan_doc "${r}" PARENT_SCOPE)
endfunction()

# last_plan_entry(<var>): the last cli.plan audit entry
function(last_plan_entry var)
  audit_entries(lines)
  split_lines("${lines}" all)
  set(found "")
  foreach(l IN LISTS all)
    if(l MATCHES "\"action\":\"cli\\.plan\"")
      set(found "${l}")
    endif()
  endforeach()
  if(found STREQUAL "")
    fail("no cli.plan audit entry:\n${lines}")
  endif()
  set(${var} "${found}" PARENT_SCOPE)
  set(${var}_all "${lines}" PARENT_SCOPE)
endfunction()

# --- only init without --plan creates a database --------------------------
foreach(cmd "init;--cn;x;--plan" "request-cert;--cn;x" "sign;x;--ca;y" "list"
    "show;1")
  bxc("no database: ${cmd}" 1 ${cmd} --db "${DB}" ${PW})
  expect_error("no database: ${cmd}" no_database)
endforeach()
if(EXISTS "${DB}")
  fail("a command other than init created the database")
endif()

bxc("root" 0 init --db "${DB}" ${PW} --cn "Plan Root")
bxc("leaf CA" 0 init --db "${DB}" ${PW} --cn "Leaf CA" --parent "Plan Root"
    --path-len 0)
bxc("request" 0 request-cert --db "${DB}" ${PW} --cn dev --name dev)
audit_entries(before)
split_lines("${before}" before)
list(LENGTH before entries_before)

# --- sign --plan: the certificate would be issued, nothing signed --------
bxc("sign plan" 0 sign dev --db "${DB}" ${PW} --ca "Plan Root" --plan
    --validity P30D)
plan_objects("sign plan" "certificate:dev")
string(JSON capped GET "${plan_doc}" objects 0 validity_capped)
if(capped)
  fail("sign plan: validity_capped '${capped}'")
endif()
last_plan_entry(e)
string(JSON res GET "${e}" result)
string(JSON cmd GET "${e}" params command)
string(JSON planned GET "${e}" params planned)
string(JSON count GET "${e}" params count)
string(JSON ch GET "${e}" channel)
if(NOT res STREQUAL "success" OR NOT cmd STREQUAL "sign" OR
   NOT planned STREQUAL "certificate:dev" OR NOT count EQUAL 1 OR
   NOT ch STREQUAL "cli")
  fail("sign plan audit entry: ${e}")
endif()

# a capped plan reports the cap
bxc("sign plan capped" 0 sign dev --db "${DB}" ${PW} --ca "Leaf CA" --plan
    --validity P100Y)
plan_objects("sign plan capped" "certificate:dev")
string(JSON capped GET "${plan_doc}" objects 0 validity_capped)
string(JSON rq GET "${plan_doc}" objects 0 requested_not_after)
if(NOT capped OR NOT rq MATCHES "^2[0-9][0-9][0-9]-")
  fail("capped plan: ${capped} ${rq}")
endif()

# --- init --parent --plan and request-cert --plan --------------------------
bxc("init plan" 0 init --db "${DB}" ${PW} --cn "Planned Sub" --parent "Plan Root"
    --plan)
# rule 7 (BTD-42): init also plans the empty CRL of the new CA
plan_objects("init plan" "key:Planned Sub;certificate:Planned Sub;crl:Planned Sub")
bxc("request plan" 0 request-cert --db "${DB}" ${PW} --cn planned-dev
    --dns planned-dev.lab --plan)
plan_objects("request plan" "key:planned-dev;request:planned-dev")
bxc("text plan" 0 init --db "${DB}" ${PW} --cn "Text Plan" --plan --text)
if(NOT out MATCHES "^would write key - 'Text Plan'\nwould write certificate - 'Text Plan'\nwould write crl - 'Text Plan'\n$")
  fail("--plan --text: ${out}")
endif()

# nothing of the plans exists; only cli.plan entries were added
bxc("list after plans" 0 list --db "${DB}" ${PW})
if(out MATCHES "Planned Sub|planned-dev|Text Plan")
  fail("a plan stored an object: ${out}")
endif()
string(REGEX MATCHALL "\"name\":\"dev\",\"type\":\"certificate\"" certs "${out}")
if(certs)
  fail("sign --plan stored a certificate: ${out}")
endif()
last_plan_entry(e)
split_lines("${e_all}" after)
list(LENGTH after entries_after)
set(new "")
foreach(l IN LISTS after)
  if(NOT l IN_LIST before)
    string(JSON a GET "${l}" action)
    list(APPEND new "${a}")
  endif()
endforeach()
list(REMOVE_ITEM new cli.plan audit.checkpoint audit.key_create)
if(new)
  fail("a plan wrote other audit entries: ${new}")
endif()

# --- failed plans are audited --------------------------------------------
bxc("plan path length" 1 init --db "${DB}" ${PW} --cn "Too Deep"
    --parent "Leaf CA" --plan)
expect_error("plan path length" path_length_exceeded)
last_plan_entry(e)
string(JSON res GET "${e}" result)
string(JSON code GET "${e}" error_code)
if(NOT res STREQUAL "failure" OR NOT code STREQUAL "path_length_exceeded")
  fail("failed plan entry: ${e}")
endif()

# a CA key with a password of its own: the unlock is checked, a wrong
# password fails the plan without a signature
set(OWN_PW "Own-Ca-Pw-77")
openssl_run(x genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256
    -out ownca.pem)
xca_run("import ownca key" 0 --database "${DB}" ${PW} --import
    "${WORK}/ownca.pem")
bxc("own CA" 0 init --db "${DB}" ${PW} --cn "Own CA" --use-key ownca)
openssl_run(x pkcs8 -topk8 -v2 aes-256-cbc -in ownca.pem
    -passout "pass:${OWN_PW}" -outform DER -out ownca.p8)
execute_process(COMMAND "${OPENSSL}" base64 -A -in "${WORK}/ownca.p8"
  OUTPUT_VARIABLE b64 RESULT_VARIABLE r)
execute_process(COMMAND "${SQL_EXEC}" "${DB}" -c
    "UPDATE private_keys SET ownPass=1, private='${b64}' WHERE item=(SELECT id FROM items WHERE name='ownca')"
  RESULT_VARIABLE r2 ERROR_VARIABLE e2)
if(NOT r EQUAL 0 OR NOT r2 EQUAL 0)
  fail("own password for the CA key: ${e2}")
endif()
bxc("plan wrong CA password" 1 sign dev --db "${DB}" ${PW} --ca "Own CA"
    --plan)
expect_error("plan wrong CA password" password_rejected)
last_plan_entry(e)
string(JSON res GET "${e}" result)
string(JSON code GET "${e}" error_code)
string(JSON cmd GET "${e}" params command)
if(NOT res STREQUAL "failure" OR NOT code STREQUAL "password_rejected" OR
   NOT cmd STREQUAL "sign")
  fail("plan with a wrong CA password: ${e}")
endif()
message(STATUS "bxc-pki --plan ok")
