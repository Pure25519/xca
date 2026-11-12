# A write command of bxc-pki that fails before its service function while
# the database is open writes one failure entry with the action the
# command would have audited and the code of its error (BTD-106): an
# invalid option value (request-cert --hash), an unknown reference
# (crl --ca, sign --ca), a refused option (crl --allow-stale-crl). A
# refusal a handler already audits (revoke of a revoked certificate) is
# not written twice. Without an open database (an unknown option, a
# missing database) and for a read command there is no entry.

include("${LIB}")

bxc("create" 0 init --db "${DB}" ${PW} --cn "Pre Root")

# error_code(<var>): the code of the error object in ${err}
macro(error_code var)
  split_lines("${err}" elines)
  list(GET elines -1 last)
  string(JSON ${var} GET "${last}" code)
endmacro()

# count(<var> <lines> <regex>)
function(count var lines regex)
  split_lines("${lines}" l)
  set(n 0)
  foreach(line IN LISTS l)
    if(line MATCHES "${regex}")
      math(EXPR n "${n} + 1")
    endif()
  endforeach()
  set(${var} ${n} PARENT_SCOPE)
endfunction()

# refused(<label> <exit code> <action> <args>...): the command fails with
# that exit code and leaves exactly one failure entry of the action with
# its error code
function(refused label code action)
  bxc("${label}" ${code} ${ARGN})
  error_code(ec)
  audit_entries(a)
  string(REPLACE "." "\\." re "${action}")
  count(n "${a}" "\"action\":\"${re}\".*\"channel\":\"cli\".*\"error_code\":\"${ec}\".*\"result\":\"failure\"")
  if(NOT n EQUAL 1)
    fail("${label}: expected one ${action} failure entry with ${ec}, got ${n}:\n${a}")
  endif()
endfunction()

refused("bad hash" 2 request.create
  request-cert --db "${DB}" ${PW} --cn half --hash md2)
refused("unknown CA for crl" 1 crl.generate
  crl --db "${DB}" ${PW} --ca no-such-ca)
refused("stale CRL flag without date" 2 crl.generate
  crl --db "${DB}" ${PW} --ca "Pre Root" --allow-stale-crl)

# a refusal the handler audits itself stays one entry
bxc("cert" 0 init --db "${DB}" ${PW} --cn "Pre Leaf" --parent "Pre Root")
bxc("revoke" 0 revoke --db "${DB}" ${PW} "Pre Leaf" --reason keyCompromise)
refused("revoke twice" 1 certificate.revoke
  revoke --db "${DB}" ${PW} "Pre Leaf" --reason keyCompromise)

# nothing to audit: no database open, or a read command
audit_entries(before)
count(n0 "${before}" "\"result\":\"failure\"")
bxc("unknown option" 2 crl --db "${DB}" ${PW} --ca "Pre Root" --no-such-option)
bxc("missing database" 1 crl --db "${WORK}/none.xdb" ${PW} --ca "Pre Root")
bxc("show unknown" any show --db "${DB}" ${PW} no-such-object)
if(rc EQUAL 0)
  fail("show of an unknown object must fail")
endif()
audit_entries(after)
count(n1 "${after}" "\"result\":\"failure\"")
if(NOT n0 EQUAL n1)
  fail("a request without an open database or a read wrote ${n0} -> ${n1} failure entries:\n${after}")
endif()
