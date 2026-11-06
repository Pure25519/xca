# A failure entry that cannot be written (BTD-274): a trigger on audit_log
# refuses every failure entry. A refused issuance (bxc-pki sign by a CA
# that is no CA) and a refused key generation (xca --keygen with an
# unknown curve) then fail with audit_entry_lost, exit code 1, and
# the detail still names the original error. Success entries are not
# affected.

include("${LIB}")

bxc("root" 0 init --db "${DB}" ${PW} --cn "Lost Root" --key ec-p256)
bxc("leaf request" 0 request-cert --db "${DB}" ${PW} --cn not-a-ca --key ec-p256)
bxc("leaf sign" 0 sign not-a-ca --db "${DB}" ${PW} --ca "Lost Root")
bxc("victim" 0 request-cert --db "${DB}" ${PW} --cn victim --key ec-p256)

sql("trigger" "CREATE TRIGGER refuse_failures BEFORE INSERT ON audit_log WHEN NEW.result = 'failure' BEGIN SELECT RAISE(ABORT, 'failure entries refused'); END")

# lost(<label> <original code>): the error object of ${err} is
# audit_entry_lost and its detail names the original code
function(lost label original)
  string(REGEX MATCH "{\"code\"[^\n]*}" obj "${err}")
  string(JSON code ERROR_VARIABLE jerr GET "${obj}" code)
  if(jerr OR NOT code STREQUAL "audit_entry_lost")
    fail("${label}: error code '${code}', expected audit_entry_lost:\n${err}")
  endif()
  string(JSON detail GET "${obj}" detail)
  if(NOT detail MATCHES "${original}")
    fail("${label}: the detail does not name ${original}: ${detail}")
  endif()
  message(STATUS "${label}: audit_entry_lost (${original})")
endfunction()

bxc("sign by a non-CA" 1 sign victim --db "${DB}" ${PW} --ca not-a-ca)
lost("sign by a non-CA" issuer_not_ca)

xca_run("keygen unknown curve" 1 --database "${DB}" ${PW} --json
    --keygen EC:nocurve --name no-curve)
lost("keygen unknown curve" invalid_curve)

# a success entry is still written: the trigger refuses failures only
bxc("sign by the root" 0 sign victim --db "${DB}" ${PW} --ca "Lost Root")
