# Rules 1 and 5 of the certstrap triage through bxc-pki (BTD-41): the
# checks of the service layer before every signature (BTD-55,
# lib/issuance_checks.h) end to end. Every rejection is a JSON error with
# its typed code, exit code 1, nothing written. Rule 3 (key usage by key
# type, BTD-195) is in cli_sign_checks_pending.cmake.

include("${LIB}")

# reject(<label> <code> <args>...): exit 1, error <code>, stdout empty
function(reject label code)
  bxc("${label}" 1 ${ARGN})
  expect_error("${label}" ${code})
  message(STATUS "${label}: ${code}")
endfunction()

bxc("root" 0 init --db "${DB}" ${PW} --cn "Check Root")
bxc("pathlen 0" 0 init --db "${DB}" ${PW} --cn "Leaf CA" --parent "Check Root"
    --path-len 0)
bxc("leaf under pathlen 0" 0 request-cert --db "${DB}" ${PW} --cn leaf)
bxc("sign leaf under pathlen 0" 0 sign leaf --db "${DB}" ${PW} --ca "Leaf CA")

# rule 1: a sub-CA under pathLen 0 is rejected, also deeper in the chain
reject("sub-CA under pathLen 0" path_length_exceeded init --db "${DB}" ${PW}
    --cn "Too Deep" --parent "Leaf CA")

# rule 5: issuer without cA
bxc("ee request" 0 request-cert --db "${DB}" ${PW} --cn not-a-ca)
bxc("ee sign" 0 sign not-a-ca --db "${DB}" ${PW} --ca "Check Root")
bxc("victim" 0 request-cert --db "${DB}" ${PW} --cn victim)
reject("issuer without cA" issuer_not_ca sign victim --db "${DB}" ${PW}
    --ca not-a-ca)

# rule 5: an issuer with cA whose key usage lacks keyCertSign
openssl_run(x req -new -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256
    -nodes -keyout noksign.key -subj "/CN=No KeyCertSign" -days 30
    -addext "basicConstraints=critical,CA:TRUE"
    -addext "keyUsage=critical,digitalSignature" -out noksign.pem)
xca_run("import noksign" 0 --database "${DB}" ${PW} --import
    "${WORK}/noksign.pem" "${WORK}/noksign.key")
reject("issuer without keyCertSign" issuer_no_keycertsign sign victim
    --db "${DB}" ${PW} --ca "No KeyCertSign")

# rule 5: expired issuer, also for dates inside its old lifetime
bxc("expired" 0 init --db "${DB}" ${PW} --cn "Expired CA"
    --not-before 2020-01-01T00:00:00Z --not-after 2021-01-01T00:00:00Z)
reject("expired issuer" issuer_expired sign victim --db "${DB}" ${PW}
    --ca "Expired CA" --not-before 2020-06-01T00:00:00Z
    --not-after 2020-12-01T00:00:00Z)

# rule 5: a CA certificate without its key in the database
openssl_run(x req -new -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256
    -nodes -keyout other.key -subj "/CN=Keyless CA" -days 30
    -addext "basicConstraints=critical,CA:TRUE"
    -addext "keyUsage=critical,keyCertSign,cRLSign" -out keyless.pem)
xca_run("import keyless" 0 --database "${DB}" ${PW} --import
    "${WORK}/keyless.pem")
reject("CA without key" no_private_signing_key sign victim --db "${DB}" ${PW}
    --ca "Keyless CA")
# (a CA key that does not match its certificate cannot be referenced
# through the database, which links keys by their public key; the
# service check issuer_key_mismatch is covered by test_service_signing)

# rule 5: a CSR with a broken signature (proof of possession)
openssl_run(x req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes
    -keyout bad.key -subj "/CN=bad-pop" -outform DER -out bad.der)
file(READ "${WORK}/bad.der" hex HEX)
string(LENGTH "${hex}" n)
math(EXPR cut "${n} - 2")
string(SUBSTRING "${hex}" 0 ${cut} head)
string(SUBSTRING "${hex}" ${cut} 2 last)
if(last STREQUAL "00")
  set(last "01")
else()
  set(last "00")
endif()
# the flipped DER through printf, then PEM with openssl
string(REGEX REPLACE "(..)" "\\\\x\\1" esc "${head}${last}")
execute_process(COMMAND printf "${esc}" OUTPUT_FILE "${WORK}/bad-flipped.der")
openssl_run(x req -inform DER -in bad-flipped.der -out bad.csr)
xca_run("import bad csr" 0 --database "${DB}" ${PW} --import "${WORK}/bad.csr")
reject("bad CSR signature" invalid_csr_signature sign bad-pop --db "${DB}"
    ${PW} --ca "Check Root")

# insecure digests are refused
reject("sha1" signature_hash_not_allowed sign victim --db "${DB}" ${PW}
    --ca "Check Root" --hash sha1)

# nothing of the rejections was stored, the chain verifies
bxc("list" 0 list --db "${DB}" ${PW} --type certificate)
if(out MATCHES "Too Deep|\"victim\"|bad-pop")
  fail("a rejected certificate was stored: ${out}")
endif()
audit_entries(lines)
foreach(code path_length_exceeded issuer_not_ca issuer_no_keycertsign
    issuer_expired no_private_signing_key invalid_csr_signature
    signature_hash_not_allowed)
  if(NOT lines MATCHES "certificate\\.issue\"[^\n]*\"channel\":\"cli\"[^\n]*\"error_code\":\"${code}\"")
    fail("no audited failure ${code}:\n${lines}")
  endif()
endforeach()
message(STATUS "bxc-pki sign checks ok")
