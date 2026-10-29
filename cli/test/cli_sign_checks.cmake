# Rules 1, 3 and 5 of the certstrap triage through bxc-pki (BTD-41): the
# checks live in the service layer (BTD-55 path length and issuer checks,
# BTD-65 CSR acceptance, BTD-54 KU by key type); these tests prove them
# end to end once those tickets are merged into bxc-main. Switched on with
# -DBXC_PKI_SIGN_CHECKS=ON (cli/CMakeLists.txt). Every rejection must be
# a JSON error with a typed code (not internal_error), exit code 1, no
# object written.

include("${LIB}")

# reject(<label> <args>...): exit 1, a typed error, nothing written
function(reject label)
  bxc("${label}" any ${ARGN})
  # BXC_SIGN_CHECKS_REPORT=1: list which checks are missing, do not stop
  if(NOT rc EQUAL 1 AND DEFINED ENV{BXC_SIGN_CHECKS_REPORT})
    message(STATUS "${label}: NOT rejected (exit ${rc})")
    return()
  endif()
  if(NOT rc EQUAL 1)
    fail("${label}: must be rejected (exit 1), got ${rc}:\n${out}${err}")
  endif()
  one_doc("${label}" "${err}" error e)
  string(JSON code GET "${e}" code)
  if(code STREQUAL "internal_error" OR NOT out STREQUAL "")
    fail("${label}: untyped error or output: ${code} ${out}")
  endif()
  message(STATUS "${label}: ${code}")
endfunction()

bxc("root" 0 init --db "${DB}" ${PW} --cn "Check Root")
bxc("pathlen 0" 0 init --db "${DB}" ${PW} --cn "Leaf CA" --parent "Check Root"
    --path-len 0)

# rule 1: a sub-CA under pathLen 0 is rejected
reject("sub-CA under pathLen 0" init --db "${DB}" ${PW} --cn "Too Deep"
    --parent "Leaf CA")

# rule 5: issuer without cA / keyCertSign
bxc("ee request" 0 request-cert --db "${DB}" ${PW} --cn not-a-ca)
bxc("ee sign" 0 sign not-a-ca --db "${DB}" ${PW} --ca "Check Root")
bxc("victim" 0 request-cert --db "${DB}" ${PW} --cn victim)
reject("issuer without cA" sign victim --db "${DB}" ${PW} --ca not-a-ca)

# rule 5: an issuer with cA but without keyCertSign (made by openssl)
openssl_run(x req -new -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256
    -nodes -keyout noksign.key -subj "/CN=No KeyCertSign" -days 30
    -addext "basicConstraints=critical,CA:TRUE"
    -addext "keyUsage=critical,digitalSignature" -out noksign.pem)
xca_run("import noksign" 0 --database "${DB}" ${PW} --import
    "${WORK}/noksign.pem" "${WORK}/noksign.key")
reject("issuer without keyCertSign" sign victim --db "${DB}" ${PW}
    --ca "No KeyCertSign")

# rule 5: expired issuer
bxc("expired" 0 init --db "${DB}" ${PW} --cn "Expired CA"
    --not-before 2020-01-01T00:00:00Z --not-after 2021-01-01T00:00:00Z)
reject("expired issuer" sign victim --db "${DB}" ${PW} --ca "Expired CA"
    --not-before 2020-06-01T00:00:00Z --not-after 2020-12-01T00:00:00Z)

# rule 5: CA key does not match the CA certificate (CA certificate
# without its key in the database)
openssl_run(x req -new -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256
    -nodes -keyout other.key -subj "/CN=Keyless CA" -days 30
    -addext "basicConstraints=critical,CA:TRUE"
    -addext "keyUsage=critical,keyCertSign,cRLSign" -out keyless.pem)
xca_run("import keyless" 0 --database "${DB}" ${PW} --import
    "${WORK}/keyless.pem")
reject("CA key mismatch" sign victim --db "${DB}" ${PW} --ca "Keyless CA")

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
# write the flipped DER back as PEM through openssl base64
string(REGEX REPLACE "(..)" "\\\\x\\1" esc "${head}${last}")
execute_process(COMMAND printf "${esc}" OUTPUT_FILE "${WORK}/bad-flipped.der")
openssl_run(x req -inform DER -in bad-flipped.der -out bad.csr)
xca_run("import bad csr" 0 --database "${DB}" ${PW} --import "${WORK}/bad.csr")
reject("bad CSR signature" sign bad-pop --db "${DB}" ${PW} --ca "Check Root")

# rule 3: no keyEncipherment/dataEncipherment for EC, whatever the template
execute_process(COMMAND "${FIXTURE}" "${DB}" env:BXC_DB_PW template
    rsa-style serverAuth "digitalSignature,keyEncipherment,dataEncipherment"
  RESULT_VARIABLE r ERROR_VARIABLE e)
if(NOT r EQUAL 0)
  fail("cli_fixture: ${e}")
endif()
bxc("ec request" 0 request-cert --db "${DB}" ${PW} --cn ec-ku)
bxc("ec sign rsa-style" any sign ec-ku --db "${DB}" ${PW} --ca "Check Root"
    --template rsa-style)
if(rc EQUAL 0)
  one_doc("ec sign rsa-style" "${out}" cli-result r)
  object_doc("${r}" certificate c)
  extension("${c}" keyUsage ku)
  if(ku MATCHES "Encipherment")
    fail("EC certificate with '${ku}' (rule 3)")
  endif()
else()
  one_doc("ec sign rsa-style" "${err}" error e)
endif()
message(STATUS "bxc-pki sign checks ok")
