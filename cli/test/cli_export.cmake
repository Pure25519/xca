# bxc-pki export (BTD-42, rule 9 of PLAN.md 8.4): every format of a
# certificate, key, request and CRL loads with the OpenSSL command line,
# the chain verifies with openssl verify; PKCS#8 is PBES2 and PKCS#12
# AES-256-CBC with PBKDF2 by default (openssl pkcs12 -info recorded);
# legacy encodings only with an explicit option; an encrypted export
# without --export-pass fails with a JSON error and writes no file; a
# private key export writes key.export_private; ML-DSA keys in each
# encoding (seed, expanded, both; RFC 9881) and a typed error for the
# option on another key; secret files have mode 0600.

include("${LIB}")

set(ENV{EXP_PW} "Export-Pw-42")
set(EP --export-pass env:EXP_PW)
file(MAKE_DIRECTORY "${WORK}/x")

bxc("root" 0 init --db "${DB}" ${PW} --cn "Exp Root" --key ec-p384)
bxc("issuing" 0 init --db "${DB}" ${PW} --cn "Exp Issuing" --parent "Exp Root"
    --key ec-p256)
bxc("request" 0 request-cert --db "${DB}" ${PW} --cn dev --key rsa-2048
    --dns dev.lab)
bxc("sign" 0 sign dev --db "${DB}" ${PW} --ca "Exp Issuing")
one_doc("sign" "${out}" cli-result r)
object_doc("${r}" certificate c)
string(JSON cid GET "${c}" id)
string(JSON kid GET "${c}" key_item id)

# xport(<label> <expected code> <args>...): export with ${DB} into x/
macro(xport label code)
  bxc("${label}" ${code} export --db "${DB}" ${PW} --out x ${ARGN})
  if(${code} EQUAL 0)
    one_doc("${label}" "${out}" cli-result _r)
    result_files("${_r}" files)
    string(JSON command GET "${_r}" command)
    if(NOT command STREQUAL "export")
      fail("${label}: command ${command}")
    endif()
  endif()
endmacro()

# --- public formats --------------------------------------------------------
xport("cert pem" 0 dev --type certificate --format pem)
openssl_run(t x509 -in ${files} -noout -subject)
xport("cert der" 0 dev --type certificate --format der)
openssl_run(t x509 -inform DER -in ${files} -noout -subject)
xport("root pem" 0 "Exp Root" --type certificate --format pem)
set(root_pem ${files})
xport("chain" 0 dev --type certificate --format chain)
set(chain ${files})
openssl_run(t verify -CAfile ${root_pem} -untrusted ${chain} ${chain})
if(NOT t MATCHES ": OK")
  fail("chain does not verify: ${t}")
endif()
xport("key pem" 0 dev --type key --format pem)
openssl_run(t pkey -pubin -in ${files} -noout)
xport("key der" 0 dev --type key --format der)
openssl_run(t pkey -pubin -inform DER -in ${files} -noout)
xport("request pem" 0 dev --type request --format pem)
openssl_run(t req -in ${files} -noout -verify)
xport("request der" 0 dev --type request --format der)
openssl_run(t req -inform DER -in ${files} -noout -verify)
xport("crl pem" 0 "Exp Issuing" --type crl --format pem)
openssl_run(t crl -in ${files} -noout)
xport("crl der" 0 "Exp Issuing" --type crl --format der)
openssl_run(t crl -inform DER -in ${files} -noout)
xport("template" 1 TLS_server --format pem)
expect_error("template" unknown_reference)
xport("p12 of a request" 1 dev --type request --format p12 ${EP})
expect_error("p12 of a request" format_not_applicable)

# --- encrypted exports need --export-pass -----------------------------------
file(GLOB before "${WORK}/x/*")
xport("p12 without pass" 1 dev --type certificate --format p12)
expect_error("p12 without pass" missing_password)
if(NOT detail MATCHES "--export-pass")
  fail("the error does not name --export-pass: ${detail}")
endif()
xport("pkcs8 without pass" 1 dev --type key --format pkcs8)
expect_error("pkcs8 without pass" missing_password)
# an empty password protects nothing; PKCS#12 accepts one, the command
# line does not (review of xca#62)
set(ENV{BXC_EMPTY} "")
xport("p12 with empty pass" 1 dev --type certificate --format p12
    --export-pass env:BXC_EMPTY)
expect_error("p12 with empty pass" missing_password)
# --interactive on a terminal (script(1) gives one): an empty password is
# refused, a new password is asked twice and must match
find_program(SCRIPT script)
if(SCRIPT)
  # tty(<label> <code> <lines>...): the p12 export with --interactive; one
  # line per prompt, sent after a pause (readPass() flushes input typed
  # ahead when it switches the terminal mode); "-" is an empty line
  function(tty label code)
    set(feed "")
    foreach(line IN LISTS ARGN)
      if(line STREQUAL "-")
        set(line "")
      endif()
      string(APPEND feed "sleep 2; printf '%s\\n' '${line}'; ")
    endforeach()
    execute_process(COMMAND sh -c "(${feed}sleep 2) | '${SCRIPT}' -qec \"'${BXC_PKI}' export dev --db '${DB}' --password env:BXC_DB_PW --type certificate --format p12 --out x --layout certstrap --force --interactive\" /dev/null"
      WORKING_DIRECTORY "${WORK}"
      RESULT_VARIABLE r OUTPUT_VARIABLE o ERROR_VARIABLE e TIMEOUT 60)
    file(APPEND "${TRANSCRIPT}" "### ${label}\nexit ${r}\n${o}${e}\n")
    if(NOT o MATCHES "\"code\": *\"${code}\"")
      fail("${label}: expected ${code} (exit ${r}):\n${o}${e}")
    endif()
  endfunction()
  tty("interactive empty p12 pass" missing_password -)
  tty("interactive p12 pass mismatch" wrong_password Tty-Pass-1
      Tty-Pass-2)
else()
  message(STATUS "script(1) not found: no --interactive terminal test")
endif()
file(GLOB after "${WORK}/x/*")
if(NOT before STREQUAL after)
  fail("a refused encrypted export wrote a file")
endif()

# --- rule 9: secure defaults ------------------------------------------------
xport("p12" 0 dev --type certificate --format p12 ${EP})
set(p12 ${files})
string(JSON alg GET "${_r}" files 0 pkcs12_algorithm)
if(NOT alg STREQUAL "AES-256-CBC")
  fail("p12 algorithm ${alg}")
endif()
openssl_run(info pkcs12 -info -noout -in ${p12} -passin env:EXP_PW)
if(NOT info MATCHES "Shrouded Keybag: PBES2, PBKDF2, AES-256-CBC" OR
   NOT info MATCHES "PKCS7 Encrypted data: PBES2, PBKDF2, AES-256-CBC")
  fail("p12 is not AES-256-CBC with PBKDF2:\n${info}")
endif()
file(WRITE "${WORK}/pkcs12-info.txt" "${info}")
openssl_run(t pkcs12 -in ${p12} -passin env:EXP_PW -nodes -noout)
file_mode("${WORK}/${p12}" m)
if(NOT m STREQUAL "600")
  fail("p12 mode ${m}")
endif()

xport("pkcs8" 0 dev --type key --format pkcs8 ${EP})
set(pk8 ${files})
file(READ "${WORK}/${pk8}" k)
if(NOT k MATCHES "BEGIN ENCRYPTED PRIVATE KEY")
  fail("pkcs8 is not encrypted PKCS#8")
endif()
openssl_run(t asn1parse -in ${pk8})
if(NOT t MATCHES ":PBES2" OR NOT t MATCHES ":PBKDF2" OR
   NOT t MATCHES "aes-256-cbc")
  fail("pkcs8 is not PBES2/PBKDF2/AES-256:\n${t}")
endif()
openssl_run(t pkey -in ${pk8} -passin env:EXP_PW -noout)
file_mode("${WORK}/${pk8}" m)
if(NOT m STREQUAL "600")
  fail("pkcs8 mode ${m}")
endif()
xport("pkcs8 of the certificate" 0 dev --type certificate --format pkcs8
    ${EP} --force)
openssl_run(t pkey -in ${files} -passin env:EXP_PW -noout)

# --- legacy only on request ---------------------------------------------------
xport("3DES p12" 0 dev --type certificate --format p12 ${EP}
    --pkcs12-algorithm PBE-SHA1-3DES --force)
openssl_run(t pkcs12 -info -noout -legacy -in ${files} -passin env:EXP_PW)
if(NOT t MATCHES "3DES|TripleDES")
  fail("--pkcs12-algorithm PBE-SHA1-3DES:\n${t}")
endif()
# --- PKCS#12 MAC and iterations (BTD-175) ----------------------------------
xport("pbmac1 p12" 0 dev --type certificate --format p12 ${EP}
    --pkcs12-mac pbmac1 --pkcs12-iterations 4096 --force)
openssl_run(t pkcs12 -info -noout -in ${files} -passin env:EXP_PW)
if(NOT t MATCHES "MAC: PBMAC1 using PBKDF2, Iteration 4096" OR
   NOT t MATCHES "Shrouded Keybag: PBES2, PBKDF2, AES-256-CBC, Iteration 4096")
  fail("--pkcs12-mac pbmac1 --pkcs12-iterations 4096:\n${t}")
endif()
string(JSON mac GET "${_r}" files 0 pkcs12_mac)
string(JSON iter GET "${_r}" files 0 pkcs12_iterations)
if(NOT mac STREQUAL "pbmac1" OR NOT iter EQUAL 4096)
  fail("pbmac1 p12: result names ${mac} ${iter}")
endif()
xport("default p12 mac" 0 dev --type certificate --format p12 ${EP} --force)
string(JSON mac GET "${_r}" files 0 pkcs12_mac)
string(JSON iter GET "${_r}" files 0 pkcs12_iterations)
if(NOT mac STREQUAL "hmac-sha256" OR NOT iter EQUAL 2048)
  fail("default p12: result names ${mac} ${iter}")
endif()
xport("p12 iterations below minimum" 1 dev --type certificate --format p12
    ${EP} --pkcs12-iterations 1000 --force)
expect_error("p12 iterations below minimum" invalid_pkcs12_iterations)
xport("p12 unknown mac" 1 dev --type certificate --format p12 ${EP}
    --pkcs12-mac hmac-md5 --force)
expect_error("p12 unknown mac" invalid_pkcs12_mac)
xport("mac option on pem" 2 dev --type certificate --format pem
    --pkcs12-mac pbmac1)
expect_error("mac option on pem" conflicting_options)
xport("unencrypted pkcs8" 0 dev --type key --format pkcs8 --key-unencrypted
    --force)
file(READ "${WORK}/${files}" k)
if(NOT k MATCHES "BEGIN PRIVATE KEY")
  fail("--key-unencrypted: no unencrypted PKCS#8")
endif()
xport("rfc 1423 pem" 0 dev --type key --format pkcs8 --legacy-key-pem ${EP}
    --force)
file(READ "${WORK}/${files}" k)
if(NOT k MATCHES "BEGIN RSA PRIVATE KEY" OR NOT k MATCHES "Proc-Type: 4,ENCRYPTED")
  fail("--legacy-key-pem: no RFC 1423 PEM")
endif()
openssl_run(t pkey -in ${files} -passin env:EXP_PW -noout)
xport("legacy option on pem" 2 dev --type certificate --format pem
    --key-unencrypted)
expect_error("legacy option on pem" conflicting_options)

# --- ML-DSA encodings ---------------------------------------------------------
bxc("ml-dsa key" 0 request-cert --db "${DB}" ${PW} --cn mld --key ml-dsa-44)
foreach(enc seed expanded both)
  xport("ml-dsa ${enc}" 0 mld --type key --format pkcs8 --key-unencrypted
      --mldsa-key-format ${enc} --force)
  string(JSON written GET "${_r}" files 0 ml_dsa_encoding)
  if(NOT written STREQUAL enc)
    fail("ml-dsa ${enc}: result names ${written}")
  endif()
  openssl_run(t asn1parse -in ${files})
  if(enc STREQUAL "seed")
    set(want "l= *34 prim: OCTET STRING *\\[HEX DUMP\\]:8020")
  elseif(enc STREQUAL "expanded")
    set(want "l= *2564 prim: OCTET STRING *\\[HEX DUMP\\]:04820A00")
  else()
    set(want "l= *2602 prim: OCTET STRING *\\[HEX DUMP\\]:30820A260420")
  endif()
  if(NOT t MATCHES "${want}")
    fail("ml-dsa ${enc}: PKCS#8 privateKey is not the ${enc} form:\n${t}")
  endif()
  openssl_run(t pkey -in ${files} -noout)
endforeach()
xport("ml-dsa encrypted" 0 mld --type key --format pkcs8 ${EP}
    --mldsa-key-format expanded --force)
openssl_run(t pkey -in ${files} -passin env:EXP_PW -noout)
xport("ml-dsa option on RSA" 1 dev --type key --format pkcs8 ${EP}
    --mldsa-key-format seed --force)
expect_error("ml-dsa option on RSA" format_not_applicable)
xport("ml-dsa bad value" 2 mld --type key --format pkcs8 ${EP}
    --mldsa-key-format compact)
expect_error("ml-dsa bad value" invalid_value)

# --- --plan reports the error of the real run (BTD-211) -------------------------
# real run and --plan: <label>|<exit code>|<error code>|<args, comma
# separated>
foreach(case
    "ml-dsa option on RSA|1|format_not_applicable|dev,--type,key,--format,pkcs8,--mldsa-key-format,seed,--export-pass,env:EXP_PW"
    "ml-dsa option on a public key|1|format_not_applicable|mld,--type,key,--format,pem,--mldsa-key-format,seed"
    "pkcs12 algorithm on pem|2|conflicting_options|dev,--type,certificate,--format,pem,--pkcs12-algorithm,PBE-SHA1-3DES"
    "unknown pkcs12 algorithm|1|invalid_pkcs12_algorithm|dev,--type,certificate,--format,p12,--pkcs12-algorithm,NO-SUCH-ALGO,--export-pass,env:EXP_PW")
  string(REPLACE "|" ";" p "${case}")
  list(GET p 0 label)
  list(GET p 1 code)
  list(GET p 2 ecode)
  list(GET p 3 args)
  string(REPLACE "," ";" args "${args}")
  foreach(mode real plan)
    set(extra --force)
    if(mode STREQUAL "plan")
      list(APPEND extra --plan)
    endif()
    bxc("${label} (${mode})" any export --db "${DB}" ${PW} --out x ${args}
        ${extra})
    if(NOT rc EQUAL code)
      fail("${label} (${mode}): exit code ${rc}, expected ${code} (${ecode}) as the real run")
    endif()
    expect_error("${label} (${mode})" ${ecode})
  endforeach()
endforeach()

# --- --plan writes nothing -------------------------------------------------------
file(GLOB before "${WORK}/x/*")
xport("plan" 0 "Exp Root" --type certificate --format der --layout certstrap
    --plan)
file(GLOB after "${WORK}/x/*")
if(NOT before STREQUAL after)
  fail("export --plan wrote a file")
endif()

# --- audit ------------------------------------------------------------------------
audit_entries(a)
audit_has("${a}" "\"action\":\"key\\.export_private\".*\"channel\":\"cli\".*\"encrypted\":true.*\"pkcs12_algorithm\":\"AES-256-CBC\"" "p12 key export")
audit_has("${a}" "\"action\":\"key\\.export_private\".*\"channel\":\"cli\".*\"encrypted\":true.*\"file\":\"x/dev-${kid}\\.key\"" "pkcs8 key export")
audit_has("${a}" "\"action\":\"key\\.export_private\".*\"channel\":\"cli\".*\"legacy\":true" "legacy key export")
audit_has("${a}" "\"action\":\"key\\.export_private\".*\"channel\":\"cli\".*\"ml_dsa_encoding\":\"seed\"" "ML-DSA seed")
# refusals before the service call get a failure entry too (review of xca#62)
foreach(code format_not_applicable unknown_reference)
  audit_has("${a}" "\"action\":\"object\\.export\".*\"channel\":\"cli\".*\"error_code\":\"${code}\".*\"result\":\"failure\"" "refusal ${code}")
endforeach()
audit_has("${a}" "\"action\":\"object\\.export\".*\"channel\":\"cli\".*\"error_code\":\"missing_password\".*\"result\":\"failure\"" "refused export")
audit_has("${a}" "\"action\":\"object\\.export\".*\"channel\":\"cli\".*\"error_code\":\"format_not_applicable\"" "ML-DSA option on RSA")
