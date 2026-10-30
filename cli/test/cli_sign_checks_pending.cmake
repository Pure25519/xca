# Sign checks of bxc-pki (BTD-41) that needed the service check of
# BTD-195:
#  - rule 3: no keyEncipherment or dataEncipherment for an EC, EdDSA,
#    ML-DSA or SLH-DSA key, whatever the template says; the certificate
#    is either refused with a typed error or issued without those bits.
#    Since BTD-195 IssuanceChecks refuses it on every issuance
#    (key_usage_not_for_key_type).

include("${LIB}")

bxc("root" 0 init --db "${DB}" ${PW} --cn "Pending Root")
execute_process(COMMAND "${FIXTURE}" "${DB}" env:BXC_DB_PW template
    rsa-style serverAuth "digitalSignature,keyEncipherment,dataEncipherment"
  RESULT_VARIABLE r ERROR_VARIABLE e)
if(NOT r EQUAL 0)
  fail("cli_fixture: ${e}")
endif()
foreach(kt ec-p256 ed25519 ml-dsa-65)
  bxc("${kt} request" 0 request-cert --db "${DB}" ${PW} --cn "ku-${kt}"
      --key ${kt})
  bxc("${kt} sign rsa-style" any sign "ku-${kt}" --db "${DB}" ${PW}
      --ca "Pending Root" --template rsa-style)
  if(rc EQUAL 0)
    one_doc("${kt} sign rsa-style" "${out}" cli-result r)
    object_doc("${r}" certificate c)
    extension("${c}" keyUsage ku)
    if(ku MATCHES "Encipherment")
      fail("${kt} certificate with '${ku}' (rule 3)")
    endif()
  else()
    split_lines("${err}" el)
    list(POP_BACK el last)
    string(JSON code GET "${last}" code)
    if(NOT rc EQUAL 1 OR code STREQUAL "internal_error" OR NOT out STREQUAL "")
      fail("${kt}: refused without a typed error: ${rc} ${err}")
    endif()
  endif()
endforeach()
message(STATUS "bxc-pki pending sign checks ok")
