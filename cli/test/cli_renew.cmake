# bxc-pki renew (BTD-56): a renewal keeps key, subject and SAN and gets a
# new serial; --rekey makes a new key of the predecessor's type (or of
# --key), --use-key takes one of the database; the selectors of revoke;
# the result names predecessor and successor; --plan writes nothing; a
# key revoked for keyCompromise is refused without --rekey and warned
# about with it; the issuer checks of sign apply; audit entries
# certificate.renew with channel cli; the link in table renewals.

include("${LIB}")

# pubkey_fp(<doc> <var>): SHA-256 fingerprint of the public key
function(pubkey_fp doc var)
  string(JSON v GET "${doc}" public_key fingerprint)
  set(${var} "${v}" PARENT_SCOPE)
endfunction()

bxc("init" 0 init --db "${DB}" ${PW} --cn "Renew Root" --key ec-p256)
bxc("request" 0 request-cert --db "${DB}" ${PW} --cn dev1
    --dns dev1.example --key ec-p256)
bxc("sign" 0 sign dev1 --db "${DB}" ${PW} --ca "Renew Root" --validity P90D)
one_doc("sign" "${out}" cli-result r)
object_doc("${r}" certificate old)
string(JSON old_id GET "${old}" id)
string(JSON old_serial GET "${old}" serial)
string(JSON old_fp GET "${old}" fingerprints sha256)
pubkey_fp("${old}" old_key)
extension("${old}" subjectAltName old_san)
string(JSON old_subject GET "${old}" subject rfc4514)

# --- refusals ----------------------------------------------------------------
bxc("no selector" 2 renew --db "${DB}" ${PW})
expect_error("no selector" missing_argument)
bxc("serial without --ca" 2 renew --db "${DB}" ${PW} --serial 01)
expect_error("serial without --ca" missing_option)
bxc("--key without --rekey" 2 renew dev1 --db "${DB}" ${PW} --key ec-p384)
expect_error("--key without --rekey" missing_option)
bxc("--rekey and --use-key" 2 renew dev1 --db "${DB}" ${PW} --rekey
    --use-key dev1)
expect_error("--rekey and --use-key" conflicting_options)
bxc("unknown" 1 renew nosuch --db "${DB}" ${PW})
expect_error("unknown" unknown_reference)

# --- --plan writes nothing --------------------------------------------------
count_items(certificate before)
bxc("plan" 0 renew dev1 --db "${DB}" ${PW} --plan)
one_doc("plan" "${out}" cli-result r)
jget(pred "${r}" renewal predecessor id)
jget(succ_type "${r}" renewal successor)
if(NOT pred STREQUAL old_id)
  fail("plan: predecessor ${pred}, expected ${old_id}")
endif()
count_items(certificate after)
if(NOT after EQUAL before)
  fail("--plan stored a certificate (${before} -> ${after})")
endif()

# --- renew with the same key, by name ---------------------------------------
bxc("renew" 0 renew dev1 --db "${DB}" ${PW})
one_doc("renew" "${out}" cli-result r)
object_doc("${r}" certificate nu)
string(JSON nu_id GET "${nu}" id)
string(JSON nu_serial GET "${nu}" serial)
pubkey_fp("${nu}" nu_key)
extension("${nu}" subjectAltName nu_san)
string(JSON nu_subject GET "${nu}" subject rfc4514)
jget(pred "${r}" renewal predecessor id)
jget(pred_serial "${r}" renewal predecessor serial)
jget(succ "${r}" renewal successor id)
jget(succ_serial "${r}" renewal successor serial)
jget(rekey "${r}" renewal rekey)
if(NOT pred STREQUAL old_id OR NOT pred_serial STREQUAL old_serial OR
   NOT succ STREQUAL nu_id OR NOT succ_serial STREQUAL nu_serial)
  fail("renewal member: ${pred}/${pred_serial} -> ${succ}/${succ_serial}, "
       "expected ${old_id}/${old_serial} -> ${nu_id}/${nu_serial}")
endif()
if(rekey)
  fail("a renewal with the same key reports rekey")
endif()
if(nu_serial STREQUAL old_serial)
  fail("the renewal kept the serial ${old_serial}")
endif()
if(NOT nu_key STREQUAL old_key)
  fail("the renewal changed the key")
endif()
if(NOT nu_san STREQUAL old_san OR NOT nu_subject STREQUAL old_subject)
  fail("subject or SAN changed: '${nu_subject}' '${nu_san}'")
endif()
# the default validity is the predecessor's period (P90D), from now
string(JSON nb GET "${nu}" not_before)
string(JSON na GET "${nu}" not_after)
string(TIMESTAMP now "%Y-%m-%d" UTC)
if(NOT nb MATCHES "^${now}")
  fail("not_before ${nb} is not today")
endif()
sql("link" "SELECT predecessor, predecessor_serial, rekey FROM renewals WHERE item=${nu_id}")
string(STRIP "${out}" link)
string(REPLACE ":" "" plain_serial "${old_serial}")
if(NOT link MATCHES "^${old_id}\\|${plain_serial}\\|0$")
  fail("renewals row '${link}', expected ${old_id}|${plain_serial}|0")
endif()

# --- re-key by fingerprint: the predecessor's type ---------------------------
bxc("rekey" 0 renew --fingerprint "${old_fp}" --db "${DB}" ${PW} --rekey
    --name dev1-rekeyed)
one_doc("rekey" "${out}" cli-result r)
result_objects("${r}" objs)
if(NOT objs STREQUAL "key:dev1-rekeyed;certificate:dev1-rekeyed")
  fail("rekey wrote '${objs}'")
endif()
object_doc("${r}" certificate rk)
pubkey_fp("${rk}" rk_key)
string(JSON rk_curve GET "${rk}" public_key curve)
jget(rekey "${r}" renewal rekey)
if(NOT rekey OR rk_key STREQUAL old_key)
  fail("--rekey kept the key")
endif()
if(NOT rk_curve MATCHES "prime256v1|P-256")
  fail("--rekey did not keep the key type: ${rk_curve}")
endif()

# --- re-key with --key, by serial and --ca ------------------------------------
bxc("rekey p384" 0 renew --serial "${old_serial}" --ca "Renew Root"
    --db "${DB}" ${PW} --rekey --key ec-p384 --name dev1-p384)
one_doc("rekey p384" "${out}" cli-result r)
object_doc("${r}" certificate p3)
string(JSON p3_curve GET "${p3}" public_key curve)
if(NOT p3_curve MATCHES "secp384r1|P-384")
  fail("--key ec-p384 gave ${p3_curve}")
endif()

# --- keyCompromise -------------------------------------------------------------
bxc("revoke" 0 revoke ${old_id} --db "${DB}" ${PW} --reason keyCompromise)
bxc("compromised key" 1 renew ${old_id} --db "${DB}" ${PW})
expect_error("compromised key" key_compromised)
bxc("compromised rekey" 0 renew ${old_id} --db "${DB}" ${PW} --rekey
    --name dev1-after)
one_doc("compromised rekey" "${out}" cli-result r)
warning_codes("${r}" codes)
if(NOT codes MATCHES "predecessor_key_compromised")
  fail("re-key after keyCompromise without warning: '${codes}'")
endif()

# --- the issuer checks of sign: a CA that is not valid yet -----------------
time_ahead(future 864000)
bxc("future root" 0 init --db "${DB}" ${PW} --cn "Late Root" --key ec-p256
    --not-before "${future}")
bxc("late request" 0 request-cert --db "${DB}" ${PW} --cn dev2)
time_ahead(later 950400)
bxc("late sign" 0 sign dev2 --db "${DB}" ${PW} --ca "Late Root"
    --not-before "${later}")
bxc("renew before the CA" 1 renew dev2 --db "${DB}" ${PW})
expect_error("renew before the CA" issuer_not_yet_valid)

# --- audit ----------------------------------------------------------------------
audit_entries(lines)
audit_has("${lines}"
  "\"action\":\"certificate.renew\".*\"channel\":\"cli\".*\"result\":\"success\""
  "renewal")
audit_has("${lines}" "\"rekey\":true" "re-key")
audit_has("${lines}" "\"error_code\":\"key_compromised\"" "key compromise")
audit_has("${lines}" "\"warning\":\"predecessor_key_compromised\""
  "warning after key compromise")
audit_has("${lines}" "\"error_code\":\"issuer_not_yet_valid\"" "issuer check")
audit_has("${lines}" "\"action\":\"certificate.renew\".*\"error_code\":\"unknown_reference\""
  "unknown reference")
