# bxc-pki --out (BTD-42, rule 10 of PLAN.md 8.4): init, request-cert, sign
# and revoke write the certstrap layout <CN>.key, .csr, .crt, .crl
# (--layout certstrap); a script written for certstrap's output works on
# them unchanged (recorded in certstrap-script.log); key files have mode
# 0600, public files are not refused for their mode; an existing file is
# never overwritten without --force, and then nothing is stored either,
# so an existing key is never reused or replaced silently; the default
# layout id never puts two objects with the same CN into one file; an
# encrypted key file needs --export-pass; --plan writes no file.

include("${LIB}")

set(ENV{EXP_PW} "Out-Pw-42")
set(D "${WORK}/certs")
file(MAKE_DIRECTORY "${D}")

# --- the certstrap layout --------------------------------------------------
bxc("init without key password" 1 init --db "${DB}" ${PW} --cn "Out Root"
    --key ec-p256 --out certs --layout certstrap)
expect_error("init without key password" missing_password)
if(NOT detail MATCHES "--export-pass")
  fail("the error does not name --export-pass: ${detail}")
endif()
file(GLOB files "${D}/*")
if(files)
  fail("a refused init wrote files: ${files}")
endif()

bxc("init" 0 init --db "${DB}" ${PW} --cn "Out Root" --key ec-p256 --out certs
    --layout certstrap --export-pass env:EXP_PW)
one_doc("init" "${out}" cli-result r)
result_files("${r}" files)
if(NOT files STREQUAL "certs/Out_Root.key;certs/Out_Root.crt;certs/Out_Root.crl")
  fail("init files: ${files}")
endif()
bxc("request" 0 request-cert --db "${DB}" ${PW} --cn host1 --dns host1.lab
    --out certs --layout certstrap --key-unencrypted)
bxc("sign" 0 sign host1 --db "${DB}" ${PW} --ca "Out Root" --out certs
    --layout certstrap)
foreach(f Out_Root.key Out_Root.crt Out_Root.crl host1.key host1.csr host1.crt)
  if(NOT EXISTS "${D}/${f}")
    fail("certstrap file ${f} missing")
  endif()
endforeach()
foreach(f Out_Root.key host1.key)
  file_mode("${D}/${f}" m)
  if(NOT m STREQUAL "600")
    fail("${f}: mode ${m}, expected 600 (rule 10)")
  endif()
endforeach()
file(READ "${D}/Out_Root.key" k)
if(NOT k MATCHES "BEGIN ENCRYPTED PRIVATE KEY")
  fail("the CA key file is not encrypted PKCS#8")
endif()

# --- a script written for certstrap's output ---------------------------------
file(WRITE "${WORK}/certstrap-script.sh" [=[
#!/bin/sh
# Written for the files of certstrap (init --common-name "Out Root",
# request-cert --common-name host1, sign host1 --CA "Out Root"); it uses
# only <CN>.key, <CN>.csr, <CN>.crt and <CN>.crl in the directory $1.
set -e
d="$1"
openssl verify -CAfile "$d/Out_Root.crt" -crl_check -CRLfile "$d/Out_Root.crl" "$d/host1.crt"
openssl req -in "$d/host1.csr" -noout -verify
openssl x509 -in "$d/host1.crt" -noout -pubkey > "$d/../crt.pub"
openssl pkey -in "$d/host1.key" -pubout > "$d/../key.pub"
cmp "$d/../crt.pub" "$d/../key.pub"
openssl pkey -in "$d/Out_Root.key" -passin env:EXP_PW -noout
openssl crl -in "$d/Out_Root.crl" -CAfile "$d/Out_Root.crt" -noout
echo "certstrap script: OK"
]=])
function(certstrap_script code var)
  execute_process(COMMAND sh "${WORK}/certstrap-script.sh" "${D}"
    WORKING_DIRECTORY "${WORK}" RESULT_VARIABLE r OUTPUT_VARIABLE o
    ERROR_VARIABLE e)
  file(APPEND "${WORK}/certstrap-script.log"
    "### certstrap-script.sh (exit ${r})\n${o}${e}\n")
  file(APPEND "${TRANSCRIPT}" "### certstrap-script.sh\nexit ${r}\n${o}${e}\n")
  if(code STREQUAL "0" AND NOT r EQUAL 0)
    fail("the certstrap script fails on the bxc-pki files:\n${o}${e}")
  endif()
  if(NOT code STREQUAL "0" AND r EQUAL 0)
    fail("the certstrap script passed, expected a failure:\n${o}${e}")
  endif()
  set(${var} "${o}${e}" PARENT_SCOPE)
endfunction()
certstrap_script(0 t)
if(NOT t MATCHES "host1.crt: OK" OR NOT t MATCHES "certstrap script: OK")
  fail("certstrap script output:\n${t}")
endif()

# revoke writes the new CRL into the same layout; the script now sees it
bxc("revoke" 0 revoke host1 --db "${DB}" ${PW} --reason superseded --out certs
    --layout certstrap --force)
certstrap_script(1 t)
if(NOT t MATCHES "certificate revoked")
  fail("the certstrap script does not see the revocation:\n${t}")
endif()

# --- rule 10: no silent overwrite, no silent key reuse -------------------------
file(SHA256 "${D}/host1.key" key1)
count_items(key keys_before)
bxc("second host1" 1 request-cert --db "${DB}" ${PW} --cn host1 --out certs
    --layout certstrap --key-unencrypted)
expect_error("second host1" file_exists)
count_items(key keys_after)
file(SHA256 "${D}/host1.key" key2)
if(NOT key1 STREQUAL key2 OR NOT keys_before EQUAL keys_after)
  fail("a refused file replaced the key file or stored a key")
endif()

# the default layout: <name>-<id>, two objects with the same CN
file(MAKE_DIRECTORY "${WORK}/ids")
set(keyfiles "")
foreach(i 1 2)
  bxc("twin ${i}" 0 request-cert --db "${DB}" ${PW} --cn twin --out ids
      --key-unencrypted)
  one_doc("twin ${i}" "${out}" cli-result r)
  object_doc("${r}" key k)
  string(JSON kid GET "${k}" id)
  result_files("${r}" files)
  list(GET files 0 kf)
  if(NOT kf STREQUAL "ids/twin-${kid}.key")
    fail("layout id: key file ${kf}, expected ids/twin-${kid}.key")
  endif()
  list(APPEND keyfiles "${kf}")
endforeach()
list(GET keyfiles 0 k1)
list(GET keyfiles 1 k2)
file(SHA256 "${WORK}/${k1}" s1)
file(SHA256 "${WORK}/${k2}" s2)
if(k1 STREQUAL k2 OR s1 STREQUAL s2)
  fail("two objects named twin share a file or a key: ${keyfiles}")
endif()

# --force replaces, a secret keeps 0600; a public file is not refused for
# its mode
bxc("replace host1" 0 request-cert --db "${DB}" ${PW} --cn host1 --out certs
    --layout certstrap --key-unencrypted --force)
one_doc("replace host1" "${out}" cli-result r)
object_doc("${r}" request q)
string(JSON rid GET "${q}" id)
file(SHA256 "${D}/host1.key" key3)
file_mode("${D}/host1.key" m)
if(key3 STREQUAL key1 OR NOT m STREQUAL "600")
  fail("--force: key file not replaced (or mode ${m})")
endif()
file(SHA256 "${D}/host1.crt" crt1)
file(CHMOD "${D}/host1.crt" PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ
    GROUP_WRITE WORLD_READ WORLD_WRITE)
bxc("public file with mode 666" 0 sign ${rid} --db "${DB}" ${PW}
    --ca "Out Root" --out certs --layout certstrap --force)
file(SHA256 "${D}/host1.crt" crt2)
if(crt1 STREQUAL crt2)
  fail("--force did not replace host1.crt")
endif()
openssl_run(t x509 -in certs/host1.crt -noout)

# --- checks before anything is stored ------------------------------------------
count_items(certificate certs_before)
bxc("no directory" 1 sign ${rid} --db "${DB}" ${PW} --ca "Out Root"
    --out missing-dir --name host1-x)
expect_error("no directory" invalid_output)
bxc("layout without --out" 2 sign ${rid} --db "${DB}" ${PW} --ca "Out Root"
    --layout certstrap)
expect_error("layout without --out" conflicting_options)
bxc("bad layout" 2 sign ${rid} --db "${DB}" ${PW} --ca "Out Root" --out certs
    --layout flat)
expect_error("bad layout" invalid_value)
count_items(certificate certs_after)
if(NOT certs_before EQUAL certs_after)
  fail("a refused --out stored a certificate")
endif()

# --- --plan --------------------------------------------------------------------
file(GLOB before "${D}/*" "${WORK}/ids/*")
bxc("plan" 0 request-cert --db "${DB}" ${PW} --cn planned --out certs
    --layout certstrap --key-unencrypted --plan)
one_doc("plan" "${out}" cli-result r)
result_files("${r}" files)
if(NOT files STREQUAL "certs/planned.key;certs/planned.csr")
  fail("plan files: ${files}")
endif()
file(GLOB after "${D}/*" "${WORK}/ids/*")
if(NOT before STREQUAL after)
  fail("--plan wrote a file")
endif()
bxc("plan collision" 1 request-cert --db "${DB}" ${PW} --cn host1 --out certs
    --layout certstrap --key-unencrypted --plan)
expect_error("plan collision" file_exists)

# --- audit -----------------------------------------------------------------------
audit_entries(a)
audit_has("${a}" "\"action\":\"key\\.export_private\".*\"channel\":\"cli\".*\"encrypted\":true.*\"file\":\"certs/Out_Root\\.key\"" "CA key file")
audit_has("${a}" "\"action\":\"key\\.export_private\".*\"channel\":\"cli\".*\"encrypted\":false.*\"file\":\"certs/host1\\.key\"" "unencrypted key file")
