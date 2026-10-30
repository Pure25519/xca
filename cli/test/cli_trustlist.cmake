# bxc-pki export --format trustlist (BTD-42, PLAN.md 14.6, OPC 10000-12
# 7.8.2): the target formats opcua-dir, pem-bundle and der-files; opcua-dir
# separates trusted/ (the given CAs) and issuer/ (their chain) with certs/
# and crl/, every exported CA comes with its CRL, openssl reads every
# file, the manifest lists CAs, then CRLs, then leaves; per-CRL and
# whole-list sizes against the budgets (a CRL above 4096 bytes: warning
# by default, error per target); an expired CRL or one past its re-issue
# point is refused without --allow-stale-crl when it cannot be renewed
# (--no-reissue), renewed otherwise; --force only replaces files; the
# remaining validity of every CRL is in the result; per-target re-issue
# fraction and budgets. The trust list replaces its directory as a whole
# (staged beside it, swapped in): one CRL file per CA, named after the CA,
# no files of an earlier export (review of xca#62).

include("${LIB}")

bxc("root" 0 init --db "${DB}" ${PW} --cn "TL Root" --key ec-p384)
bxc("issuing" 0 init --db "${DB}" ${PW} --cn "TL Issuing" --parent "TL Root"
    --key ec-p256)
bxc("request" 0 request-cert --db "${DB}" ${PW} --cn plc11)
bxc("sign" 0 sign plc11 --db "${DB}" ${PW} --ca "TL Issuing")
one_doc("sign" "${out}" cli-result r)
object_doc("${r}" certificate c)
pem_file("${c}" "${WORK}/plc11.pem")

# tl(<label> <code> <dir> <args>...): export --format trustlist into <dir>
macro(tl label code dir)
  file(MAKE_DIRECTORY "${WORK}/${dir}")
  bxc("${label}" ${code} export --db "${DB}" ${PW} --format trustlist
      --out ${dir} ${ARGN})
  if(${code} EQUAL 0)
    one_doc("${label}" "${out}" cli-result _r)
    result_files("${_r}" files)
  endif()
endmacro()

# --- opcua-dir ---------------------------------------------------------------
tl("opcua-dir" 0 opcua "TL Issuing" --target-format opcua-dir --leaf plc11)
set(kinds "")
foreach(f IN LISTS files)
  if(f MATCHES "/(trusted|issuer)/certs/[^/]+\\.der$" OR f MATCHES "/own/certs/")
    openssl_run(t x509 -inform DER -in ${f} -noout -subject)
  elseif(f MATCHES "/(trusted|issuer)/crl/[^/]+\\.crl$")
    openssl_run(t crl -inform DER -in ${f} -noout -issuer)
  elseif(NOT f MATCHES "/manifest\\.json$")
    fail("opcua-dir: unexpected file ${f}")
  endif()
endforeach()
foreach(pat "opcua/trusted/certs/TL_Issuing-[0-9]+\\.der"
    "opcua/trusted/crl/TL_Issuing-[0-9]+\\.crl"
    "opcua/issuer/certs/TL_Root-[0-9]+\\.der"
    "opcua/issuer/crl/TL_Root-[0-9]+\\.crl"
    "opcua/own/certs/plc11-[0-9]+\\.der" "opcua/manifest\\.json")
  if(NOT files MATCHES "${pat}")
    fail("opcua-dir: no file ${pat} in ${files}")
  endif()
endforeach()
# the CRL in trusted/crl belongs to the CA in trusted/certs
file(GLOB tc "${WORK}/opcua/trusted/certs/*.der")
file(GLOB tcrl "${WORK}/opcua/trusted/crl/*.crl")
openssl_run(t crl -inform DER -in ${tcrl} -noout -issuer)
if(NOT t MATCHES "CN=TL Issuing")
  fail("trusted/crl holds the CRL of another CA: ${t}")
endif()
# openssl verifies the leaf with the trust list and its CRLs
file(GLOB ic "${WORK}/opcua/issuer/certs/*.der")
file(GLOB icrl "${WORK}/opcua/issuer/crl/*.crl")
foreach(pair "${tc}|tc.pem|x509" "${ic}|ic.pem|x509" "${tcrl}|tcrl.pem|crl"
    "${icrl}|icrl.pem|crl")
  string(REPLACE "|" ";" p "${pair}")
  list(GET p 0 src)
  list(GET p 1 dst)
  list(GET p 2 kind)
  openssl_run(t ${kind} -inform DER -in ${src} -out ${dst})
endforeach()
file(READ "${WORK}/tc.pem" a)
file(READ "${WORK}/ic.pem" b)
file(WRITE "${WORK}/chain.pem" "${a}${b}")
file(READ "${WORK}/tcrl.pem" a)
file(READ "${WORK}/icrl.pem" b)
file(WRITE "${WORK}/crls.pem" "${a}${b}")
openssl_run(t verify -CAfile chain.pem -crl_check_all -CRLfile crls.pem
    plc11.pem)

# the manifest: CA certificates, then CRLs, then leaves
file(READ "${WORK}/opcua/manifest.json" m)
string(JSON schema GET "${m}" schema)
if(NOT schema STREQUAL "urn:bxc-pki:schema:trust-list-manifest:v1")
  fail("manifest schema ${schema}")
endif()
jlen(n "${m}" entries)
set(order "")
math(EXPR last "${n} - 1")
foreach(i RANGE ${last})
  string(JSON k GET "${m}" entries ${i} kind)
  string(JSON role GET "${m}" entries ${i} role)
  list(APPEND order "${k}:${role}")
endforeach()
if(NOT order STREQUAL "ca_certificate:trusted;ca_certificate:issuer;crl:trusted;crl:issuer;leaf_certificate:own")
  fail("manifest order: ${order}")
endif()
# the result: sizes, budgets, remaining validity of every CRL
string(JSON tf GET "${_r}" trust_list target_format)
string(JSON size GET "${_r}" trust_list size)
string(JSON budget GET "${_r}" trust_list budget)
string(JSON within GET "${_r}" trust_list within_budget)
if(NOT tf STREQUAL "opcua-dir" OR NOT budget EQUAL 65535 OR NOT within OR
   NOT size GREATER 0)
  fail("trust_list: ${tf} ${size}/${budget} ${within}")
endif()
jlen(n "${_r}" crls)
if(NOT n EQUAL 2)
  fail("crls: ${n} entries, expected one per CA")
endif()
foreach(i 0 1)
  crl_entry("${_r}" ${i} c)
  string(JSON rem GET "${c}" remaining_validity)
  string(JSON secs GET "${c}" remaining_seconds)
  string(JSON sb GET "${c}" size_budget)
  string(JSON ds GET "${c}" der_size)
  string(JSON role GET "${c}" role)
  if(NOT rem MATCHES "^P" OR NOT secs GREATER 0 OR NOT sb EQUAL 4096 OR
     NOT ds GREATER 0 OR NOT role MATCHES "^(trusted|issuer)$")
    fail("crls entry ${i}: ${c}")
  endif()
endforeach()

# --- pem-bundle and der-files ------------------------------------------------
tl("pem-bundle" 0 bundle "TL Issuing" --target-format pem-bundle)
if(NOT files STREQUAL "bundle/trustlist.pem;bundle/manifest.json")
  fail("pem-bundle files: ${files}")
endif()
openssl_run(t verify -CAfile bundle/trustlist.pem -crl_check_all
    -CRLfile bundle/trustlist.pem plc11.pem)
tl("der-files" 0 der "TL Issuing" --target-format der-files)
list(LENGTH files nf)
if(NOT nf EQUAL 5)
  fail("der-files: ${files}")
endif()
foreach(f IN LISTS files)
  if(f MATCHES "\\.der$")
    openssl_run(t x509 -inform DER -in ${f} -noout)
  elseif(f MATCHES "\\.crl$")
    openssl_run(t crl -inform DER -in ${f} -noout)
  endif()
endforeach()
tl("unknown target format" 2 bad "TL Issuing" --target-format scalance)
expect_error("unknown target format" invalid_value)
tl("leaf as CA" 1 bad plc11)
expect_error("leaf as CA" issuer_not_ca)
bxc("target format without trustlist" 2 export plc11 --db "${DB}" ${PW}
    --format pem --out bad --target-format opcua-dir)
expect_error("target format without trustlist" conflicting_options)

# --- budgets: a CRL above 4096 bytes ----------------------------------------------
fixture("120 revocations" revocations "TL Issuing" 120)
bxc("big crl" 0 crl --ca "TL Issuing" --db "${DB}" ${PW})
one_doc("big crl" "${out}" cli-result r)
crl_entry("${r}" 0 c)
string(JSON ds GET "${c}" der_size)
if(NOT ds GREATER 4096)
  fail("the CRL with 120 entries has only ${ds} bytes")
endif()
warning_codes("${r}" w)
if(NOT w STREQUAL "budget_exceeded")
  fail("crl above its budget: warnings '${w}'")
endif()
tl("budget warning" 0 big1 "TL Issuing")
warning_codes("${_r}" w)
crl_entry("${_r}" 0 c)
string(JSON within GET "${c}" within_budget)
if(NOT w MATCHES "budget_exceeded" OR within)
  fail("trust list with a big CRL: warnings '${w}', within ${within}")
endif()
file(GLOB_RECURSE before "${WORK}/big2/*")
tl("budget error" 1 big2 "TL Issuing" --on-budget-exceeded error)
expect_error("budget error" budget_exceeded)
file(GLOB_RECURSE after "${WORK}/big2/*")
if(after)
  fail("a refused trust list wrote files: ${after}")
endif()
tl("list budget" 0 big3 "TL Issuing" --trust-list-budget 1024
    --crl-size-budget 16384)
string(JSON within GET "${_r}" trust_list within_budget)
string(JSON budget GET "${_r}" trust_list budget)
crl_entry("${_r}" 0 c)
string(JSON sb GET "${c}" size_budget)
string(JSON cw GET "${c}" within_budget)
if(within OR NOT budget EQUAL 1024 OR NOT sb EQUAL 16384 OR NOT cw)
  fail("per-target budgets: list ${within}/${budget}, crl ${cw}/${sb}")
endif()

# --- expired and nearly expired CRLs -----------------------------------------------
bxc("expired root crl" 0 crl --ca "TL Root" --db "${DB}" ${PW}
    --this-update 2026-01-01T00:00:00Z)
tl("expired, no reissue" 1 exp1 "TL Issuing" --no-reissue)
expect_error("expired, no reissue" crl_expired)
# --force replaces files only; it does not accept a stale CRL
tl("expired, --force" 1 exp2 "TL Issuing" --no-reissue --force)
expect_error("expired, --force" crl_expired)
tl("expired, --allow-stale-crl" 0 exp2 "TL Issuing" --no-reissue
    --allow-stale-crl)
warning_codes("${_r}" w)
if(NOT w MATCHES "crl_expired")
  fail("--allow-stale-crl without the warning crl_expired: '${w}'")
endif()
crl_entry("${_r}" 1 c)
string(JSON expd GET "${c}" expired)
string(JSON rem GET "${c}" remaining_validity)
if(NOT expd OR NOT rem STREQUAL "PT0S")
  fail("expired CRL report: ${c}")
endif()
# without --no-reissue the export renews it (rule 7)
tl("expired, renewed" 0 exp3 "TL Issuing")
crl_entry("${_r}" 1 c)
string(JSON re GET "${c}" reissued)
string(JSON trig GET "${c}" trigger)
string(JSON expd GET "${c}" expired)
if(NOT re OR NOT trig STREQUAL "reissue_due" OR expd)
  fail("expired root CRL not renewed: ${c}")
endif()

time_ago(t60 216000)   # 60 h: past one third of P7D, not expired
bxc("old root crl" 0 crl --ca "TL Root" --db "${DB}" ${PW} --this-update ${t60})
tl("past re-issue point" 1 due1 "TL Issuing" --no-reissue)
expect_error("past re-issue point" crl_reissue_due)
tl("past re-issue point, --force" 1 due2 "TL Issuing" --no-reissue --force)
expect_error("past re-issue point, --force" crl_reissue_due)
tl("past re-issue point, --allow-stale-crl" 0 due2 "TL Issuing" --no-reissue
    --allow-stale-crl)
warning_codes("${_r}" w)
if(NOT w MATCHES "crl_reissue_due")
  fail("--allow-stale-crl without the warning crl_reissue_due: '${w}'")
endif()
bxc("allow-stale-crl without trustlist" 2 export plc11 --db "${DB}" ${PW}
    --format pem --out bad --allow-stale-crl)
expect_error("allow-stale-crl without trustlist" conflicting_options)

# per target: re-issue fraction of the export target
time_ago(t30 108000)   # 30 h: before one third of P7D
bxc("fresh root crl" 0 crl --ca "TL Root" --db "${DB}" ${PW} --this-update ${t30})
tl("fresh enough" 0 frac1 "TL Issuing" --no-reissue)
tl("target fraction" 1 frac2 "TL Issuing" --no-reissue
    --crl-reissue-fraction 1/10)
expect_error("target fraction" crl_reissue_due)
tl("target fraction, renewed" 0 frac3 "TL Issuing" --crl-reissue-fraction 1/10)
crl_entry("${_r}" 1 c)
string(JSON re GET "${c}" reissued)
string(JSON fr GET "${c}" reissue_fraction)
if(NOT re OR NOT fr MATCHES "^0\\.1")
  fail("per-target fraction: ${c}")
endif()

# --- re-export: the directory is replaced as a whole -----------------------------
# one_crl_per_ca(<dir> <sub>...): exactly one CRL per CA in each sub, named
# like the certificate of its CA (<CA>-<ca id>)
function(one_crl_per_ca dir)
  foreach(sub ${ARGN})
    file(GLOB crls "${WORK}/${dir}/${sub}/crl/*.crl")
    file(GLOB certs "${WORK}/${dir}/${sub}/certs/*.der")
    list(LENGTH crls nc)
    list(LENGTH certs nd)
    if(NOT nc EQUAL 1 OR NOT nd EQUAL 1)
      fail("${dir}/${sub}: ${nc} CRLs for ${nd} CAs: ${crls}")
    endif()
    get_filename_component(a "${crls}" NAME_WE)
    get_filename_component(b "${certs}" NAME_WE)
    if(NOT a STREQUAL b)
      fail("${dir}/${sub}: the CRL ${a} is not named after its CA ${b}")
    endif()
  endforeach()
endfunction()
tl("re-export 1" 0 re "TL Issuing" --leaf plc11)
one_crl_per_ca(re trusted issuer)
# a new CRL of each CA, then the same export again
bxc("new issuing crl" 0 crl --ca "TL Issuing" --db "${DB}" ${PW})
bxc("new root crl" 0 crl --ca "TL Root" --db "${DB}" ${PW})
tl("re-export without --force" 1 re "TL Issuing")
expect_error("re-export without --force" file_exists)
tl("re-export 2" 0 re "TL Issuing" --force)
one_crl_per_ca(re trusted issuer)
warning_codes("${_r}" w)
if(w MATCHES "stale_files")
  fail("a re-export reports stale files: '${w}'")
endif()
# own/ of the first export is gone: the directory holds this list only
if(EXISTS "${WORK}/re/own")
  fail("the leaf of the earlier export stays in re/own")
endif()
# the new CRL is the one in the directory
string(JSON crl_id GET "${_r}" crls 0 crl_id)
file(READ "${WORK}/re/manifest.json" m)
if(NOT m MATCHES "\"object_id\": *${crl_id}[,\n ]")
  fail("the manifest does not list the new CRL ${crl_id}:\n${m}")
endif()
# der-files: the same names, one CRL per CA
tl("der re-export 1" 0 der2 "TL Issuing" --target-format der-files)
bxc("newer issuing crl" 0 crl --ca "TL Issuing" --db "${DB}" ${PW})
tl("der re-export 2" 0 der2 "TL Issuing" --target-format der-files --force)
file(GLOB l "${WORK}/der2/*.crl")
list(LENGTH l n)
if(NOT n EQUAL 2)
  fail("der-files after a re-issue: ${n} CRLs for two CAs: ${l}")
endif()
# a directory with other files is not a trust list: refused, kept
file(MAKE_DIRECTORY "${WORK}/notes")
file(WRITE "${WORK}/notes/readme.txt" "keep me")
tl("foreign directory" 1 notes "TL Issuing" --force)
expect_error("foreign directory" invalid_output)
if(NOT EXISTS "${WORK}/notes/readme.txt")
  fail("a refused export removed a foreign file")
endif()
# no staging directory stays behind
file(GLOB left "${WORK}/.*bxc-tmp*")
if(left)
  fail("staging directories stay: ${left}")
endif()

# --- --plan -------------------------------------------------------------------------
file(GLOB_RECURSE before "${WORK}/plan/*")
tl("plan" 0 plan "TL Issuing" --plan)
file(GLOB_RECURSE after "${WORK}/plan/*")
if(after)
  fail("trust list --plan wrote ${after}")
endif()

# --- audit ------------------------------------------------------------------------
audit_entries(a)
audit_has("${a}" "\"action\":\"trustlist\\.export\".*\"channel\":\"cli\".*\"format\":\"opcua-dir\".*\"trust_list_budget\":65535" "trustlist.export")
audit_has("${a}" "\"action\":\"trustlist\\.export\".*\"channel\":\"cli\".*\"error_code\":\"crl_expired\".*\"result\":\"failure\"" "refused trust list")
audit_has("${a}" "\"action\":\"trustlist\\.export\".*\"warning\":\"budget_exceeded\"" "budget warning")
audit_has("${a}" "\"action\":\"crl\\.generate\".*\"channel\":\"cli\".*\"trigger\":\"reissue_due\"" "renewed CRL")
