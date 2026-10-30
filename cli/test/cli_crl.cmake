# bxc-pki crl and the CRL lifecycle (BTD-42, rule 7 of PLAN.md 8.4,
# PLAN.md 14.6): init issues the empty CRL at once; nextUpdate is
# thisUpdate + the CRL validity of the CA (default P7D); the re-issue
# point is one third of the validity (P7D: 56 hours), so sign renews a
# CRL issued 57 hours ago and keeps one issued 55 hours ago; validity,
# re-issue fraction and size budget are stored per CA (ca.crl_settings);
# the CRL file of --out is never overwritten without --force, and a
# refused file leaves the database unchanged; --plan writes nothing.

include("${LIB}")

# --- rule 7: the empty CRL of init -----------------------------------------
file(MAKE_DIRECTORY "${WORK}/out")
bxc("init" 0 init --db "${DB}" ${PW} --cn "CRL Root" --key ec-p256 --out out
    --layout certstrap --no-key-file)
one_doc("init" "${out}" cli-result r)
crl_entry("${r}" 0 c)
string(JSON n GET "${c}" crl_number)
string(JSON cnt GET "${c}" revoked_count)
string(JSON trig GET "${c}" trigger)
string(JSON frac GET "${c}" reissue_fraction)
string(JSON budget GET "${c}" size_budget)
string(JSON rem GET "${c}" remaining_validity)
if(NOT n EQUAL 1 OR NOT cnt EQUAL 0 OR NOT trig STREQUAL "init" OR
   NOT budget EQUAL 4096 OR NOT frac MATCHES "^0\\.333" OR
   NOT rem MATCHES "^P[67]D")
  fail("init CRL: number ${n}, ${cnt} entries, trigger ${trig}, fraction ${frac}, budget ${budget}, remaining ${rem}")
endif()
result_files("${r}" files)
if(NOT files STREQUAL "out/CRL_Root.crt;out/CRL_Root.crl")
  fail("init --out files: ${files}")
endif()
openssl_run(t crl -in out/CRL_Root.crl -noout -text)
if(NOT t MATCHES "No Revoked Certificates" OR NOT t MATCHES "CRL Number: *\n *1\n")
  fail("init CRL is not the empty CRL number 1:\n${t}")
endif()
openssl_run(t crl -in out/CRL_Root.crl -CAfile out/CRL_Root.crt -noout)

# --- nextUpdate and the re-issue point of a fixed thisUpdate --------------
bxc("crl fixed" 0 crl --ca "CRL Root" --db "${DB}" ${PW}
    --this-update 2026-01-01T00:00:00Z)
one_doc("crl fixed" "${out}" cli-result r)
crl_entry("${r}" 0 c)
string(JSON n GET "${c}" crl_number)
string(JSON nu GET "${c}" next_update)
string(JSON ra GET "${c}" reissue_at)
string(JSON exp GET "${c}" expired)
if(NOT n EQUAL 2 OR NOT nu STREQUAL "2026-01-08T00:00:00Z" OR
   NOT ra STREQUAL "2026-01-03T08:00:00Z")
  fail("P7D CRL: number ${n}, next ${nu}, re-issue at ${ra} (expected 56 h)")
endif()

# --- sign renews a CRL past its re-issue point, not one before it ---------
time_ago(t55 198000)   # 55 h
time_ago(t57 205200)   # 57 h
bxc("crl 55h ago" 0 crl --ca "CRL Root" --db "${DB}" ${PW}
    --this-update ${t55})
bxc("request a" 0 request-cert --db "${DB}" ${PW} --cn a)
bxc("sign before" 0 sign a --db "${DB}" ${PW} --ca "CRL Root")
one_doc("sign before" "${out}" cli-result r)
result_objects("${r}" objs)
if(NOT objs STREQUAL "certificate:a")
  fail("a CRL 55 h old (P7D) is renewed: ${objs}")
endif()
bxc("crl 57h ago" 0 crl --ca "CRL Root" --db "${DB}" ${PW}
    --this-update ${t57})
bxc("request b" 0 request-cert --db "${DB}" ${PW} --cn b)
bxc("sign after" 0 sign b --db "${DB}" ${PW} --ca "CRL Root")
one_doc("sign after" "${out}" cli-result r)
result_objects("${r}" objs)
if(NOT objs STREQUAL "certificate:b;crl:CRL Root")
  fail("a CRL 57 h old (P7D) is not renewed: ${objs}")
endif()
crl_entry("${r}" 0 c)
string(JSON trig GET "${c}" trigger)
string(JSON n GET "${c}" crl_number)
if(NOT trig STREQUAL "reissue_due" OR NOT n EQUAL 5)
  fail("renewed CRL: trigger ${trig}, number ${n}")
endif()

# --- settings per CA -------------------------------------------------------
bxc("bad fraction" 2 crl --ca "CRL Root" --db "${DB}" ${PW}
    --crl-reissue-fraction 1/2)
expect_error("bad fraction" invalid_value)
bxc("bad budget" 2 crl --ca "CRL Root" --db "${DB}" ${PW}
    --crl-size-budget 100)
expect_error("bad budget" invalid_value)
bxc("store settings" 0 crl --ca "CRL Root" --db "${DB}" ${PW}
    --crl-validity P3D --crl-reissue-fraction 1/4 --crl-size-budget 1024
    --this-update 2026-02-01T00:00:00Z)
one_doc("store settings" "${out}" cli-result r)
crl_entry("${r}" 0 c)
string(JSON nu GET "${c}" next_update)
string(JSON ra GET "${c}" reissue_at)
string(JSON budget GET "${c}" size_budget)
if(NOT nu STREQUAL "2026-02-04T00:00:00Z" OR
   NOT ra STREQUAL "2026-02-01T18:00:00Z" OR NOT budget EQUAL 1024)
  fail("P3D, 1/4: next ${nu}, re-issue at ${ra}, budget ${budget}")
endif()
# stored: the next CRL without options follows them
bxc("stored settings" 0 crl --ca "CRL Root" --db "${DB}" ${PW}
    --this-update 2026-03-01T00:00:00Z)
one_doc("stored settings" "${out}" cli-result r)
crl_entry("${r}" 0 c)
string(JSON nu GET "${c}" next_update)
string(JSON ra GET "${c}" reissue_at)
string(JSON budget GET "${c}" size_budget)
if(NOT nu STREQUAL "2026-03-04T00:00:00Z" OR
   NOT ra STREQUAL "2026-03-01T18:00:00Z" OR NOT budget EQUAL 1024)
  fail("stored settings not used: next ${nu}, re-issue at ${ra}, budget ${budget}")
endif()
# a CA with a short validity of its own from init
bxc("init short" 0 init --db "${DB}" ${PW} --cn "Short CRL" --key ec-p256
    --crl-validity PT12H)
one_doc("init short" "${out}" cli-result r)
crl_entry("${r}" 0 c)
string(JSON tu GET "${c}" this_update)
string(JSON nu GET "${c}" next_update)
string(JSON rem GET "${c}" remaining_validity)
if(NOT rem MATCHES "^PT1[12]H")
  fail("PT12H CRL: ${tu} .. ${nu}, remaining ${rem}")
endif()

# --- --out: no overwrite without --force; nothing stored then ------------
count_items(crl before)
bxc("crl exists" 1 crl --ca "CRL Root" --db "${DB}" ${PW} --out out
    --layout certstrap)
expect_error("crl exists" file_exists)
count_items(crl after)
if(NOT before EQUAL after)
  fail("a refused CRL file left a CRL in the database (${before} -> ${after})")
endif()
file(SHA256 "${WORK}/out/CRL_Root.crl" old)
bxc("crl --force" 0 crl --ca "CRL Root" --db "${DB}" ${PW} --out out
    --layout certstrap --force)
file(SHA256 "${WORK}/out/CRL_Root.crl" new)
if(old STREQUAL new)
  fail("--force did not replace the CRL file")
endif()
openssl_run(t crl -in out/CRL_Root.crl -noout)

# --- --plan ----------------------------------------------------------------
count_items(crl before)
bxc("plan" 0 crl --ca "CRL Root" --db "${DB}" ${PW} --plan --out out
    --layout certstrap --force)
one_doc("plan" "${out}" cli-result r)
string(JSON t TYPE "${r}" objects 0 id)
string(JSON w GET "${r}" files 0 written)
count_items(crl after)
file(SHA256 "${WORK}/out/CRL_Root.crl" same)
if(NOT t STREQUAL "NULL" OR w OR NOT before EQUAL after OR
   NOT same STREQUAL new)
  fail("plan wrote something: id ${t}, written ${w}, CRLs ${before} -> ${after}")
endif()

# --- audit -----------------------------------------------------------------
audit_entries(a)
audit_has("${a}" "\"action\":\"ca\\.crl_settings\".*\"channel\":\"cli\".*\"crl_validity\":\"P3D\".*\"reissue_fraction\":\"0\\.25\".*\"size_budget\":1024" "ca.crl_settings")
audit_has("${a}" "\"action\":\"crl\\.generate\".*\"channel\":\"cli\".*\"trigger\":\"reissue_due\"" "renewal")
