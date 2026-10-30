# bxc-pki crl and the CRL lifecycle (BTD-42, rule 7 of PLAN.md 8.4,
# PLAN.md 14.6): init issues the empty CRL at once; nextUpdate is
# thisUpdate + the CRL validity of the CA (default P7D); the re-issue
# point is one third of the validity (P7D: 56 hours), so sign renews a
# CRL issued 57 hours ago and keeps one issued 55 hours ago; validity,
# re-issue fraction and size budget are stored per CA (ca.crl_settings);
# the CRL file of --out is never overwritten without --force, and a
# refused file leaves the database unchanged; --plan writes nothing.
# BTD-211: the CRL validity is whole days, so that a CRL of the GUI path
# (crlDays) has the validity of a bxc-pki CRL; a stored setting that is no
# valid setting is crl_settings_invalid on every command that reads it;
# --this-update at most 5 minutes ahead, not before the latest CRL and no
# CRL expired at issue (the last two with --allow-stale-crl).

include("${LIB}")

# --- BTD-211 (i): CRL validity in whole days ---------------------------------
# The GUI issues the CRLs of a CA for its crlDays (NewCrl, xca --crlgen), so
# the stored validity is a whole number of days and both paths give the same
# validity; a part of a day is refused.
bxc("gui ca" 0 init --db "${DB}" ${PW} --cn "GUI CRL" --key ec-p256)
foreach(v PT1H PT36H)
  bxc("crl-validity ${v}" any crl --ca "GUI CRL" --db "${DB}" ${PW}
      --crl-validity ${v})
  if(rc EQUAL 0)
    fixture("gui-path crl after ${v}" guicrl "GUI CRL")
    string(STRIP "${out}" g)
    fail("--crl-validity ${v} accepted: the bxc-pki CRL has ${v}, a CRL of the GUI path then '${g}' (thisUpdate nextUpdate seconds)")
  endif()
  if(NOT rc EQUAL 2)
    fail("crl-validity ${v}: exit code ${rc}, expected 2")
  endif()
  expect_error("crl-validity ${v}" invalid_validity)
endforeach()
bxc("init PT12H" 2 init --db "${DB}" ${PW} --cn "Short CRL" --key ec-p256
    --crl-validity PT12H)
expect_error("init PT12H" invalid_validity)
foreach(pair "P2D|172800" "P1W|604800" "PT48H|172800")
  string(REPLACE "|" ";" p "${pair}")
  list(GET p 0 v)
  list(GET p 1 want)
  bxc("crl-validity ${v}" 0 crl --ca "GUI CRL" --db "${DB}" ${PW}
      --crl-validity ${v})
  one_doc("crl-validity ${v}" "${out}" cli-result r)
  crl_entry("${r}" 0 c)
  string(JSON secs GET "${c}" remaining_seconds)
  math(EXPR low "${want} - 120")
  if(secs GREATER want OR secs LESS low)
    fail("--crl-validity ${v}: the bxc-pki CRL has ${secs} s left, expected ${want}")
  endif()
  fixture("gui-path crl after ${v}" guicrl "GUI CRL")
  string(STRIP "${out}" g)
  if(NOT g MATCHES " ${want}$")
    fail("--crl-validity ${v}: a CRL of the GUI path has '${g}', expected ${want} s")
  endif()
endforeach()

# --- BTD-211 (h): the stored settings are read fail-closed ---------------------
bxc("settings ca" 0 init --db "${DB}" ${PW} --cn "Bad Settings" --key ec-p256
    --crl-validity P7D)
one_doc("settings ca" "${out}" cli-result r)
crl_entry("${r}" 0 c)
string(JSON bid GET "${c}" ca_id)
sql("settings row" "SELECT value FROM settings WHERE key_='crlpolicy_${bid}'")
if(NOT out MATCHES "\"validity\":\"P7D\"")
  fail("no settings row crlpolicy_${bid}: '${out}'")
endif()
bxc("request bs1" 0 request-cert --db "${DB}" ${PW} --cn bs1)
bxc("sign bs1" 0 sign bs1 --db "${DB}" ${PW} --ca "Bad Settings")
bxc("request bs2" 0 request-cert --db "${DB}" ${PW} --cn bs2)
# bad_row(<label> <value> <member>): the row holds value; every command
# that reads the setting is refused with crl_settings_invalid naming the
# CA and the member
function(bad_row label value member)
  sql("${label}" "UPDATE settings SET value='${value}' WHERE key_='crlpolicy_${bid}'")
  bxc("${label}: crl" any crl --ca "Bad Settings" --db "${DB}" ${PW})
  if(NOT rc EQUAL 1)
    fail("${label}: crl exit code ${rc}, expected 1 (crl_settings_invalid)")
  endif()
  expect_error("${label}: crl" crl_settings_invalid)
  if(NOT detail MATCHES "'Bad Settings'" OR NOT detail MATCHES "${member}")
    fail("${label}: the error does not name the CA and ${member}: ${detail}")
  endif()
endfunction()
bad_row("broken json" "{\"validity\":" value)
bad_row("no object" "[1,2]" value)
bad_row("unknown member" "{\"validity\":\"P7D\",\"reissue_fraction\":0.25,\"size_budget\":4096,\"colour\":\"red\"}" colour)
bad_row("missing member" "{\"validity\":\"P7D\",\"size_budget\":4096}" reissue_fraction)
bad_row("sub-day validity" "{\"validity\":\"PT1H\",\"reissue_fraction\":0.25,\"size_budget\":4096}" validity)
bad_row("no duration" "{\"validity\":\"seven days\",\"reissue_fraction\":0.25,\"size_budget\":4096}" validity)
bad_row("fraction" "{\"validity\":\"P7D\",\"reissue_fraction\":0.7,\"size_budget\":4096}" reissue_fraction)
bad_row("budget" "{\"validity\":\"P7D\",\"reissue_fraction\":0.25,\"size_budget\":100}" size_budget)
# every path that reads the setting: sign, revoke, trust list
bxc("bad settings: sign" 1 sign bs2 --db "${DB}" ${PW} --ca "Bad Settings")
expect_error("bad settings: sign" crl_settings_invalid)
bxc("bad settings: revoke" 1 revoke bs1 --db "${DB}" ${PW}
    --reason superseded)
expect_error("bad settings: revoke" crl_settings_invalid)
bxc("show bs1" 0 show bs1 --db "${DB}" ${PW} --type certificate)
string(STRIP "${out}" d)
string(JSON t TYPE "${d}" revocation)
if(NOT t STREQUAL "NULL")
  fail("bs1 was revoked although its CRL could not be issued")
endif()
file(MAKE_DIRECTORY "${WORK}/bstl")
bxc("bad settings: trust list" 1 export "Bad Settings" --db "${DB}" ${PW}
    --format trustlist --out bstl)
expect_error("bad settings: trust list" crl_settings_invalid)
bxc("bad settings: plan" 1 crl --ca "Bad Settings" --db "${DB}" ${PW} --plan)
expect_error("bad settings: plan" crl_settings_invalid)
# all three options replace the invalid setting; a missing row is the
# defaults with the CA's crlDays
bxc("repair settings" 0 crl --ca "Bad Settings" --db "${DB}" ${PW}
    --crl-validity P3D --crl-reissue-fraction 1/3 --crl-size-budget 4096)
bxc("repaired" 0 crl --ca "Bad Settings" --db "${DB}" ${PW})
one_doc("repaired" "${out}" cli-result r)
crl_entry("${r}" 0 c)
string(JSON secs GET "${c}" remaining_seconds)
if(secs GREATER 259200 OR secs LESS 259000)
  fail("repaired settings: ${secs} s left, expected P3D")
endif()
sql("drop row" "DELETE FROM settings WHERE key_='crlpolicy_${bid}'")
bxc("no row" 0 crl --ca "Bad Settings" --db "${DB}" ${PW})
one_doc("no row" "${out}" cli-result r)
crl_entry("${r}" 0 c)
string(JSON secs GET "${c}" remaining_seconds)
string(JSON sb GET "${c}" size_budget)
if(secs GREATER 259200 OR secs LESS 259000 OR NOT sb EQUAL 4096)
  fail("without the row: ${secs} s left (crlDays 3), budget ${sb}")
endif()


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
    --this-update 2026-01-01T00:00:00Z --allow-stale-crl)
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
    --this-update ${t57} --allow-stale-crl)
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

# --- BTD-211 (g): bounds of --this-update -------------------------------------
# the latest CRL of CRL Root is the renewed one of now
time_ahead(t_far 3600)
time_ahead(t_near 120)
time_ago(t_1h 3600)
bxc("this-update 1 h ahead" 2 crl --ca "CRL Root" --db "${DB}" ${PW}
    --this-update ${t_far})
expect_error("this-update 1 h ahead" invalid_this_update)
bxc("1 h ahead, --allow-stale-crl" 2 crl --ca "CRL Root" --db "${DB}" ${PW}
    --this-update ${t_far} --allow-stale-crl)
expect_error("1 h ahead, --allow-stale-crl" invalid_this_update)
bxc("expired at issue" 2 crl --ca "CRL Root" --db "${DB}" ${PW}
    --this-update 2026-01-01T00:00:00Z)
expect_error("expired at issue" invalid_this_update)
if(NOT detail MATCHES "expired on 2026-01-08")
  fail("expired at issue: the error does not name nextUpdate: ${detail}")
endif()
bxc("before the latest crl" 2 crl --ca "CRL Root" --db "${DB}" ${PW}
    --this-update ${t_1h})
expect_error("before the latest crl" invalid_this_update)
if(NOT detail MATCHES "number 5")
  fail("before the latest crl: the error does not name CRL 5: ${detail}")
endif()
bxc("--allow-stale-crl without --this-update" 2 crl --ca "CRL Root"
    --db "${DB}" ${PW} --allow-stale-crl)
expect_error("--allow-stale-crl without --this-update" conflicting_options)
count_items(crl before)
bxc("plan before the latest crl" 2 crl --ca "CRL Root" --db "${DB}" ${PW}
    --this-update ${t_1h} --plan)
expect_error("plan before the latest crl" invalid_this_update)
count_items(crl after)
if(NOT before EQUAL after)
  fail("a refused --this-update stored a CRL (${before} -> ${after})")
endif()
bxc("before the latest crl, --allow-stale-crl" 0 crl --ca "CRL Root"
    --db "${DB}" ${PW} --this-update ${t_1h} --allow-stale-crl)
bxc("within the clock skew" 0 crl --ca "CRL Root" --db "${DB}" ${PW}
    --this-update ${t_near})
one_doc("within the clock skew" "${out}" cli-result r)
crl_entry("${r}" 0 c)
string(JSON tu GET "${c}" this_update)
if(NOT tu STREQUAL t_near)
  fail("within the clock skew: thisUpdate ${tu}, expected ${t_near}")
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
    --this-update 2026-02-01T00:00:00Z --allow-stale-crl)
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
    --this-update 2026-03-01T00:00:00Z --allow-stale-crl)
one_doc("stored settings" "${out}" cli-result r)
crl_entry("${r}" 0 c)
string(JSON nu GET "${c}" next_update)
string(JSON ra GET "${c}" reissue_at)
string(JSON budget GET "${c}" size_budget)
if(NOT nu STREQUAL "2026-03-04T00:00:00Z" OR
   NOT ra STREQUAL "2026-03-01T18:00:00Z" OR NOT budget EQUAL 1024)
  fail("stored settings not used: next ${nu}, re-issue at ${ra}, budget ${budget}")
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
