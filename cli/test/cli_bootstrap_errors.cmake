# bxc-pki bootstrap (BTD-166): refused files. A schema error, a literal
# secret, an unresolvable secret reference, a CRL validity that is no
# whole number of days, an unresolved op:// reference and a conflicting
# change to an existing CA each end with exit code 1 and a JSON error
# whose detail starts with the JSON pointer (or names the object); the
# database is unchanged afterwards, also when the error comes in the
# middle of the run (no partial hierarchy). Own key passwords (key_password)
# from env:; parent "external" is skipped; the binary links no 1Password
# library.

include("${LIB}")
include("${CMAKE_CURRENT_LIST_DIR}/cli_bootstrap_lib.cmake")

set(BASE [=[{"schema": "urn:bxc-pki:schema:bootstrap:v1",
 "database": {"type": "sqlite", "path": "x.xdb", "password": "env:BXC_DB_PW"},
 "cas": [{"id": "err-root", "cn": "Err Root", "key": "ec-p256", "validity": "P5Y"}]}]=])

bs_write(base.json "${BASE}")
bxc("base" 0 bootstrap --file "${file}" --db "${DB}")
one_doc("base" "${out}" cli-result r)
bs_counts("base" "${r}" 1 0 0 0)

# refused(<label> <code> <pointer> <json>): the file is refused with code;
# the detail starts with "<pointer>: "; the database is unchanged
function(refused label code pointer json)
  db_state(before)
  bs_write(refused.json "${json}")
  bxc("${label}" 1 bootstrap --file "${file}" --db "${DB}")
  expect_error("${label}" ${code})
  string(FIND "${detail}" "${pointer}: " pos)
  if(NOT pos EQUAL 0)
    fail("${label}: the detail does not start with '${pointer}: ':\n${detail}")
  endif()
  db_state(after)
  if(NOT before STREQUAL after)
    fail("${label}: the database changed:\n${before}\n---\n${after}")
  endif()
  set(detail "${detail}" PARENT_SCOPE)
endfunction()

# variant(<var> <path and value>...): BASE with one member set
function(variant var)
  string(JSON j SET "${BASE}" ${ARGN})
  set(${var} "${j}" PARENT_SCOPE)
endfunction()

# --- schema errors, each with its JSON pointer --------------------------------
refused("not json" invalid_bootstrap_file "/" "{\"schema\": ")
refused("no object" invalid_bootstrap_file "/" "[]")
string(JSON j SET "${BASE}" certificate_authorities "[]")
refused("unknown top-level member" invalid_bootstrap_file
    "/certificate_authorities" "${j}")
variant(j schema [=["urn:bxc-pki:schema:bootstrap:v2"]=])
refused("schema const" invalid_bootstrap_file "/schema" "${j}")
string(JSON j REMOVE "${BASE}" cas)
refused("cas missing" invalid_bootstrap_file "/cas" "${j}")
variant(j cas "[]")
refused("cas empty" invalid_bootstrap_file "/cas" "${j}")
string(JSON j REMOVE "${BASE}" database password)
refused("database password missing" invalid_bootstrap_file
    "/database/password" "${j}")
variant(j database type [=["oracle"]=])
refused("database type" invalid_bootstrap_file "/database/type" "${j}")
variant(j cas 0 id [=["Err-Root"]=])
refused("id pattern" invalid_bootstrap_file "/cas/0/id" "${j}")
variant(j cas 0 key [=["rsa-1024"]=])
refused("key type" invalid_bootstrap_file "/cas/0/key" "${j}")
variant(j cas 0 path_len [=["0"]=])
refused("path_len string" invalid_bootstrap_file "/cas/0/path_len" "${j}")
variant(j cas 0 path_len -1)
refused("path_len negative" invalid_bootstrap_file "/cas/0/path_len" "${j}")
variant(j cas 0 dn [=["CN=Root,O=BxC"]=])
refused("dn and cn" invalid_bootstrap_file "/cas/0" "${j}")
string(JSON j REMOVE "${BASE}" cas 0 cn)
refused("no subject" invalid_bootstrap_file "/cas/0" "${j}")
string(JSON j SET "${j}" cas 0 dn "[[]]")
refused("empty rdn" invalid_bootstrap_file "/cas/0/dn/0" "${j}")
string(JSON j SET "${j}" cas 0 dn [=[[[{"type": "CN", "value": ""}]]]=])
refused("dn value empty" invalid_bootstrap_file "/cas/0/dn/0/0/value" "${j}")
variant(j cas 0 subject [=[{"C": "Germany"}]=])
refused("subject C" invalid_bootstrap_file "/cas/0/subject/C" "${j}")
variant(j cas 0 key_usage [=[["keyCertSign", "nonRepudiation", "contentCommitment"]]=])
refused("key usage synonyms" invalid_bootstrap_file "/cas/0/key_usage" "${j}")
variant(j cas 0 key_usage [=[["certSign"]]=])
refused("key usage unknown" invalid_bootstrap_file "/cas/0/key_usage/0" "${j}")
variant(j cas 0 name_constraints [=[{"critical": true}]=])
refused("name constraints empty" invalid_bootstrap_file
    "/cas/0/name_constraints" "${j}")
variant(j cas 0 name_constraints [=[{"permitted": {"ip": ["192.168.0.0"]}}]=])
refused("name constraint ip" invalid_bootstrap_file
    "/cas/0/name_constraints/permitted/ip/0" "${j}")
variant(j cas 0 not_after [=["2046-10-31T23:59:59Z"]=])
refused("validity and not_after" invalid_bootstrap_file "/cas/0" "${j}")
string(JSON j REMOVE "${BASE}" cas 0 validity)
string(JSON j SET "${j}" cas 0 not_after [=["2046-10-31T23:59:59+01:00"]=])
refused("not_after offset" invalid_bootstrap_file "/cas/0/not_after" "${j}")
variant(j cas 0 crl [=[{"validity": "P7D", "next_update": "P1D"}]=])
refused("crl unknown member" invalid_bootstrap_file "/cas/0/crl/next_update"
    "${j}")
variant(j cas 0 crl [=[{"reissue_fraction": 0.5}]=])
refused("crl reissue fraction" invalid_bootstrap_file
    "/cas/0/crl/reissue_fraction" "${j}")
variant(j cas 0 crl [=[{"size_budget": 100}]=])
refused("crl size budget" invalid_bootstrap_file "/cas/0/crl/size_budget"
    "${j}")
variant(j cas 0 crl [=[{"distribution_points": ["pki.lab/crl/root.crl"]}]=])
refused("crl distribution point" invalid_bootstrap_file
    "/cas/0/crl/distribution_points/0" "${j}")
variant(j cas 0 rsa_padding [=["oaep"]=])
refused("rsa padding" invalid_bootstrap_file "/cas/0/rsa_padding" "${j}")
variant(j profiles [=[["profiles/root-ca.yaml"]]=])
refused("profile not json" invalid_bootstrap_file "/profiles/0" "${j}")
variant(j profiles [=[[{"description": "no id"}]]=])
refused("inline profile without id" invalid_bootstrap_file "/profiles/0"
    "${j}")
variant(j profiles [=[["profiles/missing.json"]]=])
refused("profile file missing" invalid_bootstrap_file "/profiles/0" "${j}")
variant(j cas 1 [=[{"id": "err-root", "cn": "Twice", "key": "ec-p256", "validity": "P1Y"}]=])
refused("duplicate id" invalid_bootstrap_file "/cas/1/id" "${j}")
variant(j cas 0 parent [=["no-such-ca"]=])
refused("unknown parent" invalid_bootstrap_file "/cas/0/parent" "${j}")
variant(j server "[]")
refused("server type" invalid_bootstrap_file "/server" "${j}")

# --- issued_with, profiles and policies of a CA --------------------------------
# the old member profile is gone: issued_with and profiles replace it
variant(j cas 0 profile [=["root-ca"]=])
refused("ca profile" invalid_bootstrap_file "/cas/0/profile" "${j}")
variant(j cas 0 issued_with [=["Root-CA"]=])
refused("issued_with pattern" invalid_bootstrap_file "/cas/0/issued_with" "${j}")
variant(j cas 0 issued_with [=[["root-ca"]]=])
refused("issued_with array" invalid_bootstrap_file "/cas/0/issued_with" "${j}")
variant(j cas 0 profiles [=["root-ca"]=])
refused("profiles string" invalid_bootstrap_file "/cas/0/profiles" "${j}")
variant(j cas 0 profiles [=[["tls-server", "root-ca", "tls-server"]]=])
refused("profiles not unique" invalid_bootstrap_file "/cas/0/profiles" "${j}")
variant(j cas 0 profiles [=[["tls_server"]]=])
refused("profiles id" invalid_bootstrap_file "/cas/0/profiles/0" "${j}")
variant(j cas 0 policies [=[{"lab-names": true}]=])
refused("policies object" invalid_bootstrap_file "/cas/0/policies" "${j}")
variant(j cas 0 policies [=[["lab-names", "lab-names"]]=])
refused("policies not unique" invalid_bootstrap_file "/cas/0/policies" "${j}")
# every id names a profile or policy of the file or of the database
variant(j cas 0 issued_with [=["no-such-profile"]=])
refused("issued_with unknown" unknown_reference "/cas/0/issued_with" "${j}")
if(NOT detail MATCHES "no-such-profile")
  fail("issued_with unknown: the id is not named: ${detail}")
endif()
variant(j profiles [=[["profiles/tls-server.json"]]=])
string(JSON j SET "${j}" cas 0 profiles [=[["tls-server", "no-such-profile"]]=])
refused("profiles unknown" unknown_reference "/cas/0/profiles/1" "${j}")
# a policy id is no profile id (and the other way round)
variant(j profiles [=[["profiles/tls-server.json"]]=])
string(JSON j SET "${j}" cas 0 policies [=[["tls-server"]]=])
refused("policies unknown" unknown_reference "/cas/0/policies/0" "${j}")
variant(j policies [=[["policies/lab-names.json"]]=])
string(JSON j SET "${j}" cas 0 profiles [=[["lab-names"]]=])
refused("policy as profile" unknown_reference "/cas/0/profiles/0" "${j}")
# a retired profile or policy of the database is refused at the pointer of
# its id, with the code of assign (BTD-232); bootstrap does not retire, so
# cli_fixture does
variant(j profiles [=[["profiles/tls-server.json"]]=])
string(JSON j SET "${j}" policies [=[["policies/lab-names.json"]]=])
bs_write(retire-docs.json "${j}")
bxc("retire: store the documents" 0 bootstrap --file "${file}" --db "${DB}")
fixture("retire tls-server" retire profile tls-server)
fixture("retire lab-names" retire policy lab-names)
variant(j cas 0 profiles [=[["tls-server"]]=])
refused("profiles retired" document_retired "/cas/0/profiles/0" "${j}")
if(NOT detail MATCHES "tls-server")
  fail("profiles retired: the id is not named: ${detail}")
endif()
variant(j cas 0 policies [=[["lab-names"]]=])
refused("policies retired" document_retired "/cas/0/policies/0" "${j}")
bs_write(retired-plan.json "${j}")
bxc("policies retired, plan" 0 bootstrap --file "${file}" --db "${DB}" --plan)
one_doc("policies retired, plan" "${out}" cli-result r)
bs_entry("${r}" ca err-root e)
jget(act "${e}" action)
jget(code "${e}" error code)
jget(det "${e}" error detail)
if(NOT act STREQUAL "error" OR NOT code STREQUAL "document_retired" OR
   NOT det MATCHES "^/cas/0/policies/0: ")
  fail("policies retired, plan: '${act}' '${code}' '${det}':
${e}")
endif()
# issued_with records how the CA was issued; a profile retired since then
# stays a valid record
variant(j cas 0 issued_with [=["tls-server"]=])
bs_write(retired-issued-with.json "${j}")
bxc("issued_with retired" 0 bootstrap --file "${file}" --db "${DB}" --plan)

# --plan: an error entry of the CA, exit code 0
variant(j cas 0 policies [=[["no-such-policy"]]=])
bs_write(unknown-plan.json "${j}")
bxc("policies unknown, plan" 0 bootstrap --file "${file}" --db "${DB}" --plan)
one_doc("policies unknown, plan" "${out}" cli-result r)
bs_entry("${r}" ca err-root e)
jget(act "${e}" action)
jget(code "${e}" error code)
jget(det "${e}" error detail)
if(NOT act STREQUAL "error" OR NOT code STREQUAL "unknown_reference" OR
   NOT det MATCHES "^/cas/0/policies/0: ")
  fail("policies unknown, plan: '${act}' '${code}' '${det}':
${e}")
endif()

# --- DN errors name the JSON pointer, not --subject ------------------------------
# a new CA (err-dn) so that the subject is parsed; the error comes before
# anything is written
set(dnca [=[{"id": "err-dn", "cn": "Err DN", "key": "ec-p256", "validity": "P1Y"}]=])
foreach(c "subject|subject|{\"O\": \"\"}|the value of O is empty"
    "dn|dn|\"CN=Err DN,XX=y\"|unknown attribute type 'XX'"
    "dn|dn|[[{\"type\": \"XX\", \"value\": \"y\"}], [{\"type\": \"CN\", \"value\": \"Err DN\"}]]|unknown attribute type 'XX'")
  string(REPLACE "|" ";" c "${c}")
  list(GET c 0 member)
  list(GET c 1 ptr)
  list(GET c 2 value)
  list(GET c 3 why)
  string(JSON ca SET "${dnca}" ${member} "${value}")
  if(member STREQUAL "dn")
    string(JSON ca REMOVE "${ca}" cn)
  endif()
  variant(j cas 1 "${ca}")
  refused("dn error ${member} ${value}" invalid_subject "/cas/1/${ptr}" "${j}")
  if(detail MATCHES "--subject" OR NOT detail MATCHES "is no RFC 4514" OR
     NOT detail MATCHES "${why}")
    fail("dn error ${member}: the detail '${detail}' names --subject or not the reason '${why}'")
  endif()
endforeach()

# --- --text of a real run: one line per object with its database id ------------
set(TDB "${WORK}/text.xdb")
bs_write(text.json "${BASE}")
bxc("text run" 0 bootstrap --file "${file}" --db "${TDB}" --text)
if(NOT out MATCHES "ca err-root: create, id [0-9]+" OR out MATCHES "^{")
  fail("text run: no line 'ca err-root: create, id <n>':
${out}")
endif()
bxc("text run again" 0 bootstrap --file "${file}" --db "${TDB}" --text)
if(NOT out MATCHES "ca err-root: keep, id [0-9]+")
  fail("text run again: no line 'ca err-root: keep, id <n>':
${out}")
endif()

# --- CRL validity: whole days of at least P1D (BTD-211) ------------------------
foreach(v PT12H P1M P1DT1H)
  variant(j cas 0 crl "{\"validity\": \"${v}\"}")
  refused("crl validity ${v}" invalid_validity "/cas/0/crl/validity" "${j}")
endforeach()

# --- secrets -------------------------------------------------------------------
variant(j database password [=["Geheim-2026"]=])
refused("literal db password" invalid_bootstrap_file "/database/password"
    "${j}")
if(detail MATCHES "Geheim")
  fail("the literal secret is in the error: ${detail}")
endif()
variant(j cas 0 key_password [=["Geheim-2026"]=])
refused("literal key password" invalid_bootstrap_file "/cas/0/key_password"
    "${j}")
variant(j roles [=[[{"name": "ca-admin", "api_keys": ["Geheim-2026"]}]]=])
refused("literal api key" invalid_bootstrap_file "/roles/0/api_keys/0" "${j}")
variant(j database password [=["env:BXC_BS_NOT_SET"]=])
refused("unset env" missing_password "/database/password" "${j}")
variant(j cas 0 key_password [=["file:/nonexistent/bxc-key-pw"]=])
refused("unreadable file" missing_password "/cas/0/key_password" "${j}")
variant(j database password [=["op://BxC-Lab/bxc-pki-db/password"]=])
refused("op reference" unresolved_secret_reference "/database/password"
    "${j}")
if(NOT detail MATCHES "op run" OR NOT detail MATCHES "op inject" OR
   NOT detail MATCHES "env:")
  fail("op reference: the route is not named: ${detail}")
endif()
# an unresolvable reference on a fresh database creates no database
bs_write(fresh-op.json "${j}")
bxc("op reference, fresh" 1 bootstrap --file "${file}" --db "${WORK}/fresh.xdb")
expect_error("op reference, fresh" unresolved_secret_reference)
if(EXISTS "${WORK}/fresh.xdb")
  fail("op reference: a database was created")
endif()
# op:// in an element of a later phase is no error: it is not used now
variant(j roles [=[[{"name": "ca-admin", "api_keys": ["op://BxC-Lab/admin/key"]}]]=])
bs_write(roles-op.json "${j}")
bxc("op in roles" 0 bootstrap --file "${file}" --db "${DB}")
one_doc("op in roles" "${out}" cli-result r)
bs_counts("op in roles" "${r}" 0 1 0 1)

# the fork contains no 1Password library
if(LDD AND EXISTS "${LDD}")
  execute_process(COMMAND "${LDD}" "${BXC_PKI}" OUTPUT_VARIABLE l
    ERROR_VARIABLE le RESULT_VARIABLE lr)
  file(APPEND "${TRANSCRIPT}" "### ldd bxc-pki\nexit ${lr}\n${l}${le}\n")
  string(TOLOWER "${l}" l)
  if(NOT lr EQUAL 0 OR NOT l MATCHES "libcrypto")
    fail("ldd bxc-pki failed (${lr}): ${l}${le}")
  endif()
  if(l MATCHES "1password|onepassword|libop[._-]|op-sdk")
    fail("bxc-pki links a 1Password library:\n${l}")
  endif()
else()
  fail("ldd is needed for the link check (LDD)")
endif()

# --- own key passwords: env:, also for signing below the CA -------------------
set(ENV{BXC_BS_KEY_PW} "Own-Key-Pw-166")
string(JSON j SET "${BASE}" cas 1 [=[{"id": "own-root", "cn": "Own Root", "key": "ec-p256", "validity": "P5Y", "key_password": "env:BXC_BS_KEY_PW"}]=])
string(JSON j SET "${j}" cas 2 [=[{"id": "own-issuing", "parent": "own-root", "cn": "Own Issuing", "key": "ec-p256", "validity": "P2Y", "path_len": 0}]=])
bs_write(own.json "${j}")
set(OWN "${file}")
bxc("own key password" 0 bootstrap --file "${OWN}" --db "${DB}")
one_doc("own key password" "${out}" cli-result r)
bs_counts("own key password" "${r}" 2 1 0 0)
sql("own pass" "SELECT p.ownPass FROM private_keys p JOIN items i ON i.id=p.item WHERE i.name='Own Root'")
if(NOT out MATCHES "^1")
  fail("own-root: the key has no password of its own (ownPass '${out}')")
endif()
bxc("own key password again" 0 bootstrap --file "${OWN}" --db "${DB}")
one_doc("own key password again" "${out}" cli-result r)
bs_counts("own key password again" "${r}" 0 3 0 0)

# --- conflicts with existing CAs ------------------------------------------------
set(new [=[{"id": "err-new", "cn": "Err New", "key": "ec-p256", "validity": "P1Y"}]=])
foreach(c "key|\"ec-p384\"" "cn|\"Err Root 2\"" "path_len|1"
    "key_usage|[\"keyCertSign\", \"cRLSign\", \"digitalSignature\"]"
    "validity|\"P6Y\"")
  string(REPLACE "|" ";" c "${c}")
  list(GET c 0 member)
  list(GET c 1 value)
  # a new CA before the conflicting one: nothing of the file is written
  string(JSON old GET "${BASE}" cas 0)
  string(JSON old SET "${old}" ${member} "${value}")
  string(JSON j SET "${BASE}" cas 0 "${new}")
  string(JSON j SET "${j}" cas 1 "${old}")
  refused("conflict ${member}" bootstrap_conflict "/cas/1/${member}" "${j}")
  if(NOT detail MATCHES "err-root" OR NOT detail MATCHES "${member}")
    fail("conflict ${member}: the detail does not name the object and the member: ${detail}")
  endif()
  audit_entries(a)
  audit_has("${a}" "\"action\":\"bootstrap\\.apply\".*\"error_code\":\"bootstrap_conflict\".*\"result\":\"failure\"" "conflict failure entry")
endforeach()

# an error in the middle of the run (after a CA was created) rolls back
# the whole run: profile_signature_mismatch of an RSA-only profile
file(READ "${BS}/profiles/root-ca.json" p)
string(JSON p REMOVE "${p}" signature ec)
string(JSON p SET "${p}" id [=["rsa-only"]=])
string(JSON j SET "${BASE}" profiles "[]")
string(JSON j SET "${j}" profiles 0 "${p}")
string(JSON j SET "${j}" cas 1 [=[{"id": "err-mid", "cn": "Err Mid", "key": "ec-p256", "validity": "P1Y", "profiles": ["rsa-only"]}]=])
count_items(certificate nc1)
count_items(key nk1)
refused("error mid-run" profile_signature_mismatch "/cas/1" "${j}")
count_items(certificate nc2)
count_items(key nk2)
sql("rsa-only stored?" "SELECT COUNT(*) FROM profiles WHERE name='rsa-only'")
if(NOT nc1 EQUAL nc2 OR NOT nk1 EQUAL nk2 OR NOT out MATCHES "^0")
  fail("error mid-run: partial hierarchy (certificates ${nc1} -> ${nc2}, keys ${nk1} -> ${nk2}, profile rows '${out}')")
endif()
audit_entries(a)
audit_has("${a}" "\"action\":\"profile\\.assign\".*\"error_code\":\"profile_signature_mismatch\".*\"result\":\"failure\"" "assign failure entry")
audit_has("${a}" "\"action\":\"bootstrap\\.apply\".*\"error_code\":\"profile_signature_mismatch\".*\"result\":\"failure\"" "bootstrap failure entry")

# --- skipped: parent external (offline root, Phase 4) --------------------------
string(JSON j SET "${BASE}" cas 1 [=[{"id": "offline-issuing", "parent": "external", "cn": "Offline Issuing", "key": "ec-p256", "validity": "P1Y"}]=])
string(JSON j SET "${j}" cas 2 [=[{"id": "below-offline", "parent": "offline-issuing", "cn": "Below Offline", "key": "ec-p256", "validity": "P1Y"}]=])
bs_write(external.json "${j}")
bxc("parent external" 0 bootstrap --file "${file}" --db "${DB}")
one_doc("parent external" "${out}" cli-result r)
bs_counts("parent external" "${r}" 0 1 0 2)
bs_entry("${r}" ca offline-issuing e)
jget(act "${e}" action)
if(NOT act STREQUAL "skip")
  fail("parent external: offline-issuing '${act}':\n${e}")
endif()

# --- not supported in this build: rsa_padding pss ------------------------------
string(JSON j SET "${BASE}" cas 1 [=[{"id": "pss-root", "cn": "PSS Root", "key": "rsa-2048", "rsa_padding": "pss", "validity": "P1Y"}]=])
refused("rsa pss" not_supported "/cas/1/rsa_padding" "${j}")
# --plan reports it as an error entry and still lists everything
bs_write(pss.json "${j}")
bxc("rsa pss plan" 0 bootstrap --file "${file}" --db "${DB}" --plan)
one_doc("rsa pss plan" "${out}" cli-result r)
bs_entry("${r}" ca pss-root e)
jget(act "${e}" action)
jget(code "${e}" error code)
if(NOT act STREQUAL "error" OR NOT code STREQUAL "not_supported")
  fail("rsa pss plan: '${act}' '${code}':\n${e}")
endif()
