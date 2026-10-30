# The shared file helper lib/staged_file.h through the command line
# (BTD-42; rules 7, 10 and 11 of PLAN.md 8.4) with fault injection: the
# test build bxc-pki-faults makes a step of the file output fail
# (BXC_PKI_FAULT=fail:<step>:<file>) or ends the process there like a
# killed run (kill:<step>:<file>).
#  - a failed create, write or sync is before the database commit: the
#    command fails, nothing is stored, no file and no temporary file stay;
#  - a failed publish is after the commit: the error publish_failed names
#    the stored object (id, name), the target file does not exist, an
#    object.export failure entry follows;
#  - a run killed while writing a replacement (--force) or before the
#    rename leaves the old CRL file complete and unchanged, no partial
#    file under the target name.

include("${LIB}")

set(D "${WORK}/f")
file(MAKE_DIRECTORY "${D}")

# fx(<label> <code> <fault> <args>...): bxc-pki-faults with a fault
function(fx label code fault)
  set(ENV{BXC_PKI_FAULT} "${fault}")
  execute_process(COMMAND "${BXC_PKI_FAULTS}" ${ARGN}
    WORKING_DIRECTORY "${WORK}" INPUT_FILE /dev/null
    RESULT_VARIABLE r OUTPUT_VARIABLE o ERROR_VARIABLE e TIMEOUT 60)
  unset(ENV{BXC_PKI_FAULT})
  string(REPLACE ";" " " cmd "${ARGN}")
  file(APPEND "${TRANSCRIPT}"
    "### ${label}\n$ BXC_PKI_FAULT=${fault} bxc-pki-faults ${cmd}\nexit ${r}\n--- stdout\n${o}--- stderr\n${e}\n")
  if(NOT r STREQUAL "${code}")
    fail("${label}: expected exit code ${code}, got '${r}':\nstdout: ${o}\nstderr: ${e}")
  endif()
  set(out "${o}" PARENT_SCOPE)
  set(err "${e}" PARENT_SCOPE)
endfunction()

# no file of the directory, hidden temporary files included
function(dir_listing var)
  file(GLOB l LIST_DIRECTORIES false "${D}/*" "${D}/.*")
  list(SORT l)
  set(${var} "${l}" PARENT_SCOPE)
endfunction()

bxc("init" 0 init --db "${DB}" ${PW} --cn "F Root" --key ec-p256)

# --- before the commit: nothing stored, nothing written --------------------
foreach(step create write sync)
  count_items(crl before)
  fx("fail ${step}" 1 "fail:${step}:F_Root.crl" crl --ca "F Root" --db "${DB}"
      ${PW} --out f --layout certstrap)
  expect_error("fail ${step}" write_failed)
  count_items(crl after)
  dir_listing(l)
  if(NOT before EQUAL after OR l)
    fail("failed ${step}: CRLs ${before} -> ${after}, files: ${l}")
  endif()
endforeach()
# a key file that fails: the generated key is not stored either
count_items(key before)
fx("fail key write" 1 "fail:write:k1.key" request-cert --db "${DB}" ${PW} --cn k1
    --out f --layout certstrap --key-unencrypted)
expect_error("fail key write" write_failed)
count_items(key after)
dir_listing(l)
if(NOT before EQUAL after OR l)
  fail("failed key file: keys ${before} -> ${after}, files: ${l}")
endif()

# --- after the commit: the error names the stored object ------------------------
count_items(crl before)
fx("fail publish" 1 "fail:publish:F_Root.crl" crl --ca "F Root" --db "${DB}"
    ${PW} --out f --layout certstrap)
expect_error("fail publish" publish_failed)
count_items(crl after)
math(EXPR want "${before} + 1")
if(NOT after EQUAL want)
  fail("publish failed: the CRL must stay stored (${before} -> ${after})")
endif()
bxc("crls" 0 list --db "${DB}" ${PW} --type crl)
string(STRIP "${out}" l)
math(EXPR last "${after} - 1")
string(JSON crl_id GET "${l}" items ${last} id)
if(NOT detail MATCHES "crl ${crl_id} 'F Root'" OR NOT detail MATCHES "F_Root\\.crl")
  fail("publish_failed does not name the stored CRL ${crl_id}: ${detail}")
endif()
dir_listing(l)
if(l)
  fail("publish failed: files stay: ${l}")
endif()

# --- a killed run leaves an old file complete ---------------------------------------
bxc("first file" 0 crl --ca "F Root" --db "${DB}" ${PW} --out f --layout certstrap)
file(SHA256 "${D}/F_Root.crl" good)
foreach(step write sync publish)
  fx("killed at ${step}" 137 "kill:${step}:F_Root.crl" crl --ca "F Root"
      --db "${DB}" ${PW} --out f --layout certstrap --force)
  file(SHA256 "${D}/F_Root.crl" now)
  if(NOT now STREQUAL good)
    fail("a run killed at ${step} changed F_Root.crl")
  endif()
  openssl_run(t crl -in f/F_Root.crl -noout)
endforeach()
# what a killed run can leave is a hidden temporary file, never the target
dir_listing(l)
foreach(f IN LISTS l)
  get_filename_component(n "${f}" NAME)
  if(NOT n STREQUAL "F_Root.crl" AND NOT n MATCHES "^\\.F_Root\\.crl\\.bxc-tmp-[0-9a-f]+$")
    fail("unexpected file after killed runs: ${n}")
  endif()
endforeach()
# a new CRL without a target file: a killed run before the rename leaves none
fx("killed before rename, new file" 137 "kill:publish:F_Root-" crl --ca "F Root"
    --db "${DB}" ${PW} --out f)
file(GLOB l "${D}/F_Root-*.crl")
if(l)
  fail("a run killed before the rename left ${l}")
endif()

# --- audit ------------------------------------------------------------------------
audit_entries(a)
audit_has("${a}" "\"action\":\"object\\.export\".*\"channel\":\"cli\".*\"error_code\":\"write_failed\".*\"file\":\"f/F_Root\\.crl\".*\"result\":\"failure\"" "publish failure entry")
