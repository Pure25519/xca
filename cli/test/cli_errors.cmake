# Rule 11 and the output streams of bxc-pki (BTD-41): a write error on a
# read-only database gives a non-zero exit and a JSON error naming the
# object and the cause, the result lists only objects actually written
# (nothing after a rollback, and the failure stays audited); stdout carries
# only results while messages go to stderr, also for xca; a failing OID
# initialisation stops every command before the database is touched.

include("${LIB}")

bxc("create" 0 init --db "${DB}" ${PW} --cn "Err Root")

# --- a failure after a written key: the key is rolled back, the result
#     lists nothing, the failure stays audited --------------------------
bxc("bad hash" 2 request-cert --db "${DB}" ${PW} --cn half --hash md2)
expect_error("bad hash" invalid_hash)
bxc("expired root" 0 init --db "${DB}" ${PW} --cn "Old Root"
    --not-before 2020-01-01T00:00:00Z --not-after 2021-01-01T00:00:00Z)
# the new key is written, then the certificate is rejected: the parent
# expired in 2021 (issuer_expired of the BTD-55 checks)
bxc("rejected after key" 1 init --db "${DB}" ${PW} --cn "Late Sub"
    --parent "Old Root")
expect_error("rejected after key" issuer_expired)
if(NOT detail MATCHES "certificate 'Late Sub' was not written to")
  fail("the error must name the object: ${detail}")
endif()
bxc("list after failure" 0 list --db "${DB}" ${PW})
if(out MATCHES "Late Sub")
  fail("a failed command left an object: ${out}")
endif()
audit_entries(lines)
if(NOT lines MATCHES "\"action\":\"certificate.issue\"[^\n]*\"error_code\":\"issuer_expired\"[^\n]*\"result\":\"failure\"")
  fail("the failure must stay audited after the rollback:\n${lines}")
endif()
if(lines MATCHES "\"action\":\"key.generate\"[^\n]*\"name\":\"Late Sub\"")
  fail("the rolled back key must not be audited as generated:\n${lines}")
endif()

# --- read-only database: write error names object and cause -------------
file(SIZE "${DB}" size_before)
execute_process(COMMAND id -u OUTPUT_VARIABLE uid)
string(STRIP "${uid}" uid)
set(as_user "")
if(uid STREQUAL "0")
  if(SETPRIV AND EXISTS "${SETPRIV}")
    # root ignores file modes: run as nobody, database owned by root
    set(as_user "${SETPRIV}" --reuid=65534 --regid=65534 --clear-groups)
    file(MAKE_DIRECTORY "${WORK}/nobody")
    file(CHMOD "${WORK}/nobody" DIRECTORY_PERMISSIONS OWNER_READ OWNER_WRITE
      OWNER_EXECUTE GROUP_READ GROUP_WRITE GROUP_EXECUTE WORLD_READ WORLD_WRITE
      WORLD_EXECUTE)
    file(CHMOD "${DB}" PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
  endif()
else()
  file(CHMOD "${DB}" PERMISSIONS OWNER_READ GROUP_READ WORLD_READ)
endif()
if(uid STREQUAL "0" AND NOT as_user)
  message(STATUS "root without setpriv: read-only database not tested")
else()
  execute_process(COMMAND ${as_user} env HOME=${WORK}/nobody
      XDG_CONFIG_HOME=${WORK}/nobody XDG_DATA_HOME=${WORK}/nobody
      "${BXC_PKI}" request-cert --db "${DB}" ${PW} --cn ro-dev
    WORKING_DIRECTORY "${WORK}" INPUT_FILE /dev/null
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err TIMEOUT 60)
  file(APPEND "${TRANSCRIPT}" "### read-only\nexit ${rc}\n--- stdout\n${out}--- stderr\n${err}\n")
  if(NOT rc EQUAL 1)
    fail("read-only database: exit ${rc}: ${out} ${err}")
  endif()
  string(REGEX REPLACE "^.*\n([^\n]+\n)$" "\\1" lasterr "${err}")
  set(err "${lasterr}")
  # SQLite says read-only (BTD-50)
  expect_error("read-only" read_only_database)
  if(NOT detail MATCHES "key 'ro-dev' was not written to" OR
     NOT detail MATCHES "readonly|read-only|read only")
    fail("read-only database: object or cause missing: ${detail}")
  endif()
  file(SIZE "${DB}" size_after)
  if(NOT size_before EQUAL size_after)
    fail("read-only database changed")
  endif()
  file(CHMOD "${DB}" PERMISSIONS OWNER_READ OWNER_WRITE)
endif()

# --- a number that is an id and a name is ambiguous (review of xca#54) ----
bxc("key named 1" 0 request-cert --db "${DB}" ${PW} --cn one --name 1)
bxc("numeric ambiguous" 1 show 1 --type key --db "${DB}" ${PW})
expect_error("numeric ambiguous" ambiguous_reference)
if(NOT detail MATCHES "key 1 'Err Root'" OR NOT detail MATCHES "key [0-9]+ '1'")
  fail("both candidates expected: ${detail}")
endif()

# --- a remote database is no file: it is opened, not refused -------------
bxc("remote db" 1 list --db "nobody@127.0.0.1:1/QPSQL7:nodb" ${PW})
split_lines("${err}" el)
list(POP_BACK el last)
string(JSON code GET "${last}" code)
if(code STREQUAL "no_database")
  fail("a remote database must not be checked as a file: ${err}")
endif()

# --- stdout clean: a warning and a failure -------------------------------
bxc("warns" 0 list --db "${DB}" --password "pass:${DB_PW}")
json_lines("warns" "${out}")
if(NOT err MATCHES "Warning")
  fail("expected a warning on stderr")
endif()
bxc("fails" 1 show nothing-here --db "${DB}" ${PW})
expect_error("fails" unknown_reference)

# xca without --json: information on stderr, stdout empty
xca_run("xca index" 0 --database "${DB}" ${PW} --index "${WORK}/index.txt")
if(NOT out STREQUAL "" OR NOT err MATCHES "Information: Index file written")
  fail("xca --index: stdout '${out}', stderr '${err}'")
endif()
xca_run("xca error" 1 --database "${DB}" ${PW} --crlgen no-such-ca)
if(NOT out STREQUAL "" OR NOT err MATCHES "Error:")
  fail("xca error: stdout '${out}', stderr '${err}'")
endif()

# --- OID initialisation failure: every command stops before the database --
foreach(dir "$ENV{XDG_DATA_HOME}/de.hohnstaedt.xca"
    "$ENV{XDG_DATA_HOME}/hohnstaedt.de/de.hohnstaedt.xca")
  file(MAKE_DIRECTORY "${dir}")
  file(WRITE "${dir}/oids.txt" "1.2.3.x.4: bxcBrokenOid: BxC broken OID\n")
endforeach()
set(fresh "${WORK}/fresh.xdb")
file(SIZE "${DB}" size_before)
foreach(cmd "init;--cn;oid" "request-cert;--cn;oid" "sign;x;--ca;y" "list"
    "show;1")
  bxc("oid failure ${cmd}" 1 ${cmd} --db "${fresh}" ${PW})
  expect_error("oid failure ${cmd}" oid_init_failed)
  bxc("oid failure ${cmd} existing" 1 ${cmd} --db "${DB}" ${PW})
  expect_error("oid failure ${cmd} existing" oid_init_failed)
endforeach()
if(EXISTS "${fresh}")
  fail("a command created the database despite the OID failure")
endif()
file(SIZE "${DB}" size_after)
if(NOT size_before EQUAL size_after)
  fail("a command changed the database despite the OID failure")
endif()
message(STATUS "bxc-pki errors ok")
