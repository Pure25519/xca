# The clean-up of stale temporary files is reported also when the command
# fails later (BTD-213 (3)): a temporary file of a killed earlier run lies
# in the output directory, a CRL export removes it while it stages its own
# file, and then the write of the CRL fails. The error object lists the
# warning stale_temp_removed, as the result of a successful run does.

include("${LIB}")

set(D "${WORK}/f")
file(MAKE_DIRECTORY "${D}")

bxc("init" 0 init --db "${DB}" ${PW} --cn "S Root" --key ec-p256)

# a temporary file of a killed run, an hour old
set(stale "${D}/.old.crl.bxc-tmp-0123456789abcdef")
file(WRITE "${stale}" "left over\n")
execute_process(COMMAND touch -d "-1 hour" "${stale}" RESULT_VARIABLE r)
if(NOT r EQUAL 0)
  fail("touch the stale file: ${r}")
endif()

fx("fail write" 1 "fail:write:S_Root.crl" crl --ca "S Root" --db "${DB}"
    ${PW} --out f --layout certstrap)
expect_error("fail write" write_failed)
if(EXISTS "${stale}")
  fail("the stale temporary file was not removed")
endif()
string(REGEX MATCH "{\"code\"[^\n]*}" obj "${err}")
string(JSON warnings ERROR_VARIABLE jerr GET "${obj}" warnings)
if(jerr OR NOT warnings MATCHES "stale_temp_removed")
  fail("the error object does not report stale_temp_removed: ${obj}")
endif()
message(STATUS "fail write: stale_temp_removed in the error object")
