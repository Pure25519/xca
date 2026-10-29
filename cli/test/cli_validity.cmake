# Rule 6 of the certstrap triage in bxc-pki (BTD-41, BTD-51): --validity
# as ISO 8601 duration (P20Y), --not-before/--not-after (RFC 3339) and
# --backdate; a request beyond the CA lifetime is capped and the cap is
# reported in the JSON result (validity_capped, requested_not_after),
# never silently; invalid durations and dates are rejected.

include("${LIB}")

find_program(DATE date)
# epoch(<rfc3339> <var>)
function(epoch ts var)
  execute_process(COMMAND "${DATE}" -u -d "${ts}" +%s OUTPUT_VARIABLE e
    RESULT_VARIABLE r)
  if(NOT r EQUAL 0)
    fail("date -d ${ts} failed")
  endif()
  string(STRIP "${e}" e)
  set(${var} "${e}" PARENT_SCOPE)
endfunction()

string(TIMESTAMP year "%Y" UTC)
math(EXPR y2 "${year} + 2")
math(EXPR y1 "${year} + 1")

# --- root of two years, an intermediate of P20Y gets capped -------------
bxc("root P2Y" 0 init --db "${DB}" ${PW} --cn "Short Root" --validity P2Y)
one_doc("root P2Y" "${out}" cli-result r)
object_doc("${r}" certificate root)
string(JSON root_nb GET "${root}" not_before)
string(JSON root_na GET "${root}" not_after)
if(DATE)
  epoch("${root_nb}" nb)
  epoch("${root_na}" na)
  math(EXPR days "(${na} - ${nb}) / 86400")
  if(days LESS 730 OR days GREATER 731)
    fail("P2Y root: ${days} days (${root_nb} .. ${root_na})")
  endif()
endif()

bxc("intermediate P20Y" 0 init --db "${DB}" ${PW} --cn "Capped Issuing"
    --parent "Short Root" --validity P20Y)
one_doc("intermediate P20Y" "${out}" cli-result r)
object_doc("${r}" certificate int)
string(JSON capped GET "${int_entry}" validity_capped)
string(JSON requested GET "${int_entry}" requested_not_after)
string(JSON int_na GET "${int}" not_after)
if(NOT capped OR NOT int_na STREQUAL root_na)
  fail("P20Y under P2Y: capped '${capped}', not_after ${int_na}, root ${root_na}")
endif()
if(NOT requested MATCHES "^20[0-9][0-9]-" OR requested STREQUAL int_na)
  fail("requested_not_after '${requested}'")
endif()
if(DATE)
  epoch("${requested}" rq)
  math(EXPR years "(${rq} - ${nb}) / 86400 / 365")
  if(NOT years EQUAL 20)
    fail("requested_not_after is not 20 years after the start: ${requested}")
  endif()
endif()

# the audit entry says the same (BTD-51)
audit_entries(lines)
string(REGEX MATCH "[^\n]*\"name\":\"Capped Issuing\"[^\n]*certificate\\.issue[^\n]*|[^\n]*certificate\\.issue[^\n]*\"name\":\"Capped Issuing\"[^\n]*" e "${lines}")
string(JSON ac GET "${e}" params validity_capped)
string(JSON ar GET "${e}" params requested_not_after)
if(NOT ac OR NOT ar STREQUAL requested)
  fail("audit entry: capped ${ac}, requested ${ar} vs ${requested}")
endif()

# --- explicit dates, also with an offset -----------------------------------
bxc("req" 0 request-cert --db "${DB}" ${PW} --cn dated)
bxc("not-before/not-after" 0 sign dated --db "${DB}" ${PW} --ca "Short Root"
    --not-before ${y1}-06-01T00:00:00Z --not-after ${y1}-09-01T12:30:00+02:00)
one_doc("dates" "${out}" cli-result r)
object_doc("${r}" certificate c)
string(JSON a GET "${c}" not_before)
string(JSON b GET "${c}" not_after)
string(JSON capped GET "${c_entry}" validity_capped)
if(NOT a STREQUAL "${y1}-06-01T00:00:00Z" OR
   NOT b STREQUAL "${y1}-09-01T10:30:00Z" OR capped)
  fail("explicit dates: ${a} .. ${b}, capped ${capped}")
endif()

# --- --not-after beyond the CA: capped and reported -------------------------
math(EXPR y30 "${year} + 30")
bxc("req2" 0 request-cert --db "${DB}" ${PW} --cn late)
bxc("not-after beyond" 0 sign late --db "${DB}" ${PW} --ca "Short Root"
    --not-after ${y30}-01-01T00:00:00Z)
one_doc("not-after beyond" "${out}" cli-result r)
object_doc("${r}" certificate c)
string(JSON capped GET "${c_entry}" validity_capped)
string(JSON rq GET "${c_entry}" requested_not_after)
string(JSON b GET "${c}" not_after)
if(NOT capped OR NOT rq STREQUAL "${y30}-01-01T00:00:00Z" OR NOT b STREQUAL root_na)
  fail("--not-after beyond the CA: capped ${capped}, requested ${rq}, end ${b}")
endif()

# --- backdate --------------------------------------------------------------
bxc("req3" 0 request-cert --db "${DB}" ${PW} --cn backdated)
string(TIMESTAMP now "%s" UTC)
bxc("backdate" 0 sign backdated --db "${DB}" ${PW} --ca "Short Root"
    --backdate PT2H --validity P30D)
one_doc("backdate" "${out}" cli-result r)
object_doc("${r}" certificate c)
string(JSON a GET "${c}" not_before)
string(JSON b GET "${c}" not_after)
if(DATE)
  epoch("${a}" ea)
  epoch("${b}" eb)
  math(EXPR back "${now} - ${ea}")
  math(EXPR len "${eb} - ${ea}")
  if(back LESS 7190 OR back GREATER 7300 OR NOT len EQUAL 2592000)
    fail("--backdate PT2H --validity P30D: ${a} .. ${b} (back ${back}s)")
  endif()
endif()

# default validity of sign: P1Y, capped by the root of two years? no
bxc("req4" 0 request-cert --db "${DB}" ${PW} --cn default-validity)
bxc("default" 0 sign default-validity --db "${DB}" ${PW} --ca "Short Root")
one_doc("default" "${out}" cli-result r)
object_doc("${r}" certificate c)
string(JSON a GET "${c}" not_before)
string(JSON b GET "${c}" not_after)
if(DATE)
  epoch("${a}" ea)
  epoch("${b}" eb)
  math(EXPR d "(${eb} - ${ea}) / 86400")
  if(d LESS 365 OR d GREATER 366)
    fail("default validity: ${d} days")
  endif()
endif()

# --- invalid input ------------------------------------------------------
foreach(case
    "invalid_value|--validity;P" "invalid_value|--validity;PT"
    "invalid_value|--validity;P1.5Y" "invalid_value|--validity;-P1Y"
    "invalid_value|--validity;P1Y2" "invalid_value|--validity;1Y"
    "invalid_value|--not-after;2030-01-01"
    "invalid_value|--not-after;2030-01-01T00:00Z"
    "invalid_value|--not-after;2030-13-01T00:00:00Z"
    "invalid_value|--not-before;2030-01-01T00:00:00.5Z"
    "invalid_value|--backdate;yesterday"
    "invalid_validity|--not-before;${y2}-01-01T00:00:00Z;--not-after;${y1}-01-01T00:00:00Z")
  string(REPLACE "|" ";" parts "${case}")
  list(GET parts 0 code)
  list(SUBLIST parts 1 -1 args)
  bxc("${code}: ${args}" 2 sign late --db "${DB}" ${PW} --ca "Short Root" ${args})
  expect_error("${code}: ${args}" ${code})
endforeach()
message(STATUS "bxc-pki validity ok")
