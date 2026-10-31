# Shared functions of the bootstrap tests (BTD-166), included after
# cli_lib.cmake by cli_bootstrap*.cmake. The test data (a lab-like file
# with three hierarchies, its profiles and policies) is copied to
# ${BS}; files written there resolve their relative profile and policy
# paths against it.

set(BS "${WORK}/bs")
file(COPY "${CMAKE_CURRENT_LIST_DIR}/data/bootstrap/" DESTINATION "${BS}")
set(LAB "${BS}/lab.json")
file(READ "${LAB}" lab)
set(CAS ot-rsa-root ot-rsa-issuing ot-p256-root ot-p256-issuing pqc-root
    pqc-issuing)

# bs_write(<name> <json>): ${BS}/<name>, the path in ${file}
function(bs_write name json)
  file(WRITE "${BS}/${name}" "${json}\n")
  set(file "${BS}/${name}" PARENT_SCOPE)
endfunction()

# bs_entry(<result> <kind> <bootstrap id> <var>): the entry of that object
# in the member bootstrap.entries
function(bs_entry doc kind bid var)
  jlen(n "${doc}" bootstrap entries)
  if(n GREATER 0)
    math(EXPR last "${n} - 1")
    foreach(i RANGE ${last})
      string(JSON k GET "${doc}" bootstrap entries ${i} kind)
      string(JSON b GET "${doc}" bootstrap entries ${i} bootstrap_id)
      if(k STREQUAL kind AND b STREQUAL bid)
        string(JSON e GET "${doc}" bootstrap entries ${i})
        set(${var} "${e}" PARENT_SCOPE)
        return()
      endif()
    endforeach()
  endif()
  fail("no ${kind} entry '${bid}' in the result:\n${doc}")
endfunction()

# bs_actions(<result> <var>): "kind:bootstrap_id=action" of every entry
function(bs_actions doc var)
  jlen(n "${doc}" bootstrap entries)
  set(l "")
  if(n GREATER 0)
    math(EXPR last "${n} - 1")
    foreach(i RANGE ${last})
      string(JSON k GET "${doc}" bootstrap entries ${i} kind)
      string(JSON b GET "${doc}" bootstrap entries ${i} bootstrap_id)
      string(JSON a GET "${doc}" bootstrap entries ${i} action)
      list(APPEND l "${k}:${b}=${a}")
    endforeach()
  endif()
  set(${var} "${l}" PARENT_SCOPE)
endfunction()

# bs_skipped(<result> <var>): the element pointers of bootstrap.skipped
function(bs_skipped doc var)
  jlen(n "${doc}" bootstrap skipped)
  set(l "")
  if(n GREATER 0)
    math(EXPR last "${n} - 1")
    foreach(i RANGE ${last})
      string(JSON e GET "${doc}" bootstrap skipped ${i} element)
      list(APPEND l "${e}")
    endforeach()
  endif()
  set(${var} "${l}" PARENT_SCOPE)
endfunction()

# bs_counts(<label> <result> <created> <kept> <updated> <skipped>)
function(bs_counts label doc c k u s)
  foreach(pair "created|${c}" "kept|${k}" "updated|${u}" "skipped|${s}")
    string(REPLACE "|" ";" p "${pair}")
    list(GET p 0 name)
    list(GET p 1 want)
    jget(v "${doc}" bootstrap counts ${name})
    if(NOT v STREQUAL "${want}")
      fail("${label}: counts.${name} is '${v}', expected ${want}:\n${doc}")
    endif()
  endforeach()
endfunction()

# db_state(<var>): what a run must not change: the object list (ids,
# names, types) and the settings rows
function(db_state var)
  bxc("state list" 0 list --db "${DB}" ${PW})
  set(s "${out}")
  sql("state settings" "SELECT key_, value FROM settings ORDER BY key_")
  set(${var} "${s}${out}" PARENT_SCOPE)
endfunction()

# audit_count(<var>): number of audit entries of ${DB}
function(audit_count var)
  sql("audit count" "SELECT COUNT(*) FROM audit_log")
  string(STRIP "${out}" n)
  set(${var} "${n}" PARENT_SCOPE)
endfunction()
