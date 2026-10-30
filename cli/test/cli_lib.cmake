# Shared functions of the bxc-pki CLI tests (BTD-41), included by every
# cli/test/<name>.cmake. Variables from cli/CMakeLists.txt: BXC_PKI, XCA,
# FIXTURE, SQL_EXEC, OPENSSL, SCRIPT, SETPRIV, LDD, WORK.
#
# Every run of bxc-pki is appended to ${WORK}/transcript.log (command,
# exit code, stdout, stderr); the directory is kept after a run as
# evidence and removed at the start of the next one.

cmake_minimum_required(VERSION 3.19)   # string(JSON)

file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}/home")
set(ENV{HOME} "${WORK}/home")
set(ENV{XDG_CONFIG_HOME} "${WORK}/home/.config")
set(ENV{XDG_DATA_HOME} "${WORK}/home/.local/share")
set(ENV{XDG_CACHE_HOME} "${WORK}/home/.cache")
set(ENV{NO_COLOR} 1)
unset(ENV{QT_QPA_PLATFORM})

set(DB "${WORK}/test.xdb")
set(DB_PW "Cli-Db-Pw-41")
set(ENV{BXC_DB_PW} "${DB_PW}")
set(PW --password env:BXC_DB_PW)
set(TRANSCRIPT "${WORK}/transcript.log")

function(fail msg)
  message(FATAL_ERROR "${msg}\n(transcript: ${TRANSCRIPT})")
endfunction()

# bxc(<label> <expected exit code> <args>...): bxc-pki <args> in ${WORK}
# with stdin from /dev/null (nothing may wait for input); stdout in
# ${out}, stderr in ${err}. Expected code "any" accepts every code; the
# real one is in ${rc}.
function(bxc label code)
  execute_process(COMMAND "${BXC_PKI}" ${ARGN}
    WORKING_DIRECTORY "${WORK}" INPUT_FILE /dev/null
    RESULT_VARIABLE r OUTPUT_VARIABLE o ERROR_VARIABLE e TIMEOUT 60)
  string(REPLACE ";" " " cmd "${ARGN}")
  file(APPEND "${TRANSCRIPT}"
    "### ${label}\n$ bxc-pki ${cmd}\nexit ${r}\n--- stdout\n${o}--- stderr\n${e}\n")
  if(NOT code STREQUAL "any" AND NOT r STREQUAL "${code}")
    fail("${label}: expected exit code ${code}, got '${r}':\nstdout: ${o}\nstderr: ${e}")
  endif()
  set(out "${o}" PARENT_SCOPE)
  set(err "${e}" PARENT_SCOPE)
  set(rc "${r}" PARENT_SCOPE)
endfunction()

# fx(<label> <code> <fault> <args>...): the test build bxc-pki-faults with
# BXC_PKI_FAULT=<fault> (cli/main.cpp: <mode>:<step>:<text>, several
# separated by ","); otherwise like bxc()
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

# listing(<dir> <var>): the files directly in dir, hidden ones included,
# sorted (no directories)
function(listing dir var)
  file(GLOB l LIST_DIRECTORIES false "${dir}/*" "${dir}/.*")
  list(SORT l)
  set(${var} "${l}" PARENT_SCOPE)
endfunction()

# xca_run(<label> <expected exit code> <args>...): xca --no-gui
function(xca_run label code)
  execute_process(COMMAND "${XCA}" --no-gui ${ARGN}
    WORKING_DIRECTORY "${WORK}" INPUT_FILE /dev/null
    RESULT_VARIABLE r OUTPUT_VARIABLE o ERROR_VARIABLE e TIMEOUT 60)
  string(REPLACE ";" " " cmd "${ARGN}")
  file(APPEND "${TRANSCRIPT}"
    "### ${label}\n$ xca --no-gui ${cmd}\nexit ${r}\n--- stdout\n${o}--- stderr\n${e}\n")
  if(NOT code STREQUAL "any" AND NOT r STREQUAL "${code}")
    fail("${label}: expected exit code ${code}, got '${r}':\nstdout: ${o}\nstderr: ${e}")
  endif()
  set(out "${o}" PARENT_SCOPE)
  set(err "${e}" PARENT_SCOPE)
endfunction()

# split_lines(<text> <var>): the non-empty lines of text as a list; a
# ';' inside a line is kept as @SEMI@ (restore with string(REPLACE))
function(split_lines text var)
  string(REPLACE ";" "@SEMI@" t "${text}")
  string(REGEX MATCHALL "[^\n]+" l "${t}")
  set(${var} "${l}" PARENT_SCOPE)
endfunction()

# one_doc(<label> <text> <schema kind> <var>): text is exactly one JSON
# document (one line) of that schema; it goes to <var>
function(one_doc label text kind var)
  split_lines("${text}" lines)
  list(LENGTH lines n)
  if(NOT n EQUAL 1 OR NOT text MATCHES "\n$")
    fail("${label}: expected one JSON line, got ${n}:\n${text}")
  endif()
  string(STRIP "${text}" doc)
  string(JSON schema ERROR_VARIABLE jerr GET "${doc}" schema)
  if(jerr)
    fail("${label}: no JSON document (${jerr}):\n${doc}")
  endif()
  if(NOT schema STREQUAL "urn:bxc-pki:schema:${kind}:v1")
    fail("${label}: schema '${schema}', expected ${kind}")
  endif()
  set(${var} "${doc}" PARENT_SCOPE)
endfunction()

# json_lines(<label> <text>): stdout is JSON Lines (or empty)
function(json_lines label text)
  split_lines("${text}" lines)
  foreach(line IN LISTS lines)
    string(REPLACE "@SEMI@" ";" line "${line}")
    string(JSON t ERROR_VARIABLE jerr TYPE "${line}")
    if(jerr OR NOT t STREQUAL "OBJECT")
      fail("${label}: stdout line is no JSON object:\n${line}")
    endif()
  endforeach()
endfunction()

# expect_error(<label> <code>): stdout is empty; the last line of ${err}
# is the error object with this code, the lines before it are messages
# (warnings), none of them JSON
macro(expect_error label code)
  if(NOT out STREQUAL "")
    fail("${label}: stdout must be empty on an error, got:\n${out}")
  endif()
  split_lines("${err}" _elines)
  list(LENGTH _elines _en)
  if(_en EQUAL 0)
    fail("${label}: no error object on stderr")
  endif()
  list(POP_BACK _elines _elast)
  foreach(_el IN LISTS _elines)
    if(_el MATCHES "^{")
      fail("${label}: more than one JSON document on stderr:\n${err}")
    endif()
  endforeach()
  string(REPLACE "@SEMI@" ";" _elast "${_elast}")
  one_doc("${label} (stderr)" "${_elast}\n" error _edoc)
  string(JSON _ecode GET "${_edoc}" code)
  if(NOT _ecode STREQUAL "${code}")
    fail("${label}: error code '${_ecode}', expected ${code}:\n${_edoc}")
  endif()
  string(JSON detail GET "${_edoc}" detail)
endmacro()

# result_objects(<doc> <var>): the "type:name" list of a cli-result
function(result_objects doc var)
  string(JSON n LENGTH "${doc}" objects)
  set(l "")
  if(n GREATER 0)
    math(EXPR last "${n} - 1")
    foreach(i RANGE ${last})
      string(JSON t GET "${doc}" objects ${i} type)
      string(JSON nm GET "${doc}" objects ${i} name)
      list(APPEND l "${t}:${nm}")
    endforeach()
  endif()
  set(${var} "${l}" PARENT_SCOPE)
endfunction()

# object_doc(<result doc> <type> <var>): the document of the first
# written object of that type
function(object_doc doc type var)
  string(JSON n LENGTH "${doc}" objects)
  math(EXPR last "${n} - 1")
  foreach(i RANGE ${last})
    string(JSON t GET "${doc}" objects ${i} type)
    if(t STREQUAL type)
      string(JSON d GET "${doc}" objects ${i} document)
      string(JSON entry GET "${doc}" objects ${i})
      set(${var} "${d}" PARENT_SCOPE)
      set(${var}_entry "${entry}" PARENT_SCOPE)
      return()
    endif()
  endforeach()
  fail("no ${type} in the result:\n${doc}")
endfunction()

# extension(<doc> <name> <var>): value of the extension with that
# OpenSSL short name, or NOTFOUND
function(extension doc name var)
  set(${var} NOTFOUND PARENT_SCOPE)
  string(JSON n LENGTH "${doc}" extensions)
  if(n EQUAL 0)
    return()
  endif()
  math(EXPR last "${n} - 1")
  foreach(i RANGE ${last})
    string(JSON en GET "${doc}" extensions ${i} name)
    if(en STREQUAL name)
      string(JSON v GET "${doc}" extensions ${i} value)
      set(${var} "${v}" PARENT_SCOPE)
      string(JSON c GET "${doc}" extensions ${i} critical)
      set(${var}_critical "${c}" PARENT_SCOPE)
      return()
    endif()
  endforeach()
endfunction()

# pem_file(<doc> <file>): the pem member of a document into a file
function(pem_file doc file)
  string(JSON pem GET "${doc}" pem)
  file(WRITE "${file}" "${pem}")
endfunction()

# openssl_run(<var> <args>...): output of the openssl program (merged)
function(openssl_run var)
  execute_process(COMMAND "${OPENSSL}" ${ARGN} WORKING_DIRECTORY "${WORK}"
    RESULT_VARIABLE r OUTPUT_VARIABLE o ERROR_VARIABLE e)
  string(REPLACE ";" " " cmd "${ARGN}")
  file(APPEND "${TRANSCRIPT}" "### openssl ${cmd}\nexit ${r}\n${o}${e}\n")
  if(NOT r EQUAL 0)
    fail("openssl ${cmd} failed (${r}):\n${o}${e}")
  endif()
  set(${var} "${o}${e}" PARENT_SCOPE)
endfunction()

# audit_entries(<var>): the audit export of ${DB} (JSON Lines) after
# xca --audit-verify reported the chain intact
function(audit_entries var)
  xca_run("audit verify" 0 --database "${DB}" ${PW} --audit-verify)
  string(STRIP "${out}" v)
  string(JSON ok GET "${v}" ok)
  if(NOT ok)
    fail("audit chain not ok:\n${v}")
  endif()
  xca_run("audit export" 0 --database "${DB}" ${PW} --audit-export -)
  set(${var} "${out}" PARENT_SCOPE)
endfunction()

if(NOT OPENSSL OR NOT EXISTS "${OPENSSL}")
  fail("the openssl program is needed (OPENSSL)")
endif()

# --- part 2 (BTD-42) ------------------------------------------------------

# fixture(<label> <args>...): cli_fixture ${DB} env:BXC_DB_PW <args>
function(fixture label)
  execute_process(COMMAND "${FIXTURE}" "${DB}" env:BXC_DB_PW ${ARGN}
    WORKING_DIRECTORY "${WORK}" INPUT_FILE /dev/null
    RESULT_VARIABLE r OUTPUT_VARIABLE o ERROR_VARIABLE e TIMEOUT 120)
  string(REPLACE ";" " " cmd "${ARGN}")
  file(APPEND "${TRANSCRIPT}"
    "### ${label}\n$ cli_fixture ${cmd}\nexit ${r}\n${o}${e}\n")
  if(NOT r EQUAL 0)
    fail("${label}: cli_fixture failed (${r}): ${o}${e}")
  endif()
  set(out "${o}" PARENT_SCOPE)
endfunction()

# sql(<label> <statement>): one statement through sql_exec on ${DB}; the
# rows in ${out}
function(sql label statement)
  execute_process(COMMAND "${SQL_EXEC}" "${DB}" -c "${statement}"
    RESULT_VARIABLE r OUTPUT_VARIABLE o ERROR_VARIABLE e TIMEOUT 60)
  file(APPEND "${TRANSCRIPT}"
    "### ${label}\n$ sql_exec ${statement}\nexit ${r}\n${o}${e}\n")
  if(NOT r EQUAL 0)
    fail("${label}: sql_exec failed (${r}): ${e}")
  endif()
  set(out "${o}" PARENT_SCOPE)
endfunction()

# jget(<var> <doc> <path>...): string(JSON GET), NOTFOUND if absent
function(jget var doc)
  string(JSON v ERROR_VARIABLE je GET "${doc}" ${ARGN})
  if(je)
    set(v NOTFOUND)
  endif()
  set(${var} "${v}" PARENT_SCOPE)
endfunction()

# jlen(<var> <doc> <path>...): array length, 0 if absent
function(jlen var doc)
  string(JSON v ERROR_VARIABLE je LENGTH "${doc}" ${ARGN})
  if(je)
    set(v 0)
  endif()
  set(${var} "${v}" PARENT_SCOPE)
endfunction()

# result_files(<doc> <var>): the paths of the files member
function(result_files doc var)
  jlen(n "${doc}" files)
  set(l "")
  if(n GREATER 0)
    math(EXPR last "${n} - 1")
    foreach(i RANGE ${last})
      string(JSON p GET "${doc}" files ${i} path)
      list(APPEND l "${p}")
    endforeach()
  endif()
  set(${var} "${l}" PARENT_SCOPE)
endfunction()

# warning_codes(<doc> <var>): the codes of the warnings member
function(warning_codes doc var)
  jlen(n "${doc}" warnings)
  set(l "")
  if(n GREATER 0)
    math(EXPR last "${n} - 1")
    foreach(i RANGE ${last})
      string(JSON c GET "${doc}" warnings ${i} code)
      list(APPEND l "${c}")
    endforeach()
  endif()
  set(${var} "${l}" PARENT_SCOPE)
endfunction()

# warning_detail(<doc> <code> <var>): the detail of the first warning with
# this code; empty if there is none
function(warning_detail doc code var)
  jlen(n "${doc}" warnings)
  set(d "")
  if(n GREATER 0)
    math(EXPR last "${n} - 1")
    foreach(i RANGE ${last})
      string(JSON c GET "${doc}" warnings ${i} code)
      if(c STREQUAL "${code}" AND d STREQUAL "")
        string(JSON d GET "${doc}" warnings ${i} detail)
      endif()
    endforeach()
  endif()
  set(${var} "${d}" PARENT_SCOPE)
endfunction()

# crl_entry(<doc> <index> <var>): one entry of the crls member
function(crl_entry doc index var)
  string(JSON v ERROR_VARIABLE je GET "${doc}" crls ${index})
  if(je)
    fail("no crls entry ${index} in:\n${doc}")
  endif()
  set(${var} "${v}" PARENT_SCOPE)
endfunction()

# file_mode(<file> <var>): octal mode, e.g. 600
function(file_mode f var)
  execute_process(COMMAND stat -c %a "${f}" OUTPUT_VARIABLE m
    RESULT_VARIABLE r OUTPUT_STRIP_TRAILING_WHITESPACE)
  if(NOT r EQUAL 0)
    fail("stat ${f} failed")
  endif()
  set(${var} "${m}" PARENT_SCOPE)
endfunction()

# openssl_fails(<var> <args>...): output of an openssl run that must fail
function(openssl_fails var)
  execute_process(COMMAND "${OPENSSL}" ${ARGN} WORKING_DIRECTORY "${WORK}"
    RESULT_VARIABLE r OUTPUT_VARIABLE o ERROR_VARIABLE e)
  string(REPLACE ";" " " cmd "${ARGN}")
  file(APPEND "${TRANSCRIPT}" "### openssl ${cmd} (must fail)\nexit ${r}\n${o}${e}\n")
  if(r EQUAL 0)
    fail("openssl ${cmd} succeeded, expected a failure:\n${o}${e}")
  endif()
  set(${var} "${o}${e}" PARENT_SCOPE)
endfunction()

# time_ahead(<var> <seconds>): RFC 3339 UTC time that many seconds after now
function(time_ahead var secs)
  time_ago(v ${secs} +)
  set(${var} "${v}" PARENT_SCOPE)
endfunction()

# time_ago(<var> <seconds>): RFC 3339 UTC time that many seconds before now
# (after now with a third argument +)
function(time_ago var secs)
  set(op -)
  if(ARGV2 STREQUAL "+")
    set(op +)
  endif()
  set(old "$ENV{SOURCE_DATE_EPOCH}")
  unset(ENV{SOURCE_DATE_EPOCH})
  string(TIMESTAMP now "%s" UTC)
  math(EXPR t "${now} ${op} ${secs}")
  set(ENV{SOURCE_DATE_EPOCH} "${t}")
  string(TIMESTAMP v "%Y-%m-%dT%H:%M:%SZ" UTC)
  if(old STREQUAL "")
    unset(ENV{SOURCE_DATE_EPOCH})
  else()
    set(ENV{SOURCE_DATE_EPOCH} "${old}")
  endif()
  set(${var} "${v}" PARENT_SCOPE)
endfunction()

# count_items(<type> <var>): number of objects of a type in ${DB}
function(count_items type var)
  bxc("list ${type}" 0 list --db "${DB}" ${PW} --type ${type})
  string(STRIP "${out}" l)
  jlen(n "${l}" items)
  set(${var} "${n}" PARENT_SCOPE)
endfunction()

# audit_has(<entries> <regex> <label>): one JSON line of the audit export
# matches the regex
function(audit_has entries regex label)
  split_lines("${entries}" lines)
  foreach(line IN LISTS lines)
    string(REPLACE "@SEMI@" ";" line "${line}")
    if(line MATCHES "${regex}")
      return()
    endif()
  endforeach()
  fail("${label}: no audit entry matches ${regex}")
endfunction()

# hex2dec(<var> <hex>): a hex number of any length as decimal text
function(hex2dec var hex)
  string(TOUPPER "${hex}" hex)
  set(digits "0")   # decimal digits, least significant first, ';' list
  string(LENGTH "${hex}" n)
  math(EXPR last "${n} - 1")
  foreach(i RANGE ${last})
    string(SUBSTRING "${hex}" ${i} 1 h)
    string(FIND "0123456789ABCDEF" "${h}" add)
    set(new "")
    foreach(d IN LISTS digits)
      math(EXPR v "${d} * 16 + ${add}")
      math(EXPR keep "${v} % 10")
      math(EXPR add "${v} / 10")
      list(APPEND new ${keep})
    endforeach()
    while(add GREATER 0)
      math(EXPR keep "${add} % 10")
      math(EXPR add "${add} / 10")
      list(APPEND new ${keep})
    endwhile()
    set(digits "${new}")
  endforeach()
  list(REVERSE digits)
  string(REPLACE ";" "" dec "${digits}")
  string(REGEX REPLACE "^0+([0-9])" "\\1" dec "${dec}")
  set(${var} "${dec}" PARENT_SCOPE)
endfunction()
