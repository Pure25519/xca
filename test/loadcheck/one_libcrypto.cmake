# Exactly one libcrypto, OpenSSL 4, in xca, bxc-pki and the test binaries
# (BTD-251). Two libcrypto majors in one process mean two provider sets
# and two error queues; nothing fails at link time, so this test looks at
# what a real run had loaded. Each binary runs with the preload library
# LOADCHECK (test/loadcheck/loadcheck.cpp), which lists every loaded
# object at process exit; a run without such a list fails.
#
# Variables: LOADCHECK, XCA, BXC_PKI, TESTXCA, SERVICE_TEST, WORK, MODE.
# MODE clean: every run must have exactly one libcrypto, libcrypto.so.4,
# and no libssl.so.3. MODE injected: INJECT (the Debian libcrypto.so.3)
# is preloaded as well, and the check must report it for every run; this
# proves on each ctest run that the guard can fail.

cmake_minimum_required(VERSION 3.16)

file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}/home")
set(ENV{HOME} "${WORK}/home")
set(ENV{XDG_CONFIG_HOME} "${WORK}/home/.config")
set(ENV{XDG_DATA_HOME} "${WORK}/home/.local/share")
set(ENV{QT_QPA_PLATFORM} offscreen)
# an ASan build links the runtime into each binary; a library preloaded in
# front of it is fine for this test
set(ENV{ASAN_OPTIONS} "verify_asan_link_order=0:$ENV{ASAN_OPTIONS}")

set(DB "${WORK}/one.xdb")
set(DB_PW "One-Libcrypto-251")

if(MODE STREQUAL "injected")
  if(NOT EXISTS "${INJECT}")
    message(FATAL_ERROR "no libcrypto.so.3 to inject: '${INJECT}'")
  endif()
  set(PRELOAD "${INJECT}:${LOADCHECK}")
else()
  set(PRELOAD "${LOADCHECK}")
endif()

# loaded(<label> <args>...): runs the command with the preload library;
# the list of loaded objects goes to ${objects} in the caller
function(loaded label)
  set(list "${WORK}/${label}.objects")
  execute_process(COMMAND ${CMAKE_COMMAND} -E env
      "LD_PRELOAD=${PRELOAD}" "XCA_LOADCHECK_OUT=${list}" ${ARGN}
    WORKING_DIRECTORY "${WORK}" INPUT_FILE /dev/null
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err TIMEOUT 120)
  if(NOT rc EQUAL 0)
    message(FATAL_ERROR "${label}: exit code ${rc}\n${out}\n${err}")
  endif()
  if(NOT EXISTS "${list}")
    message(FATAL_ERROR "${label}: no list of loaded objects (did the "
      "process end without running its destructors?)")
  endif()
  file(STRINGS "${list}" lines REGEX "^/")
  set(objects "${lines}" PARENT_SCOPE)
endfunction()

# problem(<objects> <var>): empty when exactly one libcrypto is loaded and
# it is libcrypto.so.4 and no libssl.so.3 is loaded; otherwise the reason
function(problem objects var)
  set(crypto "")
  set(ssl3 "")
  foreach(o IN LISTS objects)
    get_filename_component(name "${o}" NAME)
    if(name MATCHES "^libcrypto\\.so")
      list(APPEND crypto "${o}")
    elseif(name MATCHES "^libssl\\.so\\.3")
      list(APPEND ssl3 "${o}")
    endif()
  endforeach()
  list(LENGTH crypto n)
  set(reason "")
  if(NOT n EQUAL 1)
    string(REPLACE ";" ", " shown "${crypto}")
    set(reason "${n} libcrypto objects loaded: ${shown}")
  else()
    get_filename_component(name "${crypto}" NAME)
    if(NOT name STREQUAL "libcrypto.so.4")
      set(reason "libcrypto is ${crypto}, not libcrypto.so.4")
    endif()
  endif()
  if(ssl3)
    string(REPLACE ";" ", " shown "${ssl3}")
    set(reason "${reason} libssl.so.3 loaded: ${shown}")
  endif()
  set(${var} "${reason}" PARENT_SCOPE)
endfunction()

set(runs "")
set(failures "")
macro(check label)
  loaded(${label} ${ARGN})
  problem("${objects}" why)
  list(APPEND runs ${label})
  if(MODE STREQUAL "injected")
    if(NOT why)
      list(APPEND failures "${label}: libcrypto.so.3 was injected, but the check found nothing")
    else()
      message(STATUS "${label}: reported as expected: ${why}")
    endif()
  elseif(why)
    list(APPEND failures "${label}: ${why}")
  else()
    message(STATUS "${label}: one libcrypto, libcrypto.so.4")
  endif()
endmacro()

# the command line: a new database with a CA (key, certificate, CRL)
check(bxc-pki "${BXC_PKI}" init --db "${DB}" --password "pass:${DB_PW}"
  --cn "One Libcrypto CA" --validity P1Y)
# the GUI binary without a window: open the database, print the certificate
check(xca "${XCA}" --no-gui --database "${DB}" --password "pass:${DB_PW}"
  --json --print --select 2)
# the GUI test binary with one test function, and one service test
check(testxca "${TESTXCA}" automationIds)
check(service_test "${SERVICE_TEST}")

if(failures)
  string(REPLACE ";" "\n" text "${failures}")
  message(FATAL_ERROR "${text}")
endif()
message(STATUS "checked: ${runs}")
