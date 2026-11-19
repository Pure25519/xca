# The layout of the server tests (BTD-320), so that parallel PRs that add a
# server test or a required member of xca-server.json do not collide:
#  - server/CMakeLists.txt registers no test itself; every server test has
#    its own server/test/<name>.test.cmake;
#  - no server test script writes a configuration of its own: the schema id
#    of xca-server.json appears only in the one base config
#    server/test/config/base.json, which the tests change member by member.
# cmake -DSERVER_DIR=<source>/server -DWORK=<dir> -P server_layout.cmake
# With WORK set, a self-test runs first (BTD-321): the check against a
# small tree that is clean (must pass) and against one copy per way of
# registering a test in server/CMakeLists.txt (each must fail).

cmake_minimum_required(VERSION 3.19)

if(WORK)
  file(REMOVE_RECURSE "${WORK}")
  set(self_failures "")
  set(clean "if(BUILD_TESTING)\n  include(\${SERVER_DIR}/test/ServerTests.cmake)\nendif()\n")
  set(case_names clean add_test set_tests_properties set_property_test
	set_property_test_spaced)
  set(case_clean "${clean}")
  set(case_add_test "${clean}add_test(NAME test_server_x COMMAND true)\n")
  set(case_set_tests_properties
	"${clean}set_tests_properties(test_server_x PROPERTIES LABELS server)\n")
  set(case_set_property_test
	"${clean}set_property(TEST test_server_x APPEND PROPERTY LABELS server)\n")
  set(case_set_property_test_spaced
	"${clean}SET_PROPERTY (\n\tTEST test_server_x PROPERTY LABELS server)\n")
  foreach(case ${case_names})
    set(tree "${WORK}/${case}")
    file(WRITE "${tree}/CMakeLists.txt" "${case_${case}}")
    file(WRITE "${tree}/test/server_x.test.cmake" "ServerTest(test_server_x)\n")
    file(WRITE "${tree}/test/config/base.json" "{}\n")
    execute_process(COMMAND ${CMAKE_COMMAND} -DSERVER_DIR=${tree}
		-P ${CMAKE_CURRENT_LIST_FILE}
	RESULT_VARIABLE rc OUTPUT_QUIET ERROR_VARIABLE err)
    if(case STREQUAL "clean" AND NOT rc EQUAL 0)
      string(APPEND self_failures "\nself-test: the clean tree fails: ${err}")
    elseif(NOT case STREQUAL "clean" AND rc EQUAL 0)
      string(APPEND self_failures "\nself-test: ${case} in server/CMakeLists.txt passes the check")
    endif()
  endforeach()
  if(self_failures)
    message(FATAL_ERROR "${self_failures}")
  endif()
  message(STATUS "ok: self-test, the check refuses every way of registering a test")
endif()

set(failures "")

# CMake commands are case-insensitive and may have blanks before "(";
# comments do not count
file(READ "${SERVER_DIR}/CMakeLists.txt" lists)
string(TOLOWER "${lists}" lists)
string(REGEX REPLACE "#[^\n]*" "" lists "${lists}")
set(blank "[ \t\r\n]*")
set(start "(^|[^a-z0-9_])")
foreach(call add_test set_tests_properties)
  if(lists MATCHES "${start}${call}${blank}\\(")
    string(APPEND failures "\nserver/CMakeLists.txt registers tests itself (${call})")
  endif()
endforeach()
if(lists MATCHES "${start}set_property${blank}\\(${blank}test[ \t\r\n)]")
  string(APPEND failures "\nserver/CMakeLists.txt registers tests itself (set_property(TEST))")
endif()

file(GLOB registrations "${SERVER_DIR}/test/*.test.cmake")
if(NOT registrations)
  string(APPEND failures "\nno server/test/*.test.cmake registers a test")
endif()

# the id is put together, so that this file does not carry it
set(id "urn:bxc-pki:schema:")
string(APPEND id "xca-server:v1")
if(NOT EXISTS "${SERVER_DIR}/test/config/base.json")
  string(APPEND failures "\nno base config server/test/config/base.json")
endif()
file(GLOB_RECURSE scripts "${SERVER_DIR}/test/*.sh" "${SERVER_DIR}/test/*.cmake")
foreach(f ${scripts})
  file(READ "${f}" text)
  string(FIND "${text}" "${id}" at)
  if(NOT at EQUAL -1)
    file(RELATIVE_PATH rel "${SERVER_DIR}" "${f}")
    string(APPEND failures "\nserver/${rel} writes a configuration of its own (${id})")
  endif()
endforeach()

if(failures)
  message(FATAL_ERROR "${failures}")
endif()
message(STATUS "ok: every server test registers itself, one base config")
