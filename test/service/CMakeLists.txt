
# Service-layer tests, ctest label "service". How to add one: README.md here.
#
# Registration is by file name (BTD-256), so that branches that add tests
# do not edit the same lines:
#  - test_service_<name>.cpp is one service test of that name;
#  - cli_<name>.cmake is one CMake script test test_cli_<name>;
# both found with file(GLOB). Only a test that needs more than the common
# settings has lines of its own below, kept in alphabetical order.

set(SERVICE_TEST_DIR ${PROJECT_SOURCE_DIR}/test/service)

add_library(xcaservicetest STATIC
	${SERVICE_TEST_DIR}/ServiceTestCase.cpp
	${SERVICE_TEST_DIR}/ServiceTestCase.h
	${PROJECT_SOURCE_DIR}/test/TestEnv.cpp
	${PROJECT_BINARY_DIR}/local.h)
target_link_libraries(xcaservicetest PUBLIC ${ASAN_LIB} ${QT}::Test xcacore)

# The service tests link xcacore, which has no Qt Gui (BTD-36): they run
# without a platform plugin, so the QT_QPA_PLATFORM of the environment
# (offscreen in the build image) is removed for them
macro(Headless test)
  set_property(TEST ${test} APPEND PROPERTY
	ENVIRONMENT_MODIFICATION QT_QPA_PLATFORM=unset:)
endmacro()

find_program(OPENSSL_PROGRAM openssl HINTS ${OPENSSL_ROOT_DIR}/bin)
find_program(SERVICE_SETPRIV setpriv)

# ServiceTest(<name>) builds test/service/<name>.cpp into one ctest. Every
# test gets the same settings; a test that does not use one ignores it:
# SERVICE_TEST_DATA (test/service/data), XCA_SOURCE_DIR (the source tree)
# and, if the program was found, OPENSSL_PROGRAM (checks with openssl).
macro(ServiceTest name)
  add_executable(${name} ${SERVICE_TEST_DIR}/${name}.cpp)
  target_link_libraries(${name} xcaservicetest)
  target_link_libraries(${name} Threads::Threads)
  target_compile_definitions(${name} PRIVATE
	SERVICE_TEST_DATA="${SERVICE_TEST_DIR}/data"
	XCA_SOURCE_DIR="${PROJECT_SOURCE_DIR}")
  if(OPENSSL_PROGRAM)
    target_compile_definitions(${name} PRIVATE
	OPENSSL_PROGRAM="${OPENSSL_PROGRAM}")
  endif()
  add_test(NAME ${name} COMMAND ${name})
  set_tests_properties(${name} PROPERTIES LABELS service)
  Headless(${name})
  add_dependencies(tests ${name})
  list(APPEND CORE_BINARIES ${name})
endmacro()

file(GLOB service_tests CONFIGURE_DEPENDS
	${SERVICE_TEST_DIR}/test_service_*.cpp)
list(SORT service_tests)
foreach(src ${service_tests})
  get_filename_component(t ${src} NAME_WE)
  ServiceTest(${t})
endforeach()

# sqlite3 for the CLI tests: prepares databases the CLI cannot create
add_executable(sql_exec ${SERVICE_TEST_DIR}/sql_exec.cpp)
target_link_libraries(sql_exec ${QT}::Sql ${ASAN_LIB})
add_dependencies(tests sql_exec)
add_dependencies(tests ${CMAKE_PROJECT_NAME})

# CliScriptTest(<name>) runs test/service/cli_<name>.cmake as the ctest
# test_cli_<name>. Every script gets the same variables; its header names
# the ones it uses: XCA, SQL_EXEC, OPENSSL (empty without the program),
# SETPRIV, DATA (test/service/data), SOURCE (the source tree) and WORK (its
# own scratch directory).
macro(CliScriptTest name)
  add_test(NAME test_cli_${name}
	COMMAND ${CMAKE_COMMAND} -DXCA=$<TARGET_FILE:${CMAKE_PROJECT_NAME}>
		-DSQL_EXEC=$<TARGET_FILE:sql_exec>
		-DOPENSSL=${OPENSSL_PROGRAM}
		-DSETPRIV=${SERVICE_SETPRIV}
		-DDATA=${SERVICE_TEST_DIR}/data
		-DSOURCE=${PROJECT_SOURCE_DIR}
		-DWORK=${CMAKE_CURRENT_BINARY_DIR}/cli_${name}
		-P ${SERVICE_TEST_DIR}/cli_${name}.cmake)
  set_tests_properties(test_cli_${name} PROPERTIES LABELS service)
endmacro()

# Scripts that need the openssl program; without it they are skipped
set(cli_needs_openssl password_sources)

file(GLOB cli_scripts CONFIGURE_DEPENDS ${SERVICE_TEST_DIR}/cli_*.cmake)
list(SORT cli_scripts)
foreach(script ${cli_scripts})
  get_filename_component(name ${script} NAME_WE)
  string(REGEX REPLACE "^cli_" "" name ${name})
  if(NOT OPENSSL_PROGRAM AND name IN_LIST cli_needs_openssl)
    message(STATUS "openssl program not found: test_cli_${name} skipped")
    continue()
  endif()
  CliScriptTest(${name})
endforeach()

# --- Tests with settings of their own, in alphabetical order ---

# xcacore without Qt Widgets, Gui and Help (BTD-36). test_core_sources
# greps its sources for GUI code; test_core_link links every object of
# the archive into xcacore_linkcheck (whole archive: a GUI symbol in an
# object no test uses fails too) and checks with readelf that it and the
# binaries linking xcacore need no Qt Gui, Widgets or Help.
get_target_property(CORE_SOURCES xcacore SOURCES)
# The bxc-pki command line is headless too (BTD-41)
get_target_property(CLI_SOURCES bxc-pki SOURCES)
list(APPEND CORE_SOURCES ${CLI_SOURCES})
list(JOIN CORE_SOURCES "|" CORE_SOURCES)
add_test(NAME test_core_sources
	COMMAND ${CMAKE_COMMAND} "-DSOURCES=${CORE_SOURCES}"
		-P ${SERVICE_TEST_DIR}/core_sources.cmake)
set_tests_properties(test_core_sources PROPERTIES LABELS service)

find_program(READELF_PROGRAM NAMES readelf ${CMAKE_READELF})
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND READELF_PROGRAM)
  add_executable(xcacore_linkcheck ${SERVICE_TEST_DIR}/xcacore_linkcheck.cpp)
  target_link_libraries(xcacore_linkcheck
	"$<LINK_LIBRARY:WHOLE_ARCHIVE,xcacore>")
  add_dependencies(tests xcacore_linkcheck)
  set(core_files "")
  foreach(bin xcacore_linkcheck test_x509rev test_takey test_x509v3ext
		bxc-pki cli_fixture ${CORE_BINARIES})
    list(APPEND core_files "$<TARGET_FILE:${bin}>")
  endforeach()
  list(JOIN core_files "|" core_files)
  add_test(NAME test_core_link
	COMMAND ${CMAKE_COMMAND} -DREADELF=${READELF_PROGRAM}
		"-DBINARIES=${core_files}"
		-DGUI_BINARY=$<TARGET_FILE:${CMAKE_PROJECT_NAME}>
		-P ${SERVICE_TEST_DIR}/core_link.cmake)
  set_tests_properties(test_core_link PROPERTIES LABELS service)
else()
  message(STATUS "readelf or Linux missing: test_core_link skipped")
endif()

# configuring against OpenSSL 3 stops with the version message (BTD-253);
# the stand-in prefix uses the Unix library names
if(UNIX)
  add_test(NAME test_openssl_minimum
	COMMAND ${CMAKE_COMMAND} -DSRC=${PROJECT_SOURCE_DIR}
		"-DGENERATOR=${CMAKE_GENERATOR}"
		-DWORK=${CMAKE_CURRENT_BINARY_DIR}/openssl_minimum
		-P ${SERVICE_TEST_DIR}/openssl_minimum.cmake)
  set_tests_properties(test_openssl_minimum PROPERTIES LABELS service)
endif()

# no internal references in the public fork (BTD-236)
add_test(NAME test_private_refs
	COMMAND ${CMAKE_COMMAND} -DSRC=${PROJECT_SOURCE_DIR}
		-P ${SERVICE_TEST_DIR}/private_refs.cmake)
set_tests_properties(test_private_refs PROPERTIES LABELS service)

# The harness must fail a test on an unexpected prompt
add_test(NAME test_service_harness_selfcheck
	COMMAND test_service_harness selfcheckUnexpectedPrompt)
set_tests_properties(test_service_harness_selfcheck PROPERTIES LABELS service
	ENVIRONMENT XCA_SERVICE_SELFCHECK=1
	PASS_REGULAR_EXPRESSION "FAIL!  : test_service_harness::selfcheckUnexpectedPrompt\\(\\)[^\n]*unexpected password prompt")
Headless(test_service_harness_selfcheck)

# The empty-DER check of cleanup() must fail when its query cannot run
# (BTD-181), not pass silently
add_test(NAME test_service_harness_selfcheck_der
	COMMAND test_service_harness selfcheckEmptyDerQuery)
set_tests_properties(test_service_harness_selfcheck_der PROPERTIES
	LABELS service ENVIRONMENT XCA_SERVICE_SELFCHECK=1
	PASS_REGULAR_EXPRESSION "FAIL!  : test_service_harness::selfcheckEmptyDerQuery\\(\\)[^\n]*empty DER check failed[^\n]*cert")
Headless(test_service_harness_selfcheck_der)

# ML-DSA keys under an openssl.cnf that changes the default provider
# (BTD-16): the same test functions with data/mldsa-<mode>.cnf; prefer_seed
# also in the other spellings OpenSSL reads as false (BTD-194). Each run
# checks first that OpenSSL loaded the cnf (checkOpensslConf)
foreach(mode output retain prefer prefer-false prefer-0 prefer-off)
  add_test(NAME test_service_importexport_cnf_${mode}
	COMMAND test_service_importexport mlDsaUnderOpensslConf
		mlDsaSeedlessPasswordChange)
  set_tests_properties(test_service_importexport_cnf_${mode} PROPERTIES
	LABELS service
	ENVIRONMENT "OPENSSL_CONF=${SERVICE_TEST_DIR}/data/mldsa-${mode}.cnf;XCA_TEST_MLDSA_CNF=${mode}")
  Headless(test_service_importexport_cnf_${mode})
endforeach()

# The Windows packaging follows MSVC and OpenSSL 4 (BTD-252), checked on
# every platform
add_test(NAME test_windows_packaging
	COMMAND ${CMAKE_COMMAND} -DSRC=${PROJECT_SOURCE_DIR}
		-DWORK=${CMAKE_CURRENT_BINARY_DIR}/windows_packaging
		-P ${SERVICE_TEST_DIR}/windows_packaging.cmake)
set_tests_properties(test_windows_packaging PROPERTIES LABELS service)
