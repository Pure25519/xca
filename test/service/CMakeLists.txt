
# Service-layer tests, ctest label "service". How to add one: README.md here.

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
  if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.22)
    set_property(TEST ${test} APPEND PROPERTY
	ENVIRONMENT_MODIFICATION QT_QPA_PLATFORM=unset:)
  endif()
endmacro()

# ServiceTest(<name>) builds test/service/<name>.cpp into one ctest
macro(ServiceTest name)
  add_executable(${name} ${SERVICE_TEST_DIR}/${name}.cpp)
  target_link_libraries(${name} xcaservicetest)
  target_link_options(${name} PRIVATE -pthread)
  add_test(NAME ${name} COMMAND ${name})
  set_tests_properties(${name} PROPERTIES LABELS service)
  Headless(${name})
  add_dependencies(tests ${name})
  list(APPEND CORE_BINARIES ${name})
endmacro()

ServiceTest(test_service_harness)
ServiceTest(test_service_key)
ServiceTest(test_service_secrets)
ServiceTest(test_service_audit)
target_compile_definitions(test_service_audit PRIVATE
	SERVICE_TEST_DATA="${SERVICE_TEST_DIR}/data"
	XCA_SOURCE_DIR="${PROJECT_SOURCE_DIR}")

# Signed audit checkpoints (BTD-37); signatures checked with openssl pkeyutl
ServiceTest(test_service_checkpoint)

# The outer commit after a nested rollback reports failure (BTD-142)
ServiceTest(test_service_transaction)

# Memory follows the database after a rollback (BTD-130)
ServiceTest(test_service_memory)

# xca --no-gui: no colour codes off a terminal, no false parser warning
add_test(NAME test_cli_plain_output
	COMMAND ${CMAKE_COMMAND} -DXCA=$<TARGET_FILE:${CMAKE_PROJECT_NAME}>
		-DWORK=${CMAKE_CURRENT_BINARY_DIR}/cli_plain_output
		-P ${SERVICE_TEST_DIR}/cli_plain_output.cmake)
set_tests_properties(test_cli_plain_output PROPERTIES LABELS service)

# The harness must fail a test on an unexpected prompt
add_test(NAME test_service_harness_selfcheck
	COMMAND test_service_harness selfcheckUnexpectedPrompt)
set_tests_properties(test_service_harness_selfcheck PROPERTIES LABELS service
	ENVIRONMENT XCA_SERVICE_SELFCHECK=1
	PASS_REGULAR_EXPRESSION "FAIL!  : test_service_harness::selfcheckUnexpectedPrompt\\(\\)[^\n]*unexpected password prompt")
Headless(test_service_harness_selfcheck)

# xca --no-gui with a missing password exits non-zero instead of prompting
add_test(NAME test_cli_missing_password
	COMMAND ${CMAKE_COMMAND} -DXCA=$<TARGET_FILE:${CMAKE_PROJECT_NAME}>
		-DWORK=${CMAKE_CURRENT_BINARY_DIR}/cli_missing_password
		-P ${SERVICE_TEST_DIR}/cli_missing_password.cmake)
set_tests_properties(test_cli_missing_password PROPERTIES LABELS service)
add_dependencies(tests ${CMAKE_PROJECT_NAME})

# xca --no-gui answers questions only with --yes or --confirm (BTD-71)
add_test(NAME test_cli_confirmations
	COMMAND ${CMAKE_COMMAND} -DXCA=$<TARGET_FILE:${CMAKE_PROJECT_NAME}>
		-DWORK=${CMAKE_CURRENT_BINARY_DIR}/cli_confirmations
		-P ${SERVICE_TEST_DIR}/cli_confirmations.cmake)
set_tests_properties(test_cli_confirmations PROPERTIES LABELS service)

# xca --no-gui checks a given database password on open (BTD-78)
add_test(NAME test_cli_password_verify
	COMMAND ${CMAKE_COMMAND} -DXCA=$<TARGET_FILE:${CMAKE_PROJECT_NAME}>
		-DWORK=${CMAKE_CURRENT_BINARY_DIR}/cli_password_verify
		-P ${SERVICE_TEST_DIR}/cli_password_verify.cmake)
set_tests_properties(test_cli_password_verify PROPERTIES LABELS service)

# sqlite3 for the CLI tests: prepares databases the CLI cannot create
add_executable(sql_exec ${SERVICE_TEST_DIR}/sql_exec.cpp)
target_link_libraries(sql_exec ${QT}::Sql ${ASAN_LIB})
add_dependencies(tests sql_exec)

# A given password is checked on a database with an empty password too,
# and a rejected one leaves an old database unchanged (BTD-117)
add_test(NAME test_cli_password_empty_db
	COMMAND ${CMAKE_COMMAND} -DXCA=$<TARGET_FILE:${CMAKE_PROJECT_NAME}>
		-DSQL_EXEC=$<TARGET_FILE:sql_exec>
		-DDUMP=${SERVICE_TEST_DIR}/data/schema8-fork.sql
		-DWORK=${CMAKE_CURRENT_BINARY_DIR}/cli_password_empty_db
		-P ${SERVICE_TEST_DIR}/cli_password_empty_db.cmake)
set_tests_properties(test_cli_password_empty_db PROPERTIES LABELS service)

# The debug output of xca --no-gui never shows --password or --sqlpass values
add_test(NAME test_cli_debug_secrets
	COMMAND ${CMAKE_COMMAND} -DXCA=$<TARGET_FILE:${CMAKE_PROJECT_NAME}>
		-DWORK=${CMAKE_CURRENT_BINARY_DIR}/cli_debug_secrets
		-P ${SERVICE_TEST_DIR}/cli_debug_secrets.cmake)
set_tests_properties(test_cli_debug_secrets PROPERTIES LABELS service)

# --password serves every database password request of one command
find_program(OPENSSL_PROGRAM openssl HINTS ${OPENSSL_ROOT_DIR}/bin)
if(OPENSSL_PROGRAM)
  add_test(NAME test_cli_password_sources
	COMMAND ${CMAKE_COMMAND} -DXCA=$<TARGET_FILE:${CMAKE_PROJECT_NAME}>
		-DOPENSSL=${OPENSSL_PROGRAM}
		-DWORK=${CMAKE_CURRENT_BINARY_DIR}/cli_password_sources
		-P ${SERVICE_TEST_DIR}/cli_password_sources.cmake)
  set_tests_properties(test_cli_password_sources PROPERTIES LABELS service)
else()
  message(STATUS "openssl program not found: test_cli_password_sources skipped")
endif()

if(OPENSSL_PROGRAM)
  target_compile_definitions(test_service_checkpoint PRIVATE
	OPENSSL_PROGRAM="${OPENSSL_PROGRAM}")
endif()

# Certificate issuance (BTD-31); checks the chain with openssl verify
ServiceTest(test_service_issuance)
if(OPENSSL_PROGRAM)
  target_compile_definitions(test_service_issuance PRIVATE
	OPENSSL_PROGRAM="${OPENSSL_PROGRAM}")
endif()

# A failed signature is an error, never a stored object (BTD-171)
ServiceTest(test_service_signing_failure)

# Checks before every signature: path length, issuer, CSR, OPC UA chains
# (BTD-55)
ServiceTest(test_service_signing)
if(OPENSSL_PROGRAM)
  target_compile_definitions(test_service_signing PRIVATE
	OPENSSL_PROGRAM="${OPENSSL_PROGRAM}")
endif()

# Device CSRs of the IDIAL corpus under the profiles (BTD-65)
ServiceTest(test_service_csr_acceptance)
target_compile_definitions(test_service_csr_acceptance PRIVATE
	SERVICE_TEST_DATA="${SERVICE_TEST_DIR}/data")
if(OPENSSL_PROGRAM)
  target_compile_definitions(test_service_csr_acceptance PRIVATE
	OPENSSL_PROGRAM="${OPENSSL_PROGRAM}")
endif()

# xca --no-gui exits 1 when a command fails, 0 when it succeeds
add_test(NAME test_cli_exit_codes
	COMMAND ${CMAKE_COMMAND} -DXCA=$<TARGET_FILE:${CMAKE_PROJECT_NAME}>
		-DOPENSSL=${OPENSSL_PROGRAM}
		-DWORK=${CMAKE_CURRENT_BINARY_DIR}/cli_exit_codes
		-P ${SERVICE_TEST_DIR}/cli_exit_codes.cmake)
set_tests_properties(test_cli_exit_codes PROPERTIES LABELS service)

# Key generation and request creation (BTD-32); openssl req -verify
ServiceTest(test_service_request)
if(OPENSSL_PROGRAM)
  target_compile_definitions(test_service_request PRIVATE
	OPENSSL_PROGRAM="${OPENSSL_PROGRAM}")
endif()

# Key sizes as openssl pkey reads them (BTD-94)
if(OPENSSL_PROGRAM)
  target_compile_definitions(test_service_key PRIVATE
	OPENSSL_PROGRAM="${OPENSSL_PROGRAM}")
endif()

# Revocation and CRL generation (BTD-33); checks every CRL with openssl crl
ServiceTest(test_service_revocation)
if(OPENSSL_PROGRAM)
  target_compile_definitions(test_service_revocation PRIVATE
	OPENSSL_PROGRAM="${OPENSSL_PROGRAM}")
endif()

# Import and export (BTD-34); files made and checked with the openssl program
ServiceTest(test_service_importexport)
if(OPENSSL_PROGRAM)
  target_compile_definitions(test_service_importexport PRIVATE
	OPENSSL_PROGRAM="${OPENSSL_PROGRAM}")
endif()

# Secure export defaults (BTD-52); every export read back with openssl
ServiceTest(test_service_export_defaults)
if(OPENSSL_PROGRAM)
  target_compile_definitions(test_service_export_defaults PRIVATE
	OPENSSL_PROGRAM="${OPENSSL_PROGRAM}")
endif()

# Templates, rename and delete (BTD-35)
ServiceTest(test_service_template)
ServiceTest(test_service_objects)

# xcacore without Qt Widgets, Gui and Help (BTD-36). test_core_sources
# greps its sources for GUI code; test_core_link links every object of
# the archive into xcacore_linkcheck (whole archive: a GUI symbol in an
# object no test uses fails too) and checks with readelf that it and the
# binaries linking xcacore need no Qt Gui, Widgets or Help.
get_target_property(CORE_SOURCES xcacore SOURCES)
list(JOIN CORE_SOURCES "|" CORE_SOURCES)
add_test(NAME test_core_sources
	COMMAND ${CMAKE_COMMAND} "-DSOURCES=${CORE_SOURCES}"
		-P ${SERVICE_TEST_DIR}/core_sources.cmake)
set_tests_properties(test_core_sources PROPERTIES LABELS service)

find_program(READELF_PROGRAM NAMES readelf ${CMAKE_READELF})
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND READELF_PROGRAM AND
   CMAKE_VERSION VERSION_GREATER_EQUAL 3.24)
  add_executable(xcacore_linkcheck ${SERVICE_TEST_DIR}/xcacore_linkcheck.cpp)
  target_link_libraries(xcacore_linkcheck
	"$<LINK_LIBRARY:WHOLE_ARCHIVE,xcacore>")
  add_dependencies(tests xcacore_linkcheck)
  set(core_files "")
  foreach(bin xcacore_linkcheck test_x509rev test_takey test_x509v3ext
		${CORE_BINARIES})
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
  message(STATUS "readelf, Linux or CMake 3.24 missing: test_core_link skipped")
endif()

# JSON documents of the objects and list outputs (BTD-39)
ServiceTest(test_service_json)
target_compile_definitions(test_service_json PRIVATE
	SERVICE_TEST_DATA="${SERVICE_TEST_DIR}/data")

# xca --no-gui --json: JSON Lines on stdout, error objects, no secrets
add_test(NAME test_cli_json_output
	COMMAND ${CMAKE_COMMAND} -DXCA=$<TARGET_FILE:${CMAKE_PROJECT_NAME}>
		-DDATA=${SERVICE_TEST_DIR}/data/json
		-DOPENSSL=${OPENSSL_PROGRAM}
		-DSQL_EXEC=$<TARGET_FILE:sql_exec>
		-DWORK=${CMAKE_CURRENT_BINARY_DIR}/cli_json_output
		-P ${SERVICE_TEST_DIR}/cli_json_output.cmake)
set_tests_properties(test_cli_json_output PROPERTIES LABELS service)
