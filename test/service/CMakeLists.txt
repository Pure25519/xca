
# Service-layer tests, ctest label "service". How to add one: README.md here.

set(SERVICE_TEST_DIR ${PROJECT_SOURCE_DIR}/test/service)

add_library(xcaservicetest STATIC
	${SERVICE_TEST_DIR}/ServiceTestCase.cpp
	${SERVICE_TEST_DIR}/ServiceTestCase.h
	${PROJECT_SOURCE_DIR}/test/TestEnv.cpp
	${PROJECT_BINARY_DIR}/local.h)
target_link_libraries(xcaservicetest PUBLIC ${ASAN_LIB} ${QT}::Test xcalib)

# ServiceTest(<name>) builds test/service/<name>.cpp into one ctest
macro(ServiceTest name)
  add_executable(${name} ${SERVICE_TEST_DIR}/${name}.cpp)
  target_link_libraries(${name} xcaservicetest)
  target_link_options(${name} PRIVATE -pthread)
  add_test(NAME ${name} COMMAND ${name})
  # xcalib still links Qt Widgets (until BTD-36)
  set_tests_properties(${name} PROPERTIES LABELS service
	ENVIRONMENT QT_QPA_PLATFORM=offscreen)
  add_dependencies(tests ${name})
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
	ENVIRONMENT "QT_QPA_PLATFORM=offscreen;XCA_SERVICE_SELFCHECK=1"
	PASS_REGULAR_EXPRESSION "FAIL!  : test_service_harness::selfcheckUnexpectedPrompt\\(\\)[^\n]*unexpected password prompt")

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
