# xca-server: the REST server of the fork (BTD-154, Phase 3 of bxc-pki).
# One binary that links xcacore and OpenSSL only, with the vendored
# cpp-httplib (server/third_party/httplib.h, pinned by tag and SHA-256 in
# bxc-pki docs/dependencies.json). No Qt Network, Gui, Widgets or Help.

set(SERVER_DIR ${PROJECT_SOURCE_DIR}/server)

# The tests name the binary by its path, so they run (and fail) also before
# the target exists
set(XCA_SERVER_BIN ${PROJECT_BINARY_DIR}/xca-server)

# POSIX hosts only for now: the Windows build (MSVC) of the server is not
# set up or tested yet
if(NOT WIN32)
  # Only where the server is built: a header that does not match must stop
  # the server, never the configure of the GUI on a host without the server
  # (review of xca#192). .gitattributes keeps the header byte-exact (-text),
  # also with core.autocrlf=true, the Git default on Windows.
  # The vendored cpp-httplib, pinned by release tag and SHA-256 (condition 1
  # of bxc-pki docs/xca-server-architecture.md; bxc-pki docs/dependencies.json
  # reads both lines). Every security advisory of yhirose/cpp-httplib means a
  # new tag here, with full gates. A changed header fails the configure.
  set(CPPHTTPLIB_VERSION "0.66.0")
  set(CPPHTTPLIB_SHA256 "51ddd1482c67acb31f3064e48329aade14acc7dd0fab31ee5397193697ea1c35")
  file(SHA256 ${SERVER_DIR}/third_party/httplib.h cpphttplib_sha256)
  if(NOT cpphttplib_sha256 STREQUAL CPPHTTPLIB_SHA256)
    message(FATAL_ERROR "server/third_party/httplib.h has SHA-256 "
		"${cpphttplib_sha256}, not the pinned ${CPPHTTPLIB_SHA256} of "
		"cpp-httplib v${CPPHTTPLIB_VERSION}")
  endif()
  file(STRINGS ${SERVER_DIR}/third_party/httplib.h cpphttplib_version_line
		REGEX "^#define CPPHTTPLIB_VERSION \"")
  if(NOT cpphttplib_version_line STREQUAL "#define CPPHTTPLIB_VERSION \"${CPPHTTPLIB_VERSION}\"")
    message(FATAL_ERROR "server/third_party/httplib.h is not cpp-httplib "
		"v${CPPHTTPLIB_VERSION}: ${cpphttplib_version_line}")
  endif()
  add_executable(xca-server
	${SERVER_DIR}/main.cpp
	${SERVER_DIR}/config.cpp ${SERVER_DIR}/config.h
	${SERVER_DIR}/worker.cpp ${SERVER_DIR}/worker.h
	${SERVER_DIR}/session.cpp ${SERVER_DIR}/session.h
	${SERVER_DIR}/routes.cpp ${SERVER_DIR}/routes.h
	${PROJECT_BINARY_DIR}/local.h)
  # SYSTEM: the OpenSSL 4.1 deprecations inside the header (condition 6)
  # are not warnings of our code
  target_include_directories(xca-server SYSTEM PRIVATE ${SERVER_DIR}/third_party)
  # server code only, no httplib::Client is used (condition 4)
  target_compile_definitions(xca-server PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)
  # GCC 14 with -fsanitize=address (dev.py asan) reports a false
  # -Wmaybe-uninitialized inside libstdc++'s std::regex, which the route
  # patterns of cpp-httplib instantiate in routes.cpp; SYSTEM does not
  # hide it, because the location is the inlined libstdc++ code
  if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND ADDRESS_SANITIZER)
    set_source_files_properties(${SERVER_DIR}/routes.cpp PROPERTIES
	COMPILE_OPTIONS -Wno-maybe-uninitialized)
  endif()
  target_link_libraries(xca-server xcacore OpenSSL::SSL Threads::Threads
	${ASAN_LIB})
  set_target_properties(xca-server PROPERTIES MACOSX_BUNDLE FALSE
	RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})
  install(TARGETS xca-server RUNTIME DESTINATION ${RUNTIME_DEST})
  if(BUILD_TESTING)
    add_dependencies(tests xca-server)
  endif()
endif()

if(BUILD_TESTING)
  find_program(SERVER_READELF readelf)
  find_program(SERVER_LDD ldd)
  find_program(SERVER_SH sh)
  find_program(SERVER_OPENSSL openssl HINTS ${OPENSSL_ROOT_DIR}/bin)

  # the binary links no Qt Gui, Widgets, Help or Network and only the
  # libssl/libcrypto of OpenSSL 4 (architecture conditions 6 and 7)
  add_test(NAME test_server_link
	COMMAND ${CMAKE_COMMAND}
		-DSERVER=${XCA_SERVER_BIN}
		-DREADELF=${SERVER_READELF}
		-DLDD=${SERVER_LDD}
		-P ${SERVER_DIR}/test/server_link.cmake)
  # xca-server.json: every rule of the schema, no literal secret
  add_test(NAME test_server_config
	COMMAND ${CMAKE_COMMAND}
		-DSERVER=${XCA_SERVER_BIN}
		-DWORK=${CMAKE_CURRENT_BINARY_DIR}/server_config
		-P ${SERVER_DIR}/test/server_config.cmake)
  # start, mTLS, the DB worker under load, the exclusive database, stop and
  # the audit entries
  add_test(NAME test_server_lifecycle
	COMMAND ${CMAKE_COMMAND} -E env
		SERVER=${XCA_SERVER_BIN}
		BXC_PKI=$<TARGET_FILE:bxc-pki>
		XCA=$<TARGET_FILE:${CMAKE_PROJECT_NAME}>
		SQL_EXEC=$<TARGET_FILE:sql_exec>
		OPENSSL=${SERVER_OPENSSL}
		WORK=${CMAKE_CURRENT_BINARY_DIR}/server_lifecycle
		${SERVER_SH} ${SERVER_DIR}/test/server_lifecycle.sh)
  # The operation table of roles.json (BTD-155) as lines for the shell test:
  # <operation_id> <METHOD> <path> <roles, comma separated> <ca_param or ->
  set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
	${SERVER_DIR}/roles.json)
  file(READ ${SERVER_DIR}/roles.json server_roles_json)
  string(JSON server_ops_n LENGTH "${server_roles_json}" operations)
  math(EXPR server_ops_last "${server_ops_n} - 1")
  set(server_roles_tsv "")
  foreach(i RANGE ${server_ops_last})
    string(JSON op GET "${server_roles_json}" operations ${i} operation_id)
    string(JSON method GET "${server_roles_json}" operations ${i} method)
    string(JSON path GET "${server_roles_json}" operations ${i} path)
    string(JSON ca_type TYPE "${server_roles_json}" operations ${i} ca_param)
    if(ca_type STREQUAL "NULL")
      set(ca "-")
    else()
      string(JSON ca GET "${server_roles_json}" operations ${i} ca_param)
    endif()
    string(JSON roles_n LENGTH "${server_roles_json}" operations ${i} roles)
    math(EXPR roles_last "${roles_n} - 1")
    set(roles "")
    foreach(j RANGE ${roles_last})
      string(JSON role GET "${server_roles_json}" operations ${i} roles ${j})
      list(APPEND roles ${role})
    endforeach()
    string(REPLACE ";" "," roles "${roles}")
    string(APPEND server_roles_tsv "${op} ${method} ${path} ${roles} ${ca}\n")
  endforeach()
  file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/server_roles.tsv "${server_roles_tsv}")
  # TLS, mTLS or API keys, the roles of every operation, the CA scope, the
  # audit entries auth.login and auth.denied with their rate limit, reload
  add_test(NAME test_server_auth
	COMMAND ${CMAKE_COMMAND} -E env
		SERVER=${XCA_SERVER_BIN}
		BXC_PKI=$<TARGET_FILE:bxc-pki>
		XCA=$<TARGET_FILE:${CMAKE_PROJECT_NAME}>
		SQL_EXEC=$<TARGET_FILE:sql_exec>
		OPENSSL=${SERVER_OPENSSL}
		WORK=${CMAKE_CURRENT_BINARY_DIR}/server_auth
		ROLES_TSV=${CMAKE_CURRENT_BINARY_DIR}/server_roles.tsv
		${SERVER_SH} ${SERVER_DIR}/test/server_auth.sh)
  set_tests_properties(test_server_link test_server_config
	test_server_lifecycle test_server_auth PROPERTIES LABELS server)
  set_property(TEST test_server_link test_server_config
	test_server_lifecycle test_server_auth APPEND PROPERTY
	ENVIRONMENT_MODIFICATION QT_QPA_PLATFORM=unset:)
endif()
