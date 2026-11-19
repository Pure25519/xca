# Helpers of the server test registrations (BTD-320), included by
# server/CMakeLists.txt before the server/test/*.test.cmake files.

# ServerTest(<name>): the settings every server test gets, the label server
macro(ServerTest name)
  set_tests_properties(${name} PROPERTIES LABELS server)
endmacro()

# ServerScriptTest(<name>): a test of a script that runs xca-server or reads
# its binary; it needs no platform plugin, so the QT_QPA_PLATFORM of the
# environment (offscreen in the build image) is removed for it
macro(ServerScriptTest name)
  ServerTest(${name})
  set_property(TEST ${name} APPEND PROPERTY
	ENVIRONMENT_MODIFICATION QT_QPA_PLATFORM=unset:)
endmacro()

# ServerShellTest(<name> <script> [<VARIABLE>=<value>]...): server/test/<script>
# run with sh, with the environment every server shell test gets and the
# extra variables given:
#  SERVER           the xca-server binary
#  OPENSSL          the openssl program of OpenSSL 4
#  WORK             <build dir>/<name without test_>, the test's directory
#  CMAKE            the cmake program, for the base config (config/lib.sh)
#  SERVER_TEST_DIR  server/test, the base config in config/
macro(ServerShellTest name script)
  string(REGEX REPLACE "^test_" "" server_work ${name})
  add_test(NAME ${name}
	COMMAND ${CMAKE_COMMAND} -E env
		SERVER=${XCA_SERVER_BIN}
		OPENSSL=${SERVER_OPENSSL}
		WORK=${CMAKE_CURRENT_BINARY_DIR}/${server_work}
		CMAKE=${CMAKE_COMMAND}
		SERVER_TEST_DIR=${SERVER_DIR}/test
		${ARGN}
		${SERVER_SH} ${SERVER_DIR}/test/${script})
  ServerScriptTest(${name})
endmacro()
