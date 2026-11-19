# xca-server.json: every rule of the schema, no literal secret (BTD-154,
# BTD-155); starts from the base config of the server tests
add_test(NAME test_server_config
	COMMAND ${CMAKE_COMMAND}
		-DSERVER=${XCA_SERVER_BIN}
		-DWORK=${CMAKE_CURRENT_BINARY_DIR}/server_config
		-DSERVER_TEST_DIR=${SERVER_DIR}/test
		-P ${SERVER_DIR}/test/server_config.cmake)
ServerScriptTest(test_server_config)
