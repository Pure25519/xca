# the layout of the server tests: each one registers itself, one base
# config (BTD-320); first the self-test of the check (BTD-321)
add_test(NAME test_server_layout
	COMMAND ${CMAKE_COMMAND} -DSERVER_DIR=${SERVER_DIR}
		-DWORK=${CMAKE_CURRENT_BINARY_DIR}/server_layout
		-P ${SERVER_DIR}/test/server_layout.cmake)
ServerTest(test_server_layout)
