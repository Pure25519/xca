# the binary links no Qt Gui, Widgets, Help or Network and only the
# libssl/libcrypto of OpenSSL 4 (architecture conditions 6 and 7; BTD-154)
add_test(NAME test_server_link
	COMMAND ${CMAKE_COMMAND}
		-DSERVER=${XCA_SERVER_BIN}
		-DREADELF=${SERVER_READELF}
		-DLDD=${SERVER_LDD}
		-P ${SERVER_DIR}/test/server_link.cmake)
ServerScriptTest(test_server_link)
