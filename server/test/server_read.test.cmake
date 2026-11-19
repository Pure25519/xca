# The read resources (BTD-156): lists with keyset paging, objects, profiles,
# policies, the index, the tokens, the CA scope of a restricted role, no
# private key material, and the audit verify and export against the CLI
ServerShellTest(test_server_read server_read.sh
	BXC_PKI=$<TARGET_FILE:bxc-pki>
	XCA=$<TARGET_FILE:${CMAKE_PROJECT_NAME}>
	SQL_EXEC=$<TARGET_FILE:sql_exec>)
