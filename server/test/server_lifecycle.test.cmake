# start, mTLS, the DB worker under load, the exclusive database, stop and
# the audit entries (BTD-154)
ServerShellTest(test_server_lifecycle server_lifecycle.sh
	BXC_PKI=$<TARGET_FILE:bxc-pki>
	XCA=$<TARGET_FILE:${CMAKE_PROJECT_NAME}>
	SQL_EXEC=$<TARGET_FILE:sql_exec>)
