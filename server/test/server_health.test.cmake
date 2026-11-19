# the health listener: /health and /ready over plain HTTP on loopback, not
# ready while the database is locked or the worker is stuck (BTD-163)
find_program(SERVER_CURL curl)
ServerShellTest(test_server_health server_health.sh
	BXC_PKI=$<TARGET_FILE:bxc-pki>
	SQL_EXEC=$<TARGET_FILE:sql_exec>
	CURL=${SERVER_CURL})
