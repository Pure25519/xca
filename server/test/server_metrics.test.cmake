# GET /v1/metrics: audit counters, remaining lifetime, access, cache and
# the cardinality limit (BTD-163)
ServerShellTest(test_server_metrics server_metrics.sh
	BXC_PKI=$<TARGET_FILE:bxc-pki>
	SQL_EXEC=$<TARGET_FILE:sql_exec>)
