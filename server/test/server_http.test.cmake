# methods outside cpp-httplib's built-in set and header lines over
# header_max_bytes get their contract answer (BTD-318, BTD-319)
ServerShellTest(test_server_http server_http.sh
	BXC_PKI=$<TARGET_FILE:bxc-pki>)
