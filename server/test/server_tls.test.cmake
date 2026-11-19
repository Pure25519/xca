# every mTLS refusal with its alert, the server alive afterwards (BTD-306)
ServerShellTest(test_server_tls server_tls.sh
	BXC_PKI=$<TARGET_FILE:bxc-pki>)
