# threads and accept queue of cpp-httplib bounded by the config (BTD-304)
ServerShellTest(test_server_limits server_limits.sh
	BXC_PKI=$<TARGET_FILE:bxc-pki>)
