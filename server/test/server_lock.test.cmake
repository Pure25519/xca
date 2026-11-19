# the database lock after kill -9, in a recreated container and with
# PID 1, and in both directions between the server and the GUI or the
# CLI (BTD-302, BTD-303); db_hold opens the database like them; across
# uids (setpriv), through a symlink, without a lock file (BTD-315)
find_program(SERVER_SETPRIV setpriv)
ServerShellTest(test_server_lock server_lock.sh
	BXC_PKI=$<TARGET_FILE:bxc-pki>
	DB_HOLD=$<TARGET_FILE:db_hold>
	SETPRIV=${SERVER_SETPRIV})
