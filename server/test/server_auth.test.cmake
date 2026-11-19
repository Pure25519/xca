# The operation table of roles.json (BTD-155) as lines for the shell test:
# <operation_id> <METHOD> <path> <roles, comma separated> <ca_param or ->
string(JSON server_ops_n LENGTH "${server_roles_json}" operations)
math(EXPR server_ops_last "${server_ops_n} - 1")
set(server_roles_tsv "")
foreach(i RANGE ${server_ops_last})
  string(JSON op GET "${server_roles_json}" operations ${i} operation_id)
  string(JSON method GET "${server_roles_json}" operations ${i} method)
  string(JSON path GET "${server_roles_json}" operations ${i} path)
  string(JSON ca_type TYPE "${server_roles_json}" operations ${i} ca_param)
  if(ca_type STREQUAL "NULL")
    set(ca "-")
  else()
    string(JSON ca GET "${server_roles_json}" operations ${i} ca_param)
  endif()
  string(JSON roles_n LENGTH "${server_roles_json}" operations ${i} roles)
  math(EXPR roles_last "${roles_n} - 1")
  set(roles "")
  foreach(j RANGE ${roles_last})
    string(JSON role GET "${server_roles_json}" operations ${i} roles ${j})
    list(APPEND roles ${role})
  endforeach()
  string(REPLACE ";" "," roles "${roles}")
  string(APPEND server_roles_tsv "${op} ${method} ${path} ${roles} ${ca}\n")
endforeach()
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/server_roles.tsv "${server_roles_tsv}")
# TLS, mTLS or API keys, the roles of every operation, the CA scope, the
# audit entries auth.login and auth.denied with their rate limit, reload
# (BTD-155, BTD-311, BTD-314)
ServerShellTest(test_server_auth server_auth.sh
	BXC_PKI=$<TARGET_FILE:bxc-pki>
	XCA=$<TARGET_FILE:${CMAKE_PROJECT_NAME}>
	SQL_EXEC=$<TARGET_FILE:sql_exec>
	ROLES_TSV=${CMAKE_CURRENT_BINARY_DIR}/server_roles.tsv)
