# bxc-pki: the headless command line of the fork (BTD-41, cli/README.md).
# Links xcacore only: no Qt Gui, Widgets or Help (test_core_link).

set(CLI_DIR ${PROJECT_SOURCE_DIR}/cli)

set(CLI_SOURCES
	${CLI_DIR}/main.cpp
	${CLI_DIR}/cli.h
	${CLI_DIR}/options.cpp
	${CLI_DIR}/framework.cpp
	${CLI_DIR}/input.cpp
	${CLI_DIR}/commands.cpp
	${CLI_DIR}/lifecycle.cpp
	${CLI_DIR}/export.cpp
	${CLI_DIR}/output.cpp
	${PROJECT_BINARY_DIR}/local.h)
add_executable(bxc-pki ${CLI_SOURCES})
target_link_libraries(bxc-pki xcacore ${ASAN_LIB})
set_target_properties(bxc-pki PROPERTIES MACOSX_BUNDLE FALSE)
install(TARGETS bxc-pki RUNTIME DESTINATION ${RUNTIME_DEST})

if(BUILD_TESTING)
  # Test helper: what part 1 of the CLI cannot create (templates)
  add_executable(cli_fixture ${CLI_DIR}/test/cli_fixture.cpp
	${PROJECT_BINARY_DIR}/local.h)
  target_link_libraries(cli_fixture xcacore ${ASAN_LIB})
  set_target_properties(cli_fixture PROPERTIES MACOSX_BUNDLE FALSE)
  # The same command line with file fault injection (BXC_PKI_FAULT,
  # cli/main.cpp); never installed
  add_executable(bxc-pki-faults ${CLI_SOURCES})
  target_compile_definitions(bxc-pki-faults PRIVATE BXC_PKI_FAULTS)
  target_link_libraries(bxc-pki-faults xcacore ${ASAN_LIB})
  set_target_properties(bxc-pki-faults PROPERTIES MACOSX_BUNDLE FALSE)
  add_dependencies(tests bxc-pki cli_fixture bxc-pki-faults)

  find_program(CLI_OPENSSL openssl HINTS ${OPENSSL_ROOT_DIR}/bin)
  find_program(CLI_SCRIPT script)
  find_program(CLI_SETPRIV setpriv)
  find_program(CLI_LDD ldd)

  # CliTest(<name>): cli/test/<name>.cmake as ctest test_<name>, label cli
  macro(CliTest name)
    add_test(NAME test_${name}
	COMMAND ${CMAKE_COMMAND}
		-DBXC_PKI=$<TARGET_FILE:bxc-pki>
		-DBXC_PKI_FAULTS=$<TARGET_FILE:bxc-pki-faults>
		-DXCA=$<TARGET_FILE:${CMAKE_PROJECT_NAME}>
		-DFIXTURE=$<TARGET_FILE:cli_fixture>
		-DSQL_EXEC=$<TARGET_FILE:sql_exec>
		-DOPENSSL=${CLI_OPENSSL}
		-DSCRIPT=${CLI_SCRIPT}
		-DSETPRIV=${CLI_SETPRIV}
		-DLDD=${CLI_LDD}
		-DLIB=${CLI_DIR}/test/cli_lib.cmake
		-DWORK=${CMAKE_CURRENT_BINARY_DIR}/cli_${name}
		-P ${CLI_DIR}/test/${name}.cmake)
    set_tests_properties(test_${name} PROPERTIES LABELS cli)
    if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.22)
      set_property(TEST test_${name} APPEND PROPERTY
	ENVIRONMENT_MODIFICATION QT_QPA_PLATFORM=unset:)
    endif()
  endmacro()

  CliTest(cli_flow)
  CliTest(cli_options)
  CliTest(cli_secrets)
  CliTest(cli_input)
  CliTest(cli_validity)
  CliTest(cli_errors)
  CliTest(cli_json_forms)
  CliTest(cli_keytypes)
  CliTest(cli_plan)
  # rules 1 and 5 through the checks of BTD-55
  CliTest(cli_sign_checks)
  # rule 3, key usage by key type for templates (BTD-195)
  CliTest(cli_sign_checks_pending)
  # part 2 (BTD-42): revoke, crl, export, --out, trust lists, files
  CliTest(cli_revoke)
  CliTest(cli_crl)
  CliTest(cli_export)
  CliTest(cli_out)
  CliTest(cli_trustlist)
  CliTest(cli_files)
  # hardening of lib/staged_file (BTD-210): publish without hard links,
  # temporary files left behind, directory swaps, long names
  CliTest(cli_files_noreplace)
  CliTest(cli_files_tempfiles)
  CliTest(cli_files_dirswap)
  CliTest(cli_files_longname)
  # the default templates of misc/ by key type (BTD-195)
  CliTest(cli_default_templates)
  # RFC 5280 upper bounds of DN values (BTD-202)
  CliTest(cli_dn_bounds)
  # renewal and re-key (BTD-56)
  CliTest(cli_renew)
  # a read-only command leaves the database file byte-identical (BTD-225)
  CliTest(cli_readonly)
endif()
