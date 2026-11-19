# the rate limit of auth.denied with simulated peers and clock (BTD-314)
if(NOT WIN32)
  add_executable(test_server_denied_limit
	${SERVER_DIR}/test/test_denied_limit.cpp
	${SERVER_DIR}/denied_limit.cpp ${SERVER_DIR}/denied_limit.h)
  target_include_directories(test_server_denied_limit PRIVATE ${SERVER_DIR})
  target_link_libraries(test_server_denied_limit PRIVATE
	${QT}::Core ${QT}::Test ${ASAN_LIB})
  set_target_properties(test_server_denied_limit PROPERTIES
	MACOSX_BUNDLE FALSE)
  add_dependencies(tests test_server_denied_limit)
  add_test(NAME test_server_denied_limit COMMAND test_server_denied_limit)
  ServerTest(test_server_denied_limit)
endif()
