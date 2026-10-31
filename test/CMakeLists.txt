
# Every source directly in test/ belongs to testxca (BTD-256): a new test
# file needs no line here. Its slots go into test/main.h, see test/README.md.
file(GLOB srcs CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/test/*.cpp
	${PROJECT_SOURCE_DIR}/test/*.h)
list(SORT srcs)

add_executable(testxca img/imgres.qrc ${srcs}
		${UI_FILES} ${PROJECT_BINARY_DIR}/local.h)

# the policy examples of test/service/data (BTD-167)
target_compile_definitions(testxca PRIVATE
	XCA_SOURCE_DIR="${PROJECT_SOURCE_DIR}")

add_test(NAME testxca COMMAND testxca)
set_tests_properties(testxca PROPERTIES LABELS gui)
add_dependencies(tests testxca)

# Automation IDs (BTD-61, doc/automation-ids.md), also part of testxca.
# The second run is kept on purpose (BTD-83): ctest -R test_automation_ids
# checks the IDs alone, and under ctest --parallel it costs no wall-clock time.
# Both entries may run at the same time: testxca works in its own temporary
# HOME and working directory (test/TestEnv.h), so they share no files.
add_test(NAME test_automation_ids COMMAND testxca automationIds)
set_tests_properties(test_automation_ids PROPERTIES LABELS gui
	ENVIRONMENT QT_QPA_PLATFORM=offscreen)
target_link_libraries(testxca ${ASAN_LIB} ${QT}::Test xcagui)

# No test drives a dialog from a worker thread (BTD-180)
add_test(NAME test_no_worker_threads
	COMMAND ${CMAKE_COMMAND} -DSRC=${PROJECT_SOURCE_DIR}
		-P ${PROJECT_SOURCE_DIR}/test/no_worker_threads.cmake)
set_tests_properties(test_no_worker_threads PROPERTIES LABELS service)
target_link_options(testxca PRIVATE -pthread)

# Exactly one libcrypto, OpenSSL 4, in xca, bxc-pki and the test binaries
# (BTD-251): a preload library lists the loaded objects at process exit.
# The _injected run preloads the Debian libcrypto.so.3 and must be caught.
if(UNIX AND NOT APPLE)
  add_library(loadcheck MODULE ${PROJECT_SOURCE_DIR}/test/loadcheck/loadcheck.cpp)
  target_link_libraries(loadcheck ${ASAN_LIB})
  add_dependencies(tests loadcheck)
  find_file(LOADCHECK_LIBCRYPTO3 libcrypto.so.3
	PATHS /usr/lib/x86_64-linux-gnu /usr/lib/aarch64-linux-gnu /usr/lib64 /usr/lib
	NO_DEFAULT_PATH)
  set(modes clean)
  if(LOADCHECK_LIBCRYPTO3)
    list(APPEND modes injected)
  endif()
  foreach(mode IN LISTS modes)
    set(name test_one_libcrypto)
    if(mode STREQUAL "injected")
      set(name test_one_libcrypto_injected)
    endif()
    add_test(NAME ${name}
	COMMAND ${CMAKE_COMMAND} -DMODE=${mode}
		-DLOADCHECK=$<TARGET_FILE:loadcheck>
		-DINJECT=${LOADCHECK_LIBCRYPTO3}
		-DXCA=$<TARGET_FILE:${CMAKE_PROJECT_NAME}>
		-DBXC_PKI=$<TARGET_FILE:bxc-pki>
		-DTESTXCA=$<TARGET_FILE:testxca>
		-DSERVICE_TEST=$<TARGET_FILE:test_service_audit>
		-DWORK=${CMAKE_CURRENT_BINARY_DIR}/${name}
		-P ${PROJECT_SOURCE_DIR}/test/loadcheck/one_libcrypto.cmake)
    set_tests_properties(${name} PROPERTIES LABELS service)
  endforeach()
endif()

if (APPLE)
  target_link_libraries(testxca
	${IOKIT_LIBRARY} ${COREFOUNDATION_LIBRARY}
  )
endif()

include(test/service/CMakeLists.txt)
