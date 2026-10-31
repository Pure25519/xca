
list(APPEND srcs PwDialogMock.h importPEM.cpp main.cpp main.h
	newKey.cpp pem.cpp export.cpp renewal.cpp staleReload.cpp dialogParent.cpp validity.cpp policy.cpp crlRefused.cpp kuByKeyType.cpp dnBounds.cpp issueInAccept.cpp ekuRows.cpp templateRoundTrip.cpp
	automationIds.cpp issuanceExt.cpp exportMlDsa.cpp optionsChanged.cpp TestEnv.cpp TestEnv.h)

list(TRANSFORM srcs PREPEND ${PROJECT_SOURCE_DIR}/test/)

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

if (APPLE)
  target_link_libraries(testxca
	${IOKIT_LIBRARY} ${COREFOUNDATION_LIBRARY}
  )
endif()

include(test/service/CMakeLists.txt)
