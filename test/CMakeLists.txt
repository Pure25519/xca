
list(APPEND srcs PwDialogMock.h importPEM.cpp main.cpp main.h
	newKey.cpp pem.cpp export.cpp renewal.cpp validity.cpp
	automationIds.cpp issuanceExt.cpp)

list(TRANSFORM srcs PREPEND ${PROJECT_SOURCE_DIR}/test/)

add_executable(testxca img/imgres.qrc ${srcs}
		${UI_FILES} ${PROJECT_BINARY_DIR}/local.h)

add_test(NAME testxca COMMAND testxca)
set_tests_properties(testxca PROPERTIES LABELS gui)
add_dependencies(tests testxca)

# Automation IDs (BTD-61, doc/automation-ids.md), also part of testxca
add_test(NAME test_automation_ids COMMAND testxca automationIds)
set_tests_properties(test_automation_ids PROPERTIES LABELS gui
	ENVIRONMENT QT_QPA_PLATFORM=offscreen)
target_link_libraries(testxca ${ASAN_LIB} ${QT}::Test xcalib)
target_link_options(testxca PRIVATE -pthread)

if (APPLE)
  target_link_libraries(testxca
	${IOKIT_LIBRARY} ${COREFOUNDATION_LIBRARY}
  )
endif()

include(test/service/CMakeLists.txt)
