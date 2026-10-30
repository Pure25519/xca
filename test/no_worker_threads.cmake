# testxca drives dialogs from the GUI thread only (BTD-180). A worker
# thread that clicks in a dialog races with the GUI thread and crashed
# testxca now and then. This test fails on any QThread::create in test/;
# a test answers a dialog with whenShown() of test/main.h instead.
# cmake -DSRC=<fork source dir> -P no_worker_threads.cmake

file(GLOB_RECURSE sources "${SRC}/test/*.cpp" "${SRC}/test/*.h")
set(found "")
foreach(f IN LISTS sources)
  file(STRINGS "${f}" hits REGEX "QThread::create")
  if(hits)
    file(RELATIVE_PATH rel "${SRC}" "${f}")
    list(APPEND found "${rel}: ${hits}")
  endif()
endforeach()
if(found)
  list(JOIN found "\n" text)
  message(FATAL_ERROR "QThread::create in test/ (drive the dialog with "
    "whenShown() in the GUI thread, BTD-180):\n${text}")
endif()
