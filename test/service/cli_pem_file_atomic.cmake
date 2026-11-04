# xca --no-gui --pem-file writes through StagedFile (BTD-139): a write that
# fails after the file was opened leaves an existing file as it was and
# exits non-zero. Before, the file was emptied first and the failed write
# went unnoticed. The failure is a real one: ulimit -f 0 makes every
# write fail with EFBIG (SIGXFSZ ignored), as a full disk would.
# cmake -DXCA=<xca> -DWORK=<scratch dir> -P cli_pem_file_atomic.cmake

file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}/home")
set(ENV{HOME} "${WORK}/home")
set(ENV{XDG_CONFIG_HOME} "${WORK}/home/.config")
set(ENV{XDG_DATA_HOME} "${WORK}/home/.local/share")
set(ENV{QT_QPA_PLATFORM} offscreen)
set(db --database "${WORK}/pem.xdb" --password pass:btd139-db-pass)
set(pem "${WORK}/out.pem")

function(fail msg)
  file(REMOVE_RECURSE "${WORK}")
  message(FATAL_ERROR "${msg}")
endfunction()

execute_process(COMMAND "${XCA}" --no-gui ${db} --keygen RSA:2048 --name pem-key
  RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE out TIMEOUT 60)
if(NOT rc EQUAL 0)
  fail("keygen: exit '${rc}':\n${out}")
endif()
execute_process(COMMAND "${XCA}" --no-gui ${db} --select 1 --pem-file "${pem}"
  RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE out TIMEOUT 60)
file(READ "${pem}" before)
if(NOT rc EQUAL 0 OR NOT before MATCHES "BEGIN PUBLIC KEY")
  fail("first --pem-file: exit '${rc}', file:\n${before}\n${out}")
endif()

execute_process(COMMAND sh -c "trap '' XFSZ; ulimit -f 0; exec \"$0\" \"$@\""
    "${XCA}" --no-gui ${db} --select 1 --pem-file "${pem}"
  RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE out TIMEOUT 60)
file(READ "${pem}" after)
if(NOT after STREQUAL before)
  fail("the failed --pem-file write changed the old file (exit '${rc}'):\n${after}\n${out}")
endif()
if(rc EQUAL 0)
  fail("the failed --pem-file write exited 0:\n${out}")
endif()
file(REMOVE_RECURSE "${WORK}")
message(STATUS "xca --no-gui: a failed --pem-file write keeps the old file and exits non-zero")
