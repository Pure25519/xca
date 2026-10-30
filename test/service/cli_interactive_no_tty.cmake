# xca --no-gui --interactive without a terminal on stdin (BTD-145): the
# password prompt cannot be answered, so the command ends with a password
# error that names the sources, not with "Inappropriate ioctl for device".
# cmake -DXCA=<path to xca> -DWORK=<scratch dir> -P cli_interactive_no_tty.cmake

file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}/home")
set(ENV{HOME} "${WORK}/home")
set(ENV{XDG_CONFIG_HOME} "${WORK}/home/.config")
set(ENV{XDG_DATA_HOME} "${WORK}/home/.local/share")
set(ENV{QT_QPA_PLATFORM} offscreen)

# stdin is a regular file, never a terminal
file(WRITE "${WORK}/stdin.txt" "")
execute_process(COMMAND "${XCA}" --no-gui --interactive
		--database "${WORK}/new.xdb" --list-items
	INPUT_FILE "${WORK}/stdin.txt"
	RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE out
	TIMEOUT 30)
file(REMOVE_RECURSE "${WORK}")

if(rc EQUAL 0)
  message(FATAL_ERROR "expected a non-zero exit code, got '${rc}':\n${out}")
endif()
if(out MATCHES "Inappropriate ioctl")
  message(FATAL_ERROR "terminal error instead of a password error:\n${out}")
endif()
if(NOT out MATCHES "no terminal")
  message(FATAL_ERROR "the error does not say that no terminal is there:\n${out}")
endif()
if(NOT out MATCHES "--password")
  message(FATAL_ERROR "the error does not name the password option:\n${out}")
endif()
message(STATUS "xca --no-gui --interactive without terminal: password error, exit ${rc}")
