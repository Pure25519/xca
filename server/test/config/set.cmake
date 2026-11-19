# xca-server.json for a server test (BTD-320): the base config with the
# members a test sets.
# cmake -DBASE=<base.json> -DSETS=<file> -DOUT=<file> -P set.cmake
# SETS has one member per line: <JSON pointer without the leading />, a tab,
# the JSON value on one line. A member that the base config lacks is added
# (an optional one such as tls/key_password).

cmake_minimum_required(VERSION 3.19)   # string(JSON)

file(READ "${BASE}" json)
if(SETS)
  file(STRINGS "${SETS}" lines)
  foreach(line IN LISTS lines)
    string(FIND "${line}" "\t" tab)
    if(tab EQUAL -1)
      message(FATAL_ERROR "set.cmake: no tab in '${line}'")
    endif()
    string(SUBSTRING "${line}" 0 ${tab} pointer)
    math(EXPR from "${tab} + 1")
    string(SUBSTRING "${line}" ${from} -1 value)
    string(REPLACE "/" ";" path "${pointer}")
    string(JSON json ERROR_VARIABLE err SET "${json}" ${path} "${value}")
    if(err)
      message(FATAL_ERROR "set.cmake: /${pointer}: ${err}")
    endif()
  endforeach()
endif()
file(WRITE "${OUT}" "${json}\n")
