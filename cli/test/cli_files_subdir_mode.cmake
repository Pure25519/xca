# The subdirectories of a staged trust list get the mode of the top
# directory (BTD-280 item 2). BTD-213 (4) gave the published directory the
# mode of the directory it replaces; its subdirectories kept the mode of
# their creation (0777 & umask). A trust list made private with mode 0700
# stays private below its top directory after an export with --force.

include("${LIB}")

file(MAKE_DIRECTORY "${WORK}/tl")

# the mode of a path as octal digits, e.g. "700"
function(mode_of var path)
  execute_process(COMMAND stat -c %a "${path}" RESULT_VARIABLE r
    OUTPUT_VARIABLE o ERROR_VARIABLE e)
  if(NOT r EQUAL 0)
    fail("stat ${path}: ${r} ${e}")
  endif()
  string(STRIP "${o}" o)
  set(${var} "${o}" PARENT_SCOPE)
endfunction()

bxc("init" 0 init --db "${DB}" ${PW} --cn "M Root" --key ec-p256)
bxc("trust list" 0 export "M Root" --db "${DB}" ${PW} --format trustlist
    --out tl)
file(CHMOD "${WORK}/tl" DIRECTORY_PERMISSIONS OWNER_READ OWNER_WRITE
  OWNER_EXECUTE)

bxc("replace" 0 export "M Root" --db "${DB}" ${PW} --format trustlist
    --out tl --force)
file(GLOB_RECURSE dirs LIST_DIRECTORIES true "${WORK}/tl/*")
list(FILTER dirs EXCLUDE REGEX "\\.(der|crl|json)$")
if(NOT dirs)
  fail("the trust list has no subdirectories: nothing to check")
endif()
foreach(d "${WORK}/tl" ${dirs})
  if(NOT IS_DIRECTORY "${d}")
    continue()
  endif()
  mode_of(m "${d}")
  if(NOT m STREQUAL "700")
    fail("${d} has mode ${m}, expected 700 like the replaced trust list")
  endif()
endforeach()
message(STATUS "subdirectories keep the mode 700 of the replaced trust list")
