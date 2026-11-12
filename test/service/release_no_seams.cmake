# The test seams of xcacore are compiled only into test builds (BTD-271):
# the definition BXC_PKI_TEST_SEAMS is set on xcacore only with
# BUILD_TESTING. OBJECTS are the xcacore sources with seams compiled
# once more without it, as a build with BUILD_TESTING=OFF compiles them;
# nm -C on them must show no seam. The same names must be found in the
# xcacore of this (test) build, CORE, so that the check cannot pass on a
# pattern that matches nothing.
# cmake -DNM=<nm> -DOBJECTS=<o1|o2|...> -DCORE=<libxcacore.a>
#       -P release_no_seams.cmake

# the seams, as nm -C prints them
set(SEAMS
  "TestSeams::"
  "db_base::tokenDeleteHook"
  "db_base::tokenPrepareHook"
  "db_token::tokenRenameHook"
  "db_token::tokenRenamePrepareHook"
  "StagedFile::faultHook")
# the names of the DbTransaction seam before BTD-271; never again
set(GONE
  "DbTransaction::injected"
  "DbTransaction::injectNestedRollback"
  "DbTransaction::injectionPending")
# test-only state outside this check, reported only (BTD-271 AC3)
set(FINDINGS "certBuild::injected" "crlBuild::injected")

function(nm_lines file var)
  execute_process(COMMAND "${NM}" -C "${file}" RESULT_VARIABLE r
    OUTPUT_VARIABLE o ERROR_VARIABLE e)
  if(NOT r EQUAL 0)
    message(FATAL_ERROR "nm -C ${file}: ${r} ${e}")
  endif()
  string(REPLACE ";" "\\;" o "${o}")
  string(REPLACE "\n" ";" o "${o}")
  set(${var} "${o}" PARENT_SCOPE)
endfunction()

# lines of list that contain name (a plain substring)
function(matching var name)
  set(m "")
  foreach(l IN LISTS ARGN)
    string(FIND "${l}" "${name}" at)
    if(NOT at EQUAL -1)
      list(APPEND m "${l}")
    endif()
  endforeach()
  set(${var} "${m}" PARENT_SCOPE)
endfunction()

string(REPLACE "|" ";" OBJECTS "${OBJECTS}")
if(NOT OBJECTS)
  message(FATAL_ERROR "no objects to check")
endif()
set(found "")
foreach(o IN LISTS OBJECTS)
  nm_lines("${o}" lines)
  foreach(name IN LISTS SEAMS GONE)
    matching(m "${name}" ${lines})
    foreach(l IN LISTS m)
      get_filename_component(n "${o}" NAME)
      list(APPEND found "${n}: ${l}")
    endforeach()
  endforeach()
endforeach()
if(found)
  list(JOIN found "\n  " found)
  message(FATAL_ERROR "test seams in the objects compiled without "
    "BXC_PKI_TEST_SEAMS:\n  ${found}")
endif()
list(LENGTH OBJECTS n)
message(STATUS "${n} objects without BXC_PKI_TEST_SEAMS: no test seam")

nm_lines("${CORE}" core)
foreach(name IN LISTS SEAMS)
  matching(m "${name}" ${core})
  if(NOT m)
    message(FATAL_ERROR "${name} is not in the xcacore of this test build: "
      "the check would not see it")
  endif()
endforeach()
foreach(name IN LISTS GONE)
  matching(m "${name}" ${core})
  if(m)
    message(FATAL_ERROR "${name} is back in xcacore:\n${m}")
  endif()
endforeach()
message(STATUS "the seams are in the xcacore of this test build")

foreach(name IN LISTS FINDINGS)
  matching(m "${name}" ${core})
  if(m)
    message(STATUS "finding (test-only state, not checked): ${name}")
  endif()
endforeach()
