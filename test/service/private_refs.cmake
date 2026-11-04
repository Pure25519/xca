# The public fork carries no internal references (BTD-236): no SMP ticket
# keys and no URL of a private repository (bxc-pki, the IDIAL GitLab) in
# the test data, the command line and the library. The bxc-pki profiles,
# policies and their PROVENANCE files are copies; fix them in bxc-pki.
# No lab domain and no lab network either: tests use example.org and the
# RFC 5737 ranges (BTD-245); the networks also in the regex-escaped form
# of the CMake checks (192\\.168...).
file(GLOB_RECURSE files
  "${SRC}/test/service/data/*.json" "${SRC}/test/service/data/*.md"
  "${SRC}/test/*.cpp" "${SRC}/cli/test/*.cmake"
  "${SRC}/cli/test/data/*.json"
  "${SRC}/cli/*.cpp" "${SRC}/cli/*.h" "${SRC}/cli/*.md"
  "${SRC}/lib/*.cpp" "${SRC}/lib/*.h" "${SRC}/widgets/*.cpp")
set(found "")
foreach(f IN LISTS files)
  file(STRINGS "${f}" lines REGEX
    "SMP-[0-9]+|gitlab[.]com/bxc|github[.]com/Pure25519/bxc-pki|bxc-technology|10[.\\\\]+10[.\\\\]+10[.\\\\]|192[.\\\\]+168[.\\\\]+0[.\\\\]")
  foreach(l IN LISTS lines)
    file(RELATIVE_PATH rel "${SRC}" "${f}")
    string(APPEND found "${rel}: ${l}\n")
  endforeach()
endforeach()
if(found)
  message(FATAL_ERROR "internal references in the public fork:\n${found}")
endif()
message(STATUS "no internal references")
