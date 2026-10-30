# xca --no-gui --keygen knows the key types without size or curve (BTD-16):
# Ed25519, Ed448, ML-DSA-44/65/87 and the twelve SLH-DSA parameter sets.
# --help names each of them; a size for such a type is rejected, not dropped.
# cmake -DXCA=<path to xca> -DWORK=<scratch dir> -P cli_keygen_types.cmake

file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}/home")
set(ENV{HOME} "${WORK}/home")
set(ENV{XDG_CONFIG_HOME} "${WORK}/home/.config")
set(ENV{XDG_DATA_HOME} "${WORK}/home/.local/share")
set(ENV{QT_QPA_PLATFORM} offscreen)

function(fail msg)
  file(REMOVE_RECURSE "${WORK}")
  message(FATAL_ERROR "${msg}")
endfunction()

set(types ED25519 ED448 ML-DSA-44 ML-DSA-65 ML-DSA-87
  SLH-DSA-SHA2-128s SLH-DSA-SHA2-128f SLH-DSA-SHA2-192s SLH-DSA-SHA2-192f
  SLH-DSA-SHA2-256s SLH-DSA-SHA2-256f SLH-DSA-SHAKE-128s SLH-DSA-SHAKE-128f
  SLH-DSA-SHAKE-192s SLH-DSA-SHAKE-192f SLH-DSA-SHAKE-256s SLH-DSA-SHAKE-256f)
set(db --database "${WORK}/keygen.xdb" --password pass:keygen-test)

# xca(<args>...): runs xca --no-gui; sets rc and out (stdout and stderr)
function(xca)
  execute_process(COMMAND "${XCA}" --no-gui ${ARGN}
    RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE out TIMEOUT 60)
  set(rc "${rc}" PARENT_SCOPE)
  set(out "${out}" PARENT_SCOPE)
endfunction()

xca(--help)
foreach(t IN LISTS types)
  string(FIND "${out}" "${t}" pos)
  if(pos EQUAL -1)
    fail("--help does not name the key type ${t}:\n${out}")
  endif()
endforeach()

foreach(t IN LISTS types)
  xca(${db} --keygen ${t} --name key-${t})
  if(NOT rc EQUAL 0)
    fail("--keygen ${t} failed (${rc}):\n${out}")
  endif()
endforeach()

# The type name is not case-sensitive
xca(${db} --keygen ml-dsa-44 --name key-lower)
if(NOT rc EQUAL 0)
  fail("--keygen ml-dsa-44 failed (${rc}):\n${out}")
endif()

xca(${db} --list-items)
foreach(t IN LISTS types ITEMS lower)
  if(NOT out MATCHES "key-${t}")
    fail("--list-items misses key-${t}:\n${out}")
  endif()
endforeach()

# A size for a type without size ends the command with an error. The
# command line checks only the type; the size is rejected by the key
# generation service, which audits it (BTD-41)
foreach(job ML-DSA-65:2048 ED448:456)
  xca(${db} --keygen ${job} --name rejected)
  if(rc EQUAL 0 OR NOT out MATCHES "takes no size or curve")
    fail("--keygen ${job} was not rejected (${rc}):\n${out}")
  endif()
endforeach()
xca(${db} --keygen ML-DSA-99 --name rejected)
if(rc EQUAL 0 OR NOT out MATCHES "Unknown key type ML-DSA-99")
  fail("--keygen ML-DSA-99 was not rejected (${rc}):\n${out}")
endif()
xca(${db} --list-items)
if(out MATCHES "rejected")
  fail("a rejected --keygen stored a key:\n${out}")
endif()

file(REMOVE_RECURSE "${WORK}")
