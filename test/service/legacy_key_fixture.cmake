# data/schema8-legacy-keys.sql is what data/make_legacy_key_fixture.py makes
# from data/schema8-fork.sql (BTD-269): made again here and compared byte by
# byte, so the fixture and its documented recipe cannot drift apart.
#
# cmake -DPYTHON=<python3> -DOPENSSL=<openssl> -DDATA=<test/service/data>
#       -DWORK=<scratch dir> -P legacy_key_fixture.cmake

file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}")
execute_process(COMMAND "${PYTHON}" -I "${DATA}/make_legacy_key_fixture.py"
    --openssl "${OPENSSL}" "${DATA}/schema8-fork.sql" "${WORK}/made.sql"
  RESULT_VARIABLE r ERROR_VARIABLE e)
if(NOT r EQUAL 0)
  message(FATAL_ERROR "make_legacy_key_fixture.py failed (${r}): ${e}")
endif()
file(SHA256 "${WORK}/made.sql" made)
file(SHA256 "${DATA}/schema8-legacy-keys.sql" stored)
if(NOT made STREQUAL stored)
  message(FATAL_ERROR "schema8-legacy-keys.sql differs from what "
    "make_legacy_key_fixture.py makes (${made} != ${stored})")
endif()
file(REMOVE_RECURSE "${WORK}")
message(STATUS "schema8-legacy-keys.sql reproduced: ${made}")
