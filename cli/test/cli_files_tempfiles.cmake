# Temporary files that stay behind (BTD-210 b): a killed run leaves a
# hidden ".<name>.bxc-tmp-<16 hex>" (possibly a plaintext key). stage()
# removes such files of this user in its directory when they are older than
# 10 minutes (any <name>; regular files only) and reports them with the
# warning stale_temp_removed; a younger one belongs to a run that may still
# be going and stays. A temporary file that cannot be removed after the
# link() publish is the warning temp_file_left with its path.

include("${LIB}")

set(D "${WORK}/st")
file(MAKE_DIRECTORY "${D}")

bxc("init" 0 init --db "${DB}" ${PW} --cn "T Root" --key ec-p256)

# temporary files of killed runs: one made old, one young (both are made
# before the first is aged: the second run would remove the old one)
fx("killed at write" 137 "kill:write:T_Root.crl" crl --ca "T Root"
    --db "${DB}" ${PW} --out st --layout certstrap)
file(GLOB old "${D}/.T_Root.crl.bxc-tmp-*")
list(LENGTH old n)
if(NOT n EQUAL 1)
  fail("a run killed at write left ${n} temporary files: ${old}")
endif()
fx("killed at sync" 137 "kill:sync:T_Root.crl" crl --ca "T Root"
    --db "${DB}" ${PW} --out st --layout certstrap)
file(GLOB young "${D}/.T_Root.crl.bxc-tmp-*")
list(REMOVE_ITEM young "${old}")
list(LENGTH young n)
if(NOT n EQUAL 1)
  fail("a run killed at sync left ${n} temporary files: ${young}")
endif()
execute_process(COMMAND touch -d "1 hour ago" "${old}" RESULT_VARIABLE r)
if(NOT r EQUAL 0)
  fail("touch -d failed")
endif()

# old things that are no temporary file of ours: they stay
set(keep "${D}/.other.bxc-tmp-0123" "${D}/.notours.bxc-tmp-0123456789abcdef"
    "${D}/plain.bxc-tmp-0123456789abcdef")
foreach(f IN LISTS keep)
  file(WRITE "${f}" "keep\n")
endforeach()
file(MAKE_DIRECTORY "${D}/.dir.bxc-tmp-0123456789abcdef")
file(CREATE_LINK "${D}/plain.bxc-tmp-0123456789abcdef"
    "${D}/.link.bxc-tmp-0123456789abcdef" SYMBOLIC)
list(APPEND keep "${D}/.link.bxc-tmp-0123456789abcdef")
execute_process(COMMAND id -u OUTPUT_VARIABLE uid
  OUTPUT_STRIP_TRAILING_WHITESPACE)
if(uid STREQUAL "0")
  # as root: a file of another user stays
  execute_process(COMMAND chown 65534 "${D}/.notours.bxc-tmp-0123456789abcdef"
    RESULT_VARIABLE r)
  if(NOT r EQUAL 0)
    fail("chown failed")
  endif()
else()
  list(REMOVE_ITEM keep "${D}/.notours.bxc-tmp-0123456789abcdef")
  file(REMOVE "${D}/.notours.bxc-tmp-0123456789abcdef")
endif()
foreach(f IN LISTS keep ITEMS "${D}/.dir.bxc-tmp-0123456789abcdef")
  execute_process(COMMAND touch -h -d "1 hour ago" "${f}")
endforeach()

# the next run removes the old one and says so
bxc("next run" 0 crl --ca "T Root" --db "${DB}" ${PW} --out st
    --layout certstrap)
one_doc("next run" "${out}" cli-result r)
warning_codes("${r}" codes)
if(NOT codes MATCHES "stale_temp_removed")
  fail("no warning stale_temp_removed: ${codes}")
endif()
warning_detail("${r}" stale_temp_removed d)
get_filename_component(oldname "${old}" NAME)
if(NOT d MATCHES "${oldname}" OR NOT d MATCHES "/st'")
  fail("stale_temp_removed does not name ${oldname} and the directory: ${d}")
endif()
if(EXISTS "${old}")
  fail("the old temporary file ${old} stays")
endif()
if(NOT EXISTS "${young}")
  fail("the young temporary file ${young} was removed")
endif()
foreach(f IN LISTS keep ITEMS "${D}/.dir.bxc-tmp-0123456789abcdef")
  if(NOT EXISTS "${f}" AND NOT IS_SYMLINK "${f}")
    fail("${f} is no temporary file of this user, but was removed")
  endif()
endforeach()
if(NOT EXISTS "${D}/T_Root.crl")
  fail("the CRL file was not written")
endif()

# a temporary file that cannot be removed after link(): temp_file_left
fx("unlink fails" 0 "fail:noreplace:T_Root-,fail:unlink:T_Root-" crl
    --ca "T Root" --db "${DB}" ${PW} --out st)
one_doc("unlink fails" "${out}" cli-result r)
warning_codes("${r}" codes)
if(NOT codes MATCHES "temp_file_left")
  fail("no warning temp_file_left: ${codes}")
endif()
warning_detail("${r}" temp_file_left d)
file(GLOB left "${D}/.T_Root-*.crl.bxc-tmp-*")
list(LENGTH left n)
if(NOT n EQUAL 1)
  fail("unlink fails: expected one temporary file, got ${left}")
endif()
get_filename_component(leftname "${left}" NAME)
string(REPLACE "." "\\." leftre "${leftname}")
if(NOT d MATCHES "/st/${leftre}")
  fail("temp_file_left does not name ${left}: ${d}")
endif()
file(GLOB crls "${D}/T_Root-*.crl")
if(NOT crls)
  fail("unlink fails: the CRL file was not published")
endif()
