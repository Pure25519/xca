# A directory swapped between stage and publish (BTD-210 c): StagedFile
# and StagedDirectory open their directory once and do every later step
# relative to that descriptor, and check right before the publish that the
# path still leads to the same directory. The fault mode swapdir renames
# the directory away (<dir>.moved) and puts a symbolic link to <dir>.other
# in its place, after the database commit:
#  - a key file: it must not appear in the other directory; the run fails
#    (publish_failed with target_directory_changed) and no key or
#    temporary file stays anywhere;
#  - a trust-list directory replaced by a link to another trust list: the
#    other list is neither replaced nor emptied; the run fails.

include("${LIB}")

bxc("init" 0 init --db "${DB}" ${PW} --cn "S Root" --key ec-p256)

# --- the directory of a key file ---------------------------------------------
file(MAKE_DIRECTORY "${WORK}/sw")
fx("key directory swapped" 1 "swapdir:publish:sw/k1.key" request-cert
    --db "${DB}" ${PW} --cn k1 --out sw --layout certstrap --key-unencrypted)
expect_error("key directory swapped" publish_failed)
if(NOT detail MATCHES "target_directory_changed")
  fail("key directory swapped: not target_directory_changed: ${detail}")
endif()
if(NOT IS_SYMLINK "${WORK}/sw" OR NOT IS_DIRECTORY "${WORK}/sw.moved")
  fail("the fault mode swapdir did not swap the directory")
endif()
listing("${WORK}/sw.other" l)
if(l)
  fail("files appeared in the directory the link points to: ${l}")
endif()
file(GLOB_RECURSE all LIST_DIRECTORIES false "${WORK}/sw.moved/*"
  "${WORK}/sw.moved/.*" "${WORK}/sw.other/*" "${WORK}/sw.other/.*")
foreach(f IN LISTS all)
  if(f MATCHES "k1\\.key" OR f MATCHES "bxc-tmp")
    fail("a key or temporary file stays: ${f}")
  endif()
endforeach()

# --- a trust-list directory --------------------------------------------------
file(MAKE_DIRECTORY "${WORK}/p/tl" "${WORK}/p/tl.other")
bxc("other list" 0 export "S Root" --db "${DB}" ${PW} --format trustlist
    --out p/tl.other)
file(SHA256 "${WORK}/p/tl.other/manifest.json" m1)
file(GLOB_RECURSE other1 LIST_DIRECTORIES false "${WORK}/p/tl.other/*")
fx("list directory swapped" 1 "swapdir:swap:/p/tl" export "S Root" --db "${DB}"
    ${PW} --format trustlist --out p/tl --force)
expect_error("list directory swapped" publish_failed)
if(NOT detail MATCHES "target_directory_changed")
  fail("list directory swapped: not target_directory_changed: ${detail}")
endif()
if(NOT IS_SYMLINK "${WORK}/p/tl")
  fail("the link in place of the trust list was replaced")
endif()
file(GLOB_RECURSE other2 LIST_DIRECTORIES false "${WORK}/p/tl.other/*")
if(NOT EXISTS "${WORK}/p/tl.other/manifest.json" OR NOT other1 STREQUAL other2)
  fail("the other trust list was changed: ${other1} -> ${other2}")
endif()
file(SHA256 "${WORK}/p/tl.other/manifest.json" m2)
if(NOT m1 STREQUAL m2)
  fail("the manifest of the other trust list changed")
endif()
file(GLOB left LIST_DIRECTORIES true "${WORK}/p/.tl.bxc-tmp-*")
if(left)
  fail("the staging directory stays: ${left}")
endif()
