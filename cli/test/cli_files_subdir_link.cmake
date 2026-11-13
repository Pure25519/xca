# The subdirectories of a staged trust list never follow a link
# (BTD-213 (2)): the test build places a symbolic link at the path of the
# staging subdirectory "trusted" right before the run creates it
# (symlink:subdir:<path>), pointing to a directory outside the staging
# tree. The export fails with target_directory_changed, nothing is written
# through the link, and the earlier trust list stays as it was.
#
# Before, OutputFiles::add() created these subdirectories with
# QDir::mkpath(), which follows a link.

include("${LIB}")

set(OUTSIDE "/tmp/bxc-pki-outside")
file(REMOVE_RECURSE "${OUTSIDE}")
file(MAKE_DIRECTORY "${WORK}/tl")

bxc("init" 0 init --db "${DB}" ${PW} --cn "L Root" --key ec-p256)
bxc("trust list" 0 export "L Root" --db "${DB}" ${PW} --format trustlist
    --out tl)
file(SHA256 "${WORK}/tl/manifest.json" before)

fx("link at subdir" 1 "symlink:subdir:/trusted" export "L Root" --db "${DB}"
    ${PW} --format trustlist --out tl --force)
expect_error("link at subdir" target_directory_changed)
file(GLOB_RECURSE through "${OUTSIDE}/*")
if(through)
  fail("files were written through the link: ${through}")
endif()
file(SHA256 "${WORK}/tl/manifest.json" after)
if(NOT before STREQUAL after)
  fail("the earlier trust list changed")
endif()
file(REMOVE_RECURSE "${OUTSIDE}")
message(STATUS "link at subdir: target_directory_changed, nothing written")

# The same link after the subdirectory was created, right before a staged
# file opens it (review of xca#172): swapdir:opendir renames
# trusted/certs to trusted/certs.moved and puts a link to
# trusted/certs.other in its place. The file keeps the directory that
# makeParents() created and opened; it is not opened again by its path,
# which would resolve the link. The export fails with
# target_directory_changed and the earlier trust list stays as it was.
fx("link before open" 1 "swapdir:opendir:/trusted/certs/" export "L Root"
    --db "${DB}" ${PW} --format trustlist --out tl --force)
expect_error("link before open" target_directory_changed)
file(SHA256 "${WORK}/tl/manifest.json" after)
if(NOT before STREQUAL after)
  fail("link before open: the earlier trust list changed")
endif()
if(EXISTS "${WORK}/tl/trusted/certs.other" OR EXISTS "${WORK}/tl/trusted/certs.moved")
  fail("link before open: the swapped directories reached the trust list")
endif()
file(GLOB left "${WORK}/.*bxc-tmp*")
if(left)
  fail("link before open: staging directories stay: ${left}")
endif()
message(STATUS "link before open: target_directory_changed")
