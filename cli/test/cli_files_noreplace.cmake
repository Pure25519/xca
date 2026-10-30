# Publishing without --force on a file system without hard links (BTD-210
# a): a new file is published with renameat2(RENAME_NOREPLACE), with
# link() only where the file system rejects that flag; stage() probes
# before the database commit that one of them works in the target
# directory. A directory where neither works (vfat, exFAT, SMB, FUSE
# without link support) is refused with target_filesystem_unsupported
# before anything is stored, not with publish_failed after the commit
# ("object stored, file missing").
#  - fail:probe:<file> and fail:publish:<file> together: the file system
#    of vfat (neither works; before BTD-210 only the publish step existed);
#  - fail:noreplace:<file>: the file system rejects RENAME_NOREPLACE
#    (EINVAL), the link() fallback publishes the file;
#  - addtarget:publish:<file>: the target appears between stage and
#    publish; it is never overwritten (file_exists), on both ways.
# A vfat loop mount runs only where the container may mount (normally
# not; then the test says so and skips that part).

include("${LIB}")

set(D "${WORK}/f")
file(MAKE_DIRECTORY "${D}")

bxc("init" 0 init --db "${DB}" ${PW} --cn "N Root" --key ec-p256)

# --- neither renameat2(RENAME_NOREPLACE) nor link(): refused before ----------
count_items(key keys_before)
count_items(request reqs_before)
fx("no hard links" 1 "fail:probe:k1.key,fail:publish:k1.key" request-cert
    --db "${DB}" ${PW} --cn k1 --out f --layout certstrap --key-unencrypted)
expect_error("no hard links" target_filesystem_unsupported)
if(NOT detail MATCHES "/f'")
  fail("target_filesystem_unsupported does not name the directory: ${detail}")
endif()
count_items(key keys_after)
count_items(request reqs_after)
listing("${D}" l)
if(NOT keys_before EQUAL keys_after OR NOT reqs_before EQUAL reqs_after OR l)
  fail("refused target: keys ${keys_before} -> ${keys_after}, requests ${reqs_before} -> ${reqs_after}, files: ${l}")
endif()

# --- RENAME_NOREPLACE rejected (EINVAL): link() publishes ---------------------
fx("link fallback" 0 "fail:noreplace:k2.key" request-cert --db "${DB}" ${PW}
    --cn k2 --out f --layout certstrap --key-unencrypted)
file_mode("${D}/k2.key" m)
if(NOT m STREQUAL "600")
  fail("link fallback: k2.key has mode ${m}")
endif()
openssl_run(t pkey -in f/k2.key -noout)
listing("${D}" l)
foreach(f IN LISTS l)
  if(f MATCHES "bxc-tmp")
    fail("link fallback: a temporary file stays: ${f}")
  endif()
endforeach()

# --- a target that appears after stage() is never overwritten ---------------
foreach(way rename link)
  set(name "k3${way}")
  set(spec "addtarget:publish:${name}.key")
  if(way STREQUAL "link")
    set(spec "${spec},fail:noreplace:${name}.key")
  endif()
  fx("late target (${way})" 1 "${spec}" request-cert --db "${DB}" ${PW}
      --cn ${name} --out f --layout certstrap --key-unencrypted)
  expect_error("late target (${way})" publish_failed)
  if(NOT detail MATCHES "file_exists")
    fail("late target (${way}): not file_exists: ${detail}")
  endif()
  file(READ "${D}/${name}.key" c)
  if(NOT c STREQUAL "late\n")
    fail("late target (${way}): the file that appeared was overwritten")
  endif()
  listing("${D}" l)
  foreach(f IN LISTS l)
    if(f MATCHES "bxc-tmp")
      fail("late target (${way}): a temporary file stays: ${f}")
    endif()
  endforeach()
endforeach()

# --- a real vfat file system, where the container may mount -------------------
find_program(MKFS_VFAT NAMES mkfs.vfat mkfs.fat)
set(V "${WORK}/vfat")
file(MAKE_DIRECTORY "${V}")
set(mounted FALSE)
if(MKFS_VFAT)
  execute_process(COMMAND truncate -s 8M "${WORK}/vfat.img" RESULT_VARIABLE r1)
  execute_process(COMMAND "${MKFS_VFAT}" "${WORK}/vfat.img"
    RESULT_VARIABLE r2 OUTPUT_QUIET ERROR_QUIET)
  execute_process(COMMAND mount -o loop "${WORK}/vfat.img" "${V}"
    RESULT_VARIABLE r3 OUTPUT_QUIET ERROR_VARIABLE e3)
  if(r1 EQUAL 0 AND r2 EQUAL 0 AND r3 EQUAL 0)
    set(mounted TRUE)
  endif()
endif()
if(NOT mounted)
  message(STATUS "vfat loop mount skipped: no mkfs.vfat or this container "
    "may not mount (normal without --privileged)")
else()
  # a public file: published (vfat supports RENAME_NOREPLACE) or refused
  # before the commit, never stored without its file
  count_items(crl before)
  bxc("vfat crl" any crl --ca "N Root" --db "${DB}" ${PW} --out vfat
      --layout certstrap)
  count_items(crl after)
  if(rc EQUAL 0)
    if(NOT EXISTS "${V}/N_Root.crl")
      fail("vfat: success without the file")
    endif()
  else()
    expect_error("vfat crl" target_filesystem_unsupported)
    if(NOT before EQUAL after)
      fail("vfat: refused, but the CRL was stored")
    endif()
  endif()
  # a key: vfat cannot keep it owner-only
  bxc("vfat key" 1 request-cert --db "${DB}" ${PW} --cn k9 --out vfat
      --layout certstrap --key-unencrypted)
  expect_error("vfat key" permission_check_failed)
  execute_process(COMMAND umount "${V}")
endif()
