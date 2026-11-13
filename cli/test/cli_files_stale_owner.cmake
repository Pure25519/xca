# The clean-up of temporary files whose owner cannot be proven alive
# (BTD-280 item 3). The owner mark p<pid>s<start> of BTD-213 (6) keeps a
# file of a running process. An owner counts as alive only when its pid
# exists and /proc gives a start time equal to the mark (or it is this
# process). A mark with start 0 (written where /proc was unreadable), an
# unreadable /proc now and a pid of another user (EPERM) prove nothing; a
# reused pid would keep such a file forever. Such a file is removed once
# it is older than the grace age of 10 minutes, with the warning
# stale_temp_removed; a younger one is kept.
#
# The test build makes /proc unreadable for the owner check with
# fail:proc_start:<text> (the target path contains <text>). pid 1 always
# exists.

include("${LIB}")

set(D "${WORK}/f")
file(MAKE_DIRECTORY "${D}")

bxc("init" 0 init --db "${DB}" ${PW} --cn "O Root" --key ec-p256)

# temp(<var> <name> <age>): a temporary file in f, <age> as for touch -d
function(temp var name age)
  set(p "${D}/${name}")
  file(WRITE "${p}" "left over\n")
  execute_process(COMMAND touch -d "${age}" "${p}" RESULT_VARIABLE r)
  if(NOT r EQUAL 0)
    fail("touch ${p}: ${r}")
  endif()
  set(${var} "${p}" PARENT_SCOPE)
endfunction()

# expect_cleaned(<label> <removed file> <kept file>)
function(expect_cleaned label gone kept)
  if(EXISTS "${gone}")
    fail("${label}: ${gone} (older than 10 minutes) was kept")
  endif()
  if(NOT EXISTS "${kept}")
    fail("${label}: ${kept} (younger than 10 minutes) was removed")
  endif()
  get_filename_component(n "${gone}" NAME)
  string(REPLACE "." "\\." n "${n}")
  if(NOT out MATCHES "stale_temp_removed" OR NOT out MATCHES "${n}")
    fail("${label}: no stale_temp_removed warning naming ${gone}:\n${out}")
  endif()
  file(REMOVE "${kept}")
  message(STATUS "${label}: old file removed with the warning, young kept")
endfunction()

# --- mark with start 0 -------------------------------------------------------
temp(old ".a.crl.bxc-tmp-p1s0-0123456789abcdef" "-1 hour")
temp(young ".b.crl.bxc-tmp-p1s0-fedcba9876543210" "-1 minute")
bxc("start 0" 0 crl --ca "O Root" --db "${DB}" ${PW} --out f
    --layout certstrap)
expect_cleaned("start 0" "${old}" "${young}")

# --- /proc unreadable --------------------------------------------------------
# the mark carries the real start time of pid 1: with /proc readable the
# owner is proven alive and even the old file stays; with /proc unreadable
# nothing is proven and the old file goes
file(READ "/proc/1/stat" stat1)
string(REGEX REPLACE "^.*\\) " "" stat1 "${stat1}")
string(REPLACE " " ";" stat1 "${stat1}")
list(GET stat1 19 start1)
if(NOT start1 MATCHES "^[0-9]+$")
  fail("no start time of pid 1 in /proc/1/stat: ${start1}")
endif()
temp(old ".c.crl.bxc-tmp-p1s${start1}-0123456789abcdef" "-1 hour")
temp(young ".d.crl.bxc-tmp-p1s${start1}-fedcba9876543210" "-1 minute")
bxc("owner alive" 0 crl --ca "O Root" --db "${DB}" ${PW} --out f
    --layout certstrap --force)
if(NOT EXISTS "${old}" OR NOT EXISTS "${young}")
  fail("owner alive: a file of a proven owner was removed")
endif()
message(STATUS "owner alive: both files kept")
fx("no proc" 0 "fail:proc_start:O_Root" crl --ca "O Root" --db "${DB}" ${PW}
    --out f --layout certstrap --force)
expect_cleaned("no proc" "${old}" "${young}")
