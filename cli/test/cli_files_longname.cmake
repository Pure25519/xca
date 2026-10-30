# Temporary names of long targets (BTD-210 d): ".<name>.bxc-tmp-<16 hex>"
# of a 250-character file name is longer than a file name may be (255
# bytes); such a name is shortened to a prefix of the name, a hash of the
# whole name and the random part, so the file is written all the same.

include("${LIB}")

set(D "${WORK}/f")
file(MAKE_DIRECTORY "${D}")

bxc("init" 0 init --db "${DB}" ${PW} --cn "L Root" --key ec-p256)

# <name>.key and <name>.csr: 254 characters
string(REPEAT "n" 250 long)
bxc("long name" 0 request-cert --db "${DB}" ${PW} --cn longname --name "${long}"
    --out f --layout certstrap --key-unencrypted)
foreach(ext key csr)
  if(NOT EXISTS "${D}/${long}.${ext}")
    fail("long name: ${long}.${ext} was not written")
  endif()
endforeach()
file_mode("${D}/${long}.key" m)
if(NOT m STREQUAL "600")
  fail("long name: the key has mode ${m}")
endif()

# the temporary name of a killed run: short enough, and it still has the
# form the clean-up of stage() looks for
string(REPEAT "m" 250 long2)
fx("long name, killed" 137 "kill:sync:${long2}.key" request-cert --db "${DB}"
    ${PW} --cn longname2 --name "${long2}" --out f --layout certstrap
    --key-unencrypted)
file(GLOB t "${D}/.*bxc-tmp-*")
list(LENGTH t n)
if(NOT n EQUAL 1)
  fail("long name, killed: expected one temporary file, got ${t}")
endif()
get_filename_component(tn "${t}" NAME)
string(LENGTH "${tn}" len)
if(len GREATER 255 OR NOT tn MATCHES "^\\.m+.*\\.bxc-tmp-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]$")
  fail("long name, killed: temporary name '${tn}' (${len} characters)")
endif()
