# RFC 5280 upper bounds of DN values through bxc-pki (BTD-202): the
# --subject parser builds the name without OpenSSL's string table, the
# service refuses an O of 65 characters with invalid_dn_value before
# anything is written; at the limit the objects are created.

include("${LIB}")

set(o64 "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo")
set(o65 "ooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo")
bxc("root" 0 init --db "${DB}" ${PW} --cn "Bounds Root")
# C: the --subject parser itself wants two letters (usage error)
bxc("init C=DEU" 2 init --db "${DB}" ${PW} --subject "C=DEU,CN=red"
    --parent "Bounds Root")
expect_error("init C=DEU" invalid_subject)
# O: refused by the service before anything is written
bxc("init O 65" 1 init --db "${DB}" ${PW} --subject "O=${o65},CN=red"
    --parent "Bounds Root")
expect_error("init O 65" invalid_dn_value)
if(NOT detail MATCHES "organizationName.*65 characters.*at most 64")
  fail("the detail does not name attribute, length and limit: ${detail}")
endif()
bxc("request O 65" 1 request-cert --db "${DB}" ${PW} --subject "O=${o65},CN=red")
expect_error("request O 65" invalid_dn_value)
bxc("at the limit" 0 init --db "${DB}" ${PW} --subject "C=DE,O=${o64},CN=ok"
    --parent "Bounds Root")
bxc("list" 0 list --db "${DB}" ${PW} --type certificate)
if(out MATCHES "red")
  fail("a refused certificate was stored: ${out}")
endif()
message(STATUS "bxc-pki DN bounds ok")
