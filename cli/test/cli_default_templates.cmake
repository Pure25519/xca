# The default templates of misc/ under key usage by key type (BTD-195):
# TLS_server and TLS_client issue for RSA keys, TLS_server_EC and
# TLS_client_EC for EC keys; an EC key with an RSA template is refused
# with key_usage_not_for_key_type, and the detail names every bit the key
# cannot use. Regression of xca#57, which refused the old templates
# (keyEncipherment and keyAgreement together) for every key type.

include("${LIB}")

# the predefined templates come from the application data directory
get_filename_component(misc "${LIB}/../../../misc" ABSOLUTE)
foreach(dir "$ENV{XDG_DATA_HOME}/de.hohnstaedt.xca"
    "$ENV{XDG_DATA_HOME}/hohnstaedt.de/de.hohnstaedt.xca")
  file(MAKE_DIRECTORY "${dir}")
  foreach(t TLS_server TLS_client TLS_server_EC TLS_client_EC)
    file(COPY "${misc}/${t}.xca" DESTINATION "${dir}")
  endforeach()
endforeach()

bxc("root" 0 init --db "${DB}" ${PW} --cn "Template Root")

# sign_ok(<key type> <template> <bits that must be absent>)
function(sign_ok kt template absent)
  bxc("${kt} ${template} request" 0 request-cert --db "${DB}" ${PW}
      --cn "${kt}-${template}" --dns host.example --key ${kt})
  bxc("${kt} ${template} sign" 0 sign "${kt}-${template}" --db "${DB}" ${PW}
      --ca "Template Root" --template ${template})
  one_doc("${kt} ${template} sign" "${out}" cli-result r)
  object_doc("${r}" certificate c)
  extension("${c}" keyUsage ku)
  if(NOT ku MATCHES "Digital Signature" OR ku MATCHES "${absent}")
    fail("${kt} with ${template}: key usage '${ku}'")
  endif()
  message(STATUS "${kt} ${template}: ${ku}")
endfunction()

sign_ok(rsa-2048 TLS_server "Key Agreement")
sign_ok(rsa-2048 TLS_client "Key Agreement")
sign_ok(ec-p256 TLS_server_EC "Encipherment")
sign_ok(ec-p256 TLS_client_EC "Encipherment")

# an EC key with the RSA template: refused, every unfitting bit named
bxc("ec client request" 0 request-cert --db "${DB}" ${PW} --cn ec-rsa-client
    --key ec-p256)
bxc("ec with TLS_client" 1 sign ec-rsa-client --db "${DB}" ${PW}
    --ca "Template Root" --template TLS_client)
expect_error("ec with TLS_client" key_usage_not_for_key_type)
if(NOT detail MATCHES "keyEncipherment, dataEncipherment" OR
    NOT detail MATCHES "TLS_client")
  fail("the detail does not name the bits and the template: ${detail}")
endif()
message(STATUS "bxc-pki default templates ok")
