# xca-server links no Qt Gui, Widgets, Help or Network, and the only TLS
# libraries are libssl.so.4 and libcrypto.so.4 of OpenSSL 4 (BTD-154,
# conditions 6 and 7 of bxc-pki docs/xca-server-architecture.md). readelf
# gives the direct needs, ldd what the loader really resolves.
# cmake -DSERVER=<xca-server> -DREADELF=<readelf> -DLDD=<ldd>
#       -P server_link.cmake

if(NOT EXISTS "${SERVER}")
  message(FATAL_ERROR "xca-server not built: ${SERVER}")
endif()

execute_process(COMMAND "${READELF}" -d "${SERVER}"
  OUTPUT_VARIABLE dyn RESULT_VARIABLE rc)
if(NOT rc EQUAL 0)
  message(FATAL_ERROR "readelf -d ${SERVER} failed (${rc})")
endif()
if(NOT dyn MATCHES "libQt[0-9]*Core")
  message(FATAL_ERROR "xca-server lists no Qt Core: the check is broken")
endif()
if(dyn MATCHES "libQt[0-9]*(Gui|Widgets|Help|Network)[^ \n]*")
  message(FATAL_ERROR "xca-server needs ${CMAKE_MATCH_0}")
endif()
foreach(lib libssl.so.4 libcrypto.so.4)
  if(NOT dyn MATCHES "${lib}")
    message(FATAL_ERROR "xca-server does not need ${lib}:\n${dyn}")
  endif()
endforeach()

execute_process(COMMAND "${LDD}" "${SERVER}"
  OUTPUT_VARIABLE resolved RESULT_VARIABLE rc)
if(NOT rc EQUAL 0)
  message(FATAL_ERROR "ldd ${SERVER} failed (${rc})")
endif()
if(resolved MATCHES "lib(ssl|crypto)\\.so\\.3")
  message(FATAL_ERROR "xca-server resolves OpenSSL 3:\n${resolved}")
endif()
if(NOT resolved MATCHES "libssl\\.so\\.4 => /opt/openssl/")
  message(FATAL_ERROR "libssl.so.4 does not come from /opt/openssl:\n${resolved}")
endif()
message(STATUS "xca-server: Qt Core and Sql only, libssl/libcrypto .so.4 from /opt/openssl")
