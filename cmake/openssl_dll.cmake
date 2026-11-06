# xca_openssl_crypto_dll(<var> <version> <processor>) sets <var> to the file
# name of OpenSSL's libcrypto DLL on Windows (BTD-252): libcrypto-<major>-<arch>.dll
# as OpenSSL 3 and 4 name it, <arch> x64 for AMD64 and arm64 for ARM64, so the
# installer ships the DLL of the OpenSSL found, not a fixed version.
function(xca_openssl_crypto_dll var version processor)
  string(REGEX MATCH "^[0-9]+" major "${version}")
  string(TOUPPER "${processor}" processor)
  if(processor MATCHES "ARM64|AARCH64")
    set(arch arm64)
  else()
    set(arch x64)
  endif()
  set(${var} "libcrypto-${major}-${arch}.dll" PARENT_SCOPE)
endfunction()
