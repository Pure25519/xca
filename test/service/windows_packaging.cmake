# The Windows packaging follows MSVC and OpenSSL 4 (BTD-252). Runs on every
# platform with cmake -P, so the Linux build checks what only a Windows build
# could run:
#  - the libcrypto DLL name comes from the OpenSSL version and the target
#    architecture (cmake/openssl_dll.cmake), in the install step and in the
#    WiX template misc/dynamic.wxs.in;
#  - the MinGW runtime DLLs are installed only under MinGW, and no MinGW link
#    option is left for the main program;
#  - warning flags are set per compiler;
#  - the OpenSSL source builds for Windows check the pinned SHA-256.
# Parameters: SRC (source tree), WORK (scratch directory).

function(expect what got want)
  if(NOT got STREQUAL want)
    message(FATAL_ERROR "${what}: got '${got}', expected '${want}'")
  endif()
endfunction()

function(read_file var rel)
  file(READ "${SRC}/${rel}" text)
  set(${var} "${text}" PARENT_SCOPE)
endfunction()

# 1. DLL name from version and architecture
include("${SRC}/cmake/openssl_dll.cmake")
xca_openssl_crypto_dll(dll 4.1.0 AMD64)
expect("OpenSSL 4.1.0 on x64" "${dll}" "libcrypto-4-x64.dll")
xca_openssl_crypto_dll(dll 4.1.0 ARM64)
expect("OpenSSL 4.1.0 on arm64" "${dll}" "libcrypto-4-arm64.dll")
xca_openssl_crypto_dll(dll 3.5.4 AMD64)
expect("OpenSSL 3.5.4 on x64" "${dll}" "libcrypto-3-x64.dll")

# 2. The WiX template takes that name
file(REMOVE_RECURSE "${WORK}")
set(OPENSSL_ROOT_DIR "C:/OpenSSL")
set(OPENSSL_CRYPTO_DLL libcrypto-4-x64.dll)
set(SYSTEM32 "C:/Windows/system32")
set(QT Qt6)
set(WINDOWSSTYLE modernwindowsstyle)
configure_file("${SRC}/misc/dynamic.wxs.in" "${WORK}/dynamic.wxs")
file(READ "${WORK}/dynamic.wxs" wxs)
file(REMOVE_RECURSE "${WORK}")
if(NOT wxs MATCHES "Source=\"C:/OpenSSL/bin/libcrypto-4-x64.dll\"")
  message(FATAL_ERROR "dynamic.wxs does not ship C:/OpenSSL/bin/libcrypto-4-x64.dll")
endif()

# 3. No literal OpenSSL 3 DLL in the packaging
foreach(rel CMakeLists.txt misc/dynamic.wxs.in release/build-w64.sh)
  read_file(text ${rel})
  if(text MATCHES "libcrypto-3")
    message(FATAL_ERROR "${rel} still names libcrypto-3")
  endif()
endforeach()

# 4. MinGW runtime DLLs only inside if(MINGW), no -mwindows
read_file(top CMakeLists.txt)
string(REGEX MATCH "if *\\(MINGW\\)[^\n]*\n([^\n]*\n)*[^\n]*endif\\(\\)" mingw "${top}")
foreach(dll libgcc_s_seh-1.dll libstdc++-6.dll libwinpthread-1.dll)
  string(FIND "${mingw}" "${dll}" in_block)
  # occurrences without a regular expression (libstdc++ has two '+')
  string(REPLACE "${dll}" "" rest "${top}")
  string(LENGTH "${top}" len_all)
  string(LENGTH "${rest}" len_rest)
  string(LENGTH "${dll}" len_dll)
  math(EXPR count "(${len_all} - ${len_rest}) / ${len_dll}")
  if(in_block EQUAL -1 OR NOT count EQUAL 1)
    message(FATAL_ERROR "${dll} must appear once, inside if(MINGW)")
  endif()
endforeach()
if(top MATCHES "-mwindows")
  message(FATAL_ERROR "CMakeLists.txt still links -mwindows; use WIN32_EXECUTABLE")
endif()

# 5. Warning flags per compiler: the GCC/Clang flags only outside MSVC
if(NOT top MATCHES "if *\\(MSVC\\)[ \t\n]*add_compile_options\\([^)]*/W[0-4][^)]*\\)[ \t\n]*else\\(\\)[ \t\n]*add_compile_options\\(-Wall")
  message(FATAL_ERROR "the warning flags are not set per compiler (if(MSVC) /W... else() -Wall ...)")
endif()
foreach(rel CMakeLists.txt test/CMakeLists.txt test/service/CMakeLists.txt)
  read_file(text ${rel})
  if(text MATCHES "PRIVATE -pthread")
    message(FATAL_ERROR "${rel} links -pthread directly; use Threads::Threads")
  endif()
endforeach()

# 6. The OpenSSL source builds for Windows check the pinned tarball
set(OPENSSL_SHA256 50c17baf54cb008f6ce42d50deb4b28050a1aad711636cabd4b241c7e90cc2fd)
foreach(rel release/build-openssl-msvc.ps1 release/build-w64.sh)
  read_file(text ${rel})
  if(NOT text MATCHES "openssl-4\\.1\\.0" OR NOT text MATCHES "${OPENSSL_SHA256}")
    message(FATAL_ERROR "${rel} does not build openssl-4.1.0 checked against its SHA-256")
  endif()
endforeach()
message(STATUS "windows packaging: ok")
