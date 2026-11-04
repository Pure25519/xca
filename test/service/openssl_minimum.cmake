# The fork needs OpenSSL 4.1 (BTD-253): configuring it against an
# OpenSSL 3 prefix must stop at find_package(OpenSSL) with a message
# naming the found and the required version, not build silently.
# The prefix is a stand-in with the header and library names CMake's
# FindOpenSSL looks for, so the test needs no OpenSSL 3 installation.
# cmake -DSRC=<source dir> -DGENERATOR=<generator> -DWORK=<scratch dir>
#       -P openssl_minimum.cmake

set(prefix "${WORK}/openssl3")
file(REMOVE_RECURSE "${WORK}")
file(WRITE "${prefix}/include/openssl/opensslv.h"
	"# define OPENSSL_VERSION_STR \"3.5.4\"\n")
file(WRITE "${prefix}/include/openssl/ssl.h" "")
file(WRITE "${prefix}/lib/libcrypto.so" "")
file(WRITE "${prefix}/lib/libssl.so" "")

execute_process(
	COMMAND ${CMAKE_COMMAND} -S "${SRC}" -B "${WORK}/build" -G "${GENERATOR}"
		"-DOPENSSL_ROOT_DIR=${prefix}"
	RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err)
file(REMOVE_RECURSE "${WORK}")

if(rc EQUAL 0)
	message(FATAL_ERROR "configure against OpenSSL 3.5.4 succeeded:\n${out}")
endif()
# CMake wraps the message depending on the path lengths
string(REGEX REPLACE "[ \t\n]+" " " msg "${err}")
if(NOT msg MATCHES "Could NOT find OpenSSL[^(]*Found unsuitable version \"3\\.5\\.4\", but required is at least \"4\\.1\"")
	message(FATAL_ERROR "configure failed without the OpenSSL version message:\n${err}")
endif()
