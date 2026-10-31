/* vi: set sw=4 ts=4:
 *
 * OpenSSL API compatibility of the bxc-pki fork (BTD-20).
 */

#ifndef __OPENSSL_COMPAT_H
#define __OPENSSL_COMPAT_H

#include <openssl/opensslv.h>

/*
 * The fork uses the OpenSSL 4.1 API, e.g. the size_t based
 * ASN1_STRING_get_length() and ASN1_STRING_set1_data() instead of the
 * deprecated ASN1_STRING_length() and ASN1_STRING_set(). CMake requires
 * OpenSSL 4.1 (BTD-253); this catches a build that bypasses that check.
 */
#if OPENSSL_VERSION_NUMBER < 0x40100000L
#error "XCA needs OpenSSL 4.1 or later"
#endif

#endif
