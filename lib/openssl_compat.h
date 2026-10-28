/* vi: set sw=4 ts=4:
 *
 * OpenSSL API compatibility of the bxc-pki fork (BTD-20).
 */

#ifndef __OPENSSL_COMPAT_H
#define __OPENSSL_COMPAT_H

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <openssl/asn1.h>
#include <openssl/opensslv.h>

/*
 * OpenSSL 4.1 deprecates ASN1_STRING_length() and ASN1_STRING_set()
 * in favour of the size_t based ASN1_STRING_get_length() and
 * ASN1_STRING_set1_data(). Provide the new names for older OpenSSL 3.x
 * so the code uses one API.
 */
#if OPENSSL_VERSION_NUMBER < 0x40100000L
static inline size_t ASN1_STRING_get_length(const ASN1_STRING *x)
{
	int len = ASN1_STRING_length(x);
	return len > 0 ? (size_t)len : 0;
}

static inline int ASN1_STRING_set1_data(ASN1_STRING *str,
					const uint8_t *data, size_t len)
{
	if (len > INT_MAX)
		return 0;
	return ASN1_STRING_set(str, data, (int)len);
}
#endif

#endif
