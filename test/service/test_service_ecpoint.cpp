/* vi: set sw=4 ts=4:
 *
 * The EC point of a CKA_EC_POINT attribute (BTD-298). PKCS#11 2.40 gives
 * the point as the DER encoding of an OCTET STRING, some tokens give the
 * bare point. Both start with 0x04 (the OCTET STRING tag, the prefix of an
 * uncompressed point), so a bare uncompressed point whose first coordinate
 * byte equals the remaining length parses as a complete OCTET STRING too
 * (P-256: X[0] = 0x3f, about one key in 256). The attribute is DER only
 * when its content has the length of a point of the curve; these tests
 * need no token.
 */

#include <openssl/core_names.h>
#include <openssl/evp.h>

#include "lib/pki_scard.h"

#include "ServiceTestCase.h"

class test_service_ecpoint : public ServiceTestCase
{
	Q_OBJECT

	static QByteArray point(const char *curve, bool compressed,
			int firstX = -1);
	static QByteArray der(const QByteArray &content);

  private slots:
	void derUncompressed();
	void bareUncompressed();
	void derCompressed();
	void bareCompressed();
	void bareLooksLikeDer();
	void derLongLength();
	void bareP521LooksLikeLongDer();
};

/* The encoded public point of a new key on curve; with firstX >= 0, of
 * the first key whose X coordinate starts with that byte */
QByteArray test_service_ecpoint::point(const char *curve, bool compressed,
		int firstX)
{
	for (int i = 0; i < 20000; i++) {
		EVP_PKEY *pkey = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC",
				curve);
		if (!pkey)
			return QByteArray();
		if (compressed)
			EVP_PKEY_set_utf8_string_param(pkey,
				OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
				"compressed");
		unsigned char *buf = nullptr;
		size_t len = EVP_PKEY_get1_encoded_public_key(pkey, &buf);
		QByteArray pt((const char *)buf, (int)len);
		OPENSSL_free(buf);
		EVP_PKEY_free(pkey);
		if (firstX < 0 || (pt.size() > 1 &&
				(unsigned char)pt[1] == firstX))
			return pt;
	}
	return QByteArray();
}

/* The DER encoding of an OCTET STRING with content */
QByteArray test_service_ecpoint::der(const QByteArray &content)
{
	QByteArray d(1, '\x04');
	int len = content.size();
	if (len < 0x80) {
		d += char(len);
	} else if (len < 0x100) {
		d += '\x81';
		d += char(len);
	} else {
		d += '\x82';
		d += char(len >> 8);
		d += char(len & 0xff);
	}
	return d + content;
}

void test_service_ecpoint::derUncompressed()
{
	QByteArray pt = point("P-256", false);
	QCOMPARE(pt.size(), 65);
	QCOMPARE(pki_scard::ecPointFromAttribute(der(pt), 32), pt);
}

void test_service_ecpoint::bareUncompressed()
{
	QByteArray pt = point("P-256", false);
	if ((unsigned char)pt[1] == 0x3f)
		pt = point("P-256", false);
	QVERIFY((unsigned char)pt[1] != 0x3f);
	QCOMPARE(pki_scard::ecPointFromAttribute(pt, 32), pt);
}

void test_service_ecpoint::derCompressed()
{
	QByteArray pt = point("P-256", true);
	QCOMPARE(pt.size(), 33);
	QCOMPARE(pki_scard::ecPointFromAttribute(der(pt), 32), pt);
}

void test_service_ecpoint::bareCompressed()
{
	QByteArray pt = point("P-256", true);
	QCOMPARE(pki_scard::ecPointFromAttribute(pt, 32), pt);
}

/* 04 3f X[1..31] Y: a complete OCTET STRING of 63 bytes, but no point of
 * P-256 has 63 bytes, so it is the bare point */
void test_service_ecpoint::bareLooksLikeDer()
{
	QByteArray pt = point("P-256", false, 0x3f);
	QCOMPARE(pt.size(), 65);
	QCOMPARE((int)(unsigned char)pt[1], 0x3f);
	QCOMPARE(pki_scard::ecPointFromAttribute(pt, 32), pt);
}

/* P-521: 133 bytes, the DER length has the long form */
void test_service_ecpoint::derLongLength()
{
	QByteArray pt = point("P-521", false);
	QCOMPARE(pt.size(), 133);
	QCOMPARE(pki_scard::ecPointFromAttribute(der(pt), 66), pt);
}

/* 04 81 82 X[2..65] Y: a complete OCTET STRING of 130 bytes in the long
 * form; X[0] = 0x81 also needs X[1] = 0x82, so the key is crafted from a
 * real point instead of searched */
void test_service_ecpoint::bareP521LooksLikeLongDer()
{
	QByteArray pt = point("P-521", false);
	QCOMPARE(pt.size(), 133);
	pt[1] = '\x81';
	pt[2] = '\x82';
	QCOMPARE(pki_scard::ecPointFromAttribute(pt, 66), pt);
}

XCA_SERVICE_TEST_MAIN(test_service_ecpoint)
#include "test_service_ecpoint.moc"
