/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2026 BxC Security GmbH.
 *
 * All rights reserved.
 */

#include <QTest>

#include "x509rev.h"
#include "openssl_compat.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>

/* Required by pkcs11.cpp which is compiled into xcalib */
char segv_data[1024];

class test_x509rev: public QObject
{
	Q_OBJECT

	X509_REVOKED *encode(const x509rev &r);
	QString invalidityDate(X509_REVOKED *rev);

private slots:
	void noInvalidityDate();
	void withInvalidityDate();
	void withInvalidityDateAndReason();
};

X509_REVOKED *test_x509rev::encode(const x509rev &r)
{
	QByteArray ba = r.i2d();
	const unsigned char *p = (const unsigned char *)ba.constData();
	return d2i_X509_REVOKED(NULL, &p, ba.size());
}

/* Returns the GeneralizedTime of the Invalidity Date extension,
 * or an empty string if the entry has none */
QString test_x509rev::invalidityDate(X509_REVOKED *rev)
{
	ASN1_GENERALIZEDTIME *gt = (ASN1_GENERALIZEDTIME *)
		X509_REVOKED_get_ext_d2i(rev, NID_invalidity_date, NULL, NULL);
	if (!gt)
		return QString();
	QString s = QString::fromLatin1(
		(const char *)ASN1_STRING_get0_data(gt), ASN1_STRING_get_length(gt));
	ASN1_GENERALIZEDTIME_free(gt);
	return s;
}

void test_x509rev::noInvalidityDate()
{
	/* Revocations imported from a CRL without Invalidity Date
	 * carry an undefined date, see x509rev::fromREVOKED() */
	x509rev r;
	r.setSerial(a1int(QString("1A2B")));
	r.setDate(a1time("20261028100000Z"));
	r.setInvalDate(a1time().setUndefined());

	X509_REVOKED *rev = encode(r);
	QVERIFY(rev);
	QCOMPARE(X509_REVOKED_get_ext_by_NID(rev, NID_invalidity_date, -1), -1);
	QCOMPARE(X509_REVOKED_get_ext_count(rev), 0);
	X509_REVOKED_free(rev);

	x509rev back;
	QByteArray ba = r.i2d();
	back.d2i(ba);
	QVERIFY(back.getInvalDate().isUndefined());
	QVERIFY(back.identical(r));
}

void test_x509rev::withInvalidityDate()
{
	x509rev r;
	r.setSerial(a1int(QString("1A2B")));
	r.setDate(a1time("20261028100000Z"));
	r.setInvalDate(a1time("20261027120000Z"));

	X509_REVOKED *rev = encode(r);
	QVERIFY(rev);
	QCOMPARE(X509_REVOKED_get_ext_count(rev), 1);
	QCOMPARE(invalidityDate(rev), "20261027120000Z");
	X509_REVOKED_free(rev);
}

void test_x509rev::withInvalidityDateAndReason()
{
	x509rev r;
	r.setSerial(a1int(QString("1A2B")));
	r.setDate(a1time("20261028100000Z"));
	r.setInvalDate(a1time("20261027120000Z"));
	r.setReason(x509rev::crlreasons().at(1)); /* Key Compromise */

	X509_REVOKED *rev = encode(r);
	QVERIFY(rev);
	QCOMPARE(X509_REVOKED_get_ext_count(rev), 2);
	QCOMPARE(invalidityDate(rev), "20261027120000Z");
	QVERIFY(X509_REVOKED_get_ext_by_NID(rev, NID_crl_reason, -1) >= 0);
	X509_REVOKED_free(rev);
}

QTEST_MAIN(test_x509rev)
#include "test_x509rev.moc"
