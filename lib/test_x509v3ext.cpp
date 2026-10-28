/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2026 Xavier MARTIN.
 *
 * All rights reserved.
 */

#include <QTest>
#include <QApplication>

#include "x509v3ext.h"
#include "oid.h"
#include "openssl_compat.h"

#include <openssl/x509v3.h>

/* Required by pkcs11.cpp which is compiled into xcalib */
char segv_data[1024];

/* The SID URI used in all round-trip tests */
static const QString SID_URI =
	"tag:microsoft.com,2022-09-14:sid:S-1-5-21-1234567890-1234567890-1234567890-1001";
static const QString SID_SAN = "URI:" + SID_URI;

class test_x509v3ext: public QObject
{
	Q_OBJECT

private slots:
	void initTestCase();
	void splitSanEntries_singleEntry();
	void splitSanEntries_twoEntries_space();
	void splitSanEntries_twoEntries_noSpace();
	void splitSanEntries_sidUri_alone();
	void splitSanEntries_sidUri_withOtherEntry();
	void splitSanEntries_criticalPrefix();
	void sanCreate_sidUri_alone();
	void sanCreate_sidUri_withDns();
	void sanCreate_multipleUris();

	/* Review tests (BTD-46): exact GeneralNames after x509v3ext::create() */
	void review_urnApplicationUri();
	void review_legacyCommaBeforeUpn();
	void review_ipv6AndEmail();
	void review_criticalMixedList();
	void review_sectionPath_hash();
	void review_sectionPath_dollar();
	void review_sectionPath_quoteBackslash();
	void review_sectionPath_newline();
};

/* Decode a SAN/IAN extension into "TYPE:value" strings,
 * or an empty list if the extension is invalid */
static QStringList generalNames(const x509v3ext &ext)
{
	QStringList out;
	X509_EXTENSION *e = ext.get();
	if (!e)
		return out;
	GENERAL_NAMES *gens = (GENERAL_NAMES *)X509V3_EXT_d2i(e);
	X509_EXTENSION_free(e);
	if (!gens)
		return out;
	for (int i = 0; i < sk_GENERAL_NAME_num(gens); i++) {
		GENERAL_NAME *gen = sk_GENERAL_NAME_value(gens, i);
		int type;
		ASN1_STRING *str = (ASN1_STRING *)GENERAL_NAME_get0_value(gen, &type);
		QString val;
		switch (type) {
		case GEN_DNS: val = "DNS:"; break;
		case GEN_URI: val = "URI:"; break;
		case GEN_EMAIL: val = "email:"; break;
		case GEN_IPADD: val = "IP:"; break;
		case GEN_OTHERNAME: {
			OTHERNAME *on = (OTHERNAME *)str;
			out << QString("otherName:%1;UTF8:%2")
				.arg(OBJ_nid2sn(OBJ_obj2nid(on->type_id)))
				.arg(QString::fromUtf8((const char *)
					ASN1_STRING_get0_data(on->value->value.utf8string),
					ASN1_STRING_get_length(on->value->value.utf8string)));
			continue;
		}
		default: out << QString("type%1").arg(type); continue;
		}
		if (type == GEN_IPADD)
			val += QString::fromLatin1(QByteArray((const char *)
				ASN1_STRING_get0_data(str),
				ASN1_STRING_get_length(str)).toHex());
		else
			val += QString::fromUtf8((const char *)
				ASN1_STRING_get0_data(str), ASN1_STRING_get_length(str));
		out << val;
	}
	GENERAL_NAMES_free(gens);
	return out;
}

void test_x509v3ext::initTestCase()
{
	initOIDs();
}

/* --- splitSanEntries() unit tests --------------------------------------- */

void test_x509v3ext::splitSanEntries_singleEntry()
{
	QStringList r = splitSanEntries("DNS:example.com");
	QCOMPARE(r.size(), 1);
	QCOMPARE(r[0], "DNS:example.com");
}

void test_x509v3ext::splitSanEntries_twoEntries_space()
{
	QStringList r = splitSanEntries("DNS:example.com, IP:192.0.2.1");
	QCOMPARE(r.size(), 2);
	QCOMPARE(r[0], "DNS:example.com");
	QCOMPARE(r[1], "IP:192.0.2.1");
}

void test_x509v3ext::splitSanEntries_twoEntries_noSpace()
{
	/* Legacy format: bare comma without space */
	QStringList r = splitSanEntries("DNS:example.com,IP:192.0.2.1");
	QCOMPARE(r.size(), 2);
	QCOMPARE(r[0], "DNS:example.com");
	QCOMPARE(r[1], "IP:192.0.2.1");
}

void test_x509v3ext::splitSanEntries_sidUri_alone()
{
	/* The comma inside the tag: URI must NOT be treated as a separator */
	QStringList r = splitSanEntries(SID_SAN);
	QCOMPARE(r.size(), 1);
	QCOMPARE(r[0], SID_SAN);
}

void test_x509v3ext::splitSanEntries_sidUri_withOtherEntry()
{
	QString input = "DNS:host.example.com, " + SID_SAN;
	QStringList r = splitSanEntries(input);
	QCOMPARE(r.size(), 2);
	QCOMPARE(r[0], "DNS:host.example.com");
	QCOMPARE(r[1], SID_SAN);
}

void test_x509v3ext::splitSanEntries_criticalPrefix()
{
	/* The critical prefix is stripped before splitSanEntries() is called
	 * (in v3ext::addItem and x509v3ext::create).  When the remaining text
	 * is just the SID SAN, it must parse as one token. */
	QString text = SID_SAN; /* prefix already stripped */
	QStringList r = splitSanEntries(text);
	QCOMPARE(r.size(), 1);
	QCOMPARE(r[0], SID_SAN);
}

/* --- x509v3ext::create() round-trip tests ------------------------------- */

void test_x509v3ext::sanCreate_sidUri_alone()
{
	/* Create a subjectAltName extension with only a SID URI.
	 * Verify the extension is valid and the URI survives the round-trip. */
	x509v3ext ext;
	ext.create(NID_subject_alt_name, SID_SAN);

	QVERIFY2(ext.isValid(), "Extension with SID URI should be valid");

	/* getValue() uses OpenSSL's built-in printer */
	QString val = ext.getValue();
	QVERIFY2(val.contains(SID_URI),
		qPrintable("getValue() did not preserve SID URI. Got: " + val));
}

void test_x509v3ext::sanCreate_sidUri_withDns()
{
	/* Combine a DNS name and a SID URI -- the path through createExtBySection */
	QString san = "DNS:host.example.com, " + SID_SAN;
	x509v3ext ext;
	ext.create(NID_subject_alt_name, san);

	QVERIFY2(ext.isValid(), "Extension with DNS + SID URI should be valid");

	QString val = ext.getValue();
	QVERIFY2(val.contains("host.example.com"),
		qPrintable("getValue() lost the DNS entry. Got: " + val));
	QVERIFY2(val.contains(SID_URI),
		qPrintable("getValue() did not preserve SID URI. Got: " + val));
}

void test_x509v3ext::sanCreate_multipleUris()
{
	/* Two ordinary URIs -- exercises the same createExtBySection path since
	 * URIs can contain ':' after the scheme, but not internal commas here.
	 * Also mix in the SID URI as a third entry. */
	QString san = "URI:https://example.com/path, URI:ldap://ldap.example.com, " + SID_SAN;
	x509v3ext ext;
	ext.create(NID_subject_alt_name, san);

	QVERIFY2(ext.isValid(), "Extension with multiple URIs should be valid");

	QString val = ext.getValue();
	QVERIFY2(val.contains("https://example.com/path"),
		qPrintable("getValue() lost the HTTPS URI. Got: " + val));
	QVERIFY2(val.contains("ldap://ldap.example.com"),
		qPrintable("getValue() lost the LDAP URI. Got: " + val));
	QVERIFY2(val.contains(SID_URI),
		qPrintable("getValue() did not preserve SID URI. Got: " + val));
}

/* --- Review tests (BTD-46) --------------------------------------------- */

void test_x509v3ext::review_urnApplicationUri()
{
	/* OPC UA ApplicationUri: a urn: URI SAN next to a DNS name */
	x509v3ext ext;
	ext.create(NID_subject_alt_name, "URI:urn:bxc:lab:plc10, DNS:plc10.lab");
	QCOMPARE(generalNames(ext), QStringList({
		"URI:urn:bxc:lab:plc10", "DNS:plc10.lab" }));
}

void test_x509v3ext::review_legacyCommaBeforeUpn()
{
	/* Legacy bare comma before XCA's UPN: alias must still separate */
	x509v3ext ext;
	ext.create(NID_subject_alt_name, "DNS:host.example,UPN:user@example");
	QCOMPARE(generalNames(ext), QStringList({
		"DNS:host.example", "otherName:msUPN;UTF8:user@example" }));
}

void test_x509v3ext::review_ipv6AndEmail()
{
	x509v3ext ext;
	ext.create(NID_subject_alt_name,
		"IP:2001:db8::1,email:ops@example.com, IP:192.0.2.1");
	QCOMPARE(generalNames(ext), QStringList({
		"IP:20010db8000000000000000000000001",
		"email:ops@example.com", "IP:c0000201" }));
}

void test_x509v3ext::review_criticalMixedList()
{
	x509v3ext ext;
	ext.create(NID_subject_alt_name, "critical," + SID_SAN +
		", DNS:host.example, URI:urn:bxc:lab:plc10");
	QCOMPARE(ext.getCritical(), 1);
	QCOMPARE(generalNames(ext), QStringList({
		SID_SAN, "DNS:host.example", "URI:urn:bxc:lab:plc10" }));
}

/* Values with an internal comma go through an NCONF section.
 * NCONF syntax characters in the value must arrive unchanged. */
void test_x509v3ext::review_sectionPath_hash()
{
	x509v3ext ext;
	ext.create(NID_subject_alt_name, "URI:tag:example.com,2026:a#frag");
	QCOMPARE(generalNames(ext), QStringList({
		"URI:tag:example.com,2026:a#frag" }));
}

void test_x509v3ext::review_sectionPath_dollar()
{
	x509v3ext ext;
	ext.create(NID_subject_alt_name, "URI:tag:example.com,2026:a$b");
	QCOMPARE(generalNames(ext), QStringList({
		"URI:tag:example.com,2026:a$b" }));
}

void test_x509v3ext::review_sectionPath_quoteBackslash()
{
	x509v3ext ext;
	ext.create(NID_subject_alt_name,
		"URI:tag:example.com,2026:'a\\b\"c");
	QCOMPARE(generalNames(ext), QStringList({
		"URI:tag:example.com,2026:'a\\b\"c" }));
}

void test_x509v3ext::review_sectionPath_newline()
{
	/* A line break must not inject another CONF line (entry) */
	x509v3ext ext;
	ext.create(NID_subject_alt_name,
		"URI:tag:example.com,2026:a\nDNS.9=evil.example");
	QVERIFY(!generalNames(ext).contains("DNS:evil.example"));
}

QTEST_MAIN(test_x509v3ext)
#include "test_x509v3ext.moc"
