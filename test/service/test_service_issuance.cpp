/* vi: set sw=4 ts=4:
 *
 * Certificate issuance through db_x509::newCert(ctx, IssuanceSpec)
 * (BTD-31): root CA, intermediate CA and an end entity from a CSR,
 * checked with openssl verify; one audit entry per issuance; the serial
 * number rule; the end date below the issuer chain (BTD-51).
 */

#include <QDir>
#include <QFile>
#include <QProcess>
#include <QSet>

#include <openssl/asn1.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/db_crl.h"
#include "lib/db_key.h"
#include "lib/db_x509.h"
#include "lib/db_x509req.h"
#include "lib/exception.h"
#include "lib/issuance.h"
#include "lib/pki_crl.h"
#include "lib/pki_evp.h"
#include "lib/pki_x509.h"
#include "lib/pki_x509req.h"

#include "ServiceTestCase.h"

class test_service_issuance : public ServiceTestCase
{
	Q_OBJECT

	ServiceContext ctx{ ServiceContext::cli, "os:service-test" };

	static pki_key *newKey(const QString &name)
	{
		return Database.model<db_key>()->newKey(
				keyjob("EC:prime256v1"), name);
	}
	static x509name dn(const QString &cn)
	{
		x509name n;
		n.addEntryByNid(NID_countryName, "DE");
		n.addEntryByNid(NID_organizationName, "BxC Security");
		n.addEntryByNid(NID_commonName, cn);
		return n;
	}
	static IssuanceSpec caSpec(const QString &cn, pki_key *key,
				pki_x509 *signer, int days);
	IssuanceSpec eeSpec(pki_x509req *req, pki_x509 *signer);
	pki_x509 *issue(const IssuanceSpec &spec);
	void writePem(pki_x509 *cert, const QString &file);
	QString openssl(const QStringList &args, int *exitCode);
	static QString extText(pki_x509 *cert, int nid);
	static void checkSerial(const a1int &serial);
	static QString notAfterText(pki_x509 *cert);
	static a1time plainTime(const QString &plain);
	IssuanceSpec validitySpec(const QString &cn, pki_x509 *signer,
				const QString &notAfter);
	pki_x509req *csrFromOpenssl(const QString &dir);

  private slots:
	void chain();
	void auditOnRejectedSpec_data();
	void auditOnRejectedSpec();
	void serials();
	void forcedDuplicateSerial();
	void validityUnderIssuer_data();
	void validityUnderIssuer();
	void validityCappedByRoot();
	void validityEndsBeforeStart_data();
	void validityEndsBeforeStart();
	void akiOnSelfSignedRoot_data();
	void akiOnSelfSignedRoot();
	void edwardsSelfSigned_data();
	void edwardsSelfSigned();
};

IssuanceSpec test_service_issuance::caSpec(const QString &cn, pki_key *key,
				pki_x509 *signer, int days)
{
	IssuanceSpec spec;
	spec.name = cn;
	spec.subject = dn(cn);
	spec.key = key;
	spec.signer = signer;
	spec.notBefore = a1time();
	spec.notAfter = a1time(QDateTime::currentDateTimeUtc().addDays(days));
	spec.hashAlgo = digest(NID_sha256);
	spec.extensions.basicCA = ExtensionSpec::bc_ca;
	spec.extensions.basicCritical = true;
	if (signer)
		spec.extensions.pathLen = "0";
	spec.extensions.subjectKeyId = true;
	spec.extensions.authorityKeyId = true;
	spec.extensions.keyUsage << "keyCertSign" << "cRLSign";
	spec.extensions.keyUsageCritical = true;
	return spec;
}

IssuanceSpec test_service_issuance::eeSpec(pki_x509req *req, pki_x509 *signer)
{
	IssuanceSpec spec;
	spec.request = req;
	spec.subject = req->getSubject();
	spec.signer = signer;
	spec.notBefore = a1time();
	spec.notAfter = a1time(QDateTime::currentDateTimeUtc().addDays(90));
	spec.hashAlgo = digest(NID_sha256);
	spec.copyRequestExtensions = true;
	spec.extensions.basicCA = ExtensionSpec::bc_not_ca;
	spec.extensions.subjectKeyId = true;
	spec.extensions.authorityKeyId = true;
	spec.extensions.keyUsage << "digitalSignature" << "keyAgreement";
	spec.extensions.keyUsageCritical = true;
	spec.extensions.crlDistPoints = "URI:http://pki.example/root.crl";
	spec.templateName = "service-test";
	return spec;
}

pki_x509 *test_service_issuance::issue(const IssuanceSpec &spec)
{
	try {
		return Database.model<db_x509>()->newCert(ctx, spec);
	} catch (errorEx &err) {
		qWarning() << "newCert failed:" << err.getString();
		return nullptr;
	}
}

void test_service_issuance::writePem(pki_x509 *cert, const QString &file)
{
	BIO *b = BIO_new_file(QFile::encodeName(file).constData(), "w");
	QVERIFY(b);
	QVERIFY(PEM_write_bio_X509(b, cert->getCert()));
	BIO_free(b);
}

QString test_service_issuance::openssl(const QStringList &args, int *exitCode)
{
	QProcess p;
	p.setProcessChannelMode(QProcess::MergedChannels);
	p.start(OPENSSL_PROGRAM, args);
	if (!p.waitForFinished(30000))
		*exitCode = -1;
	else
		*exitCode = p.exitCode();
	return QString::fromUtf8(p.readAll());
}

/* The extension as OpenSSL prints it, critical flag included */
QString test_service_issuance::extText(pki_x509 *cert, int nid)
{
	X509 *x = cert->getCert();
	int i = X509_get_ext_by_NID(x, nid, -1);
	if (i < 0)
		return QString();
	const X509_EXTENSION *ext = X509_get_ext(x, i);
	BIO *b = BIO_new(BIO_s_mem());
	X509V3_EXT_print(b, ext, 0, 0);
	char *data;
	long len = BIO_get_mem_data(b, &data);
	QString s = QString::fromUtf8(data, len);
	BIO_free(b);
	return (X509_EXTENSION_get_critical(ext) ? "critical: " : "") + s;
}

/* Rule 2: positive, >= 64 random bits, <= 20 octets */
void test_service_issuance::checkSerial(const a1int &serial)
{
	const ASN1_INTEGER *ai = serial.get0();
	QCOMPARE(ASN1_STRING_type(ai), V_ASN1_INTEGER);   // not negative
	int len = ASN1_STRING_get_length(ai);
	const unsigned char *d = ASN1_STRING_get0_data(ai);
	QVERIFY2(len >= 9 && len <= 20, CCHAR(serial.toHex()));
	QVERIFY2(d[0] >= 0x01 && d[0] <= 0x7f, CCHAR(serial.toHex()));
}

pki_x509req *test_service_issuance::csrFromOpenssl(const QString &dir)
{
	int rc;
	QString csr = dir + "/ee.csr";
	QString out = openssl({ "req", "-new", "-newkey", "ec",
		"-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
		"-keyout", dir + "/ee.key", "-out", csr,
		"-subj", "/C=DE/O=BxC Security/CN=device.example",
		"-addext", "subjectAltName=DNS:device.example,IP:10.0.0.7,"
			"URI:urn:bxc:device:7",
		"-addext", "extendedKeyUsage=serverAuth,clientAuth" }, &rc);
	if (rc != 0) {
		qWarning() << out;
		return nullptr;
	}
	pki_x509req *req = new pki_x509req("device-csr");
	req->fload(csr);
	return dynamic_cast<pki_x509req*>(
			Database.model<db_x509req>()->insert(req));
}

/* The AKI option applies to a self-signed root too (BTD-48): without it
 * no AKI, with it keyIdentifier = own SKI, in the issuer form also the
 * issuer and serial; a chain below the root verifies either way */
void test_service_issuance::akiOnSelfSignedRoot_data()
{
	QTest::addColumn<bool>("aki");
	QTest::addColumn<bool>("issuerForm");

	QTest::newRow("no AKI") << false << false;
	QTest::newRow("keyIdentifier") << true << false;
	QTest::newRow("keyIdentifier, issuer and serial") << true << true;
}

void test_service_issuance::akiOnSelfSignedRoot()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	QFETCH(bool, aki);
	QFETCH(bool, issuerForm);
	QTemporaryDir dir;
	QVERIFY(dir.isValid());
	IssuanceSpec rs = caSpec("AKI Root", newKey("aki-root-key"), nullptr,
				3650);
	rs.extensions.authorityKeyId = aki;
	rs.extensions.authorityKeyIdIssuer = issuerForm;
	pki_x509 *root = issue(rs);
	QVERIFY(root);
	IssuanceSpec ss = caSpec("AKI Sub", newKey("aki-sub-key"), root, 1825);
	ss.extensions.authorityKeyIdIssuer = issuerForm;
	pki_x509 *sub = issue(ss);
	QVERIFY(sub);

	QString rootAki = extText(root, NID_authority_key_identifier);
	QString rootSki = extText(root, NID_subject_key_identifier).trimmed();
	if (!aki) {
		QVERIFY2(rootAki.isEmpty(), CCHAR(rootAki));
	} else {
		QVERIFY2(rootAki.contains(rootSki), CCHAR(rootAki + " / " + rootSki));
		QCOMPARE(rootAki.contains("DirName:"), issuerForm);
		QCOMPARE(rootAki.contains("serial:"), issuerForm);
	}

	writePem(root, dir.path() + "/root.pem");
	writePem(sub, dir.path() + "/sub.pem");
	int rc;
	QString out = openssl({ "verify", "-x509_strict",
		"-CAfile", dir.path() + "/root.pem",
		dir.path() + "/sub.pem" }, &rc);
	QVERIFY2(rc == 0, CCHAR(out));
#endif
}

void test_service_issuance::chain()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	QTemporaryDir dir;
	QVERIFY(dir.isValid());
	/* each key has its own audit entry key.generate (BTD-32) */
	pki_key *rootKey = newKey("root-key"), *subKey = newKey("sub-key");
	QVERIFY(rootKey && subKey);
	int rc, before = AuditLog::entries().size();

	pki_x509 *root = issue(caSpec("Service Root CA", rootKey,
					nullptr, 3650));
	QVERIFY(root);
	QCOMPARE(AuditLog::entries().size(), before + 1);
	pki_x509 *sub = issue(caSpec("Service Sub CA", subKey,
					root, 1825));
	QVERIFY(sub);
	QCOMPARE(AuditLog::entries().size(), before + 2);

	/* The device key stays outside the database, as with EST */
	pki_x509req *req = csrFromOpenssl(dir.path());
	QVERIFY(req);
	QVERIFY(!req->getRefKey());
	pki_x509 *ee = issue(eeSpec(req, sub));
	QVERIFY(ee);
	QCOMPARE(AuditLog::entries().size(), before + 3);

	/* Names and subject come from the CSR, RDN order kept */
	QCOMPARE(ee->getIntName(), QString("device-csr"));
	QCOMPARE(ee->getSubject().oneLine(),
		QString("C = DE, O = BxC Security, CN = device.example"));
	QCOMPARE(ee->getSigner(), sub);
	QVERIFY(req->getDone());
	QVERIFY(root->isCA());
	QVERIFY(sub->isCA());
	QVERIFY(!ee->isCA());

	/* Requested extensions */
	QCOMPARE(extText(root, NID_basic_constraints),
		QString("critical: CA:TRUE"));
	QCOMPARE(extText(sub, NID_basic_constraints),
		QString("critical: CA:TRUE, pathlen:0"));
	QCOMPARE(extText(root, NID_key_usage),
		QString("critical: Certificate Sign, CRL Sign"));
	/* Self-signed with authorityKeyId: AKI keyid = own SKI (BTD-48) */
	QVERIFY(extText(root, NID_authority_key_identifier)
			.contains(extText(root, NID_subject_key_identifier).trimmed()));
	QVERIFY(!extText(sub, NID_authority_key_identifier).isEmpty());
	QCOMPARE(extText(ee, NID_basic_constraints), QString("CA:FALSE"));
	QCOMPARE(extText(ee, NID_key_usage),
		QString("critical: Digital Signature, Key Agreement"));
	QCOMPARE(extText(ee, NID_ext_key_usage),
		QString("TLS Web Server Authentication, "
			"TLS Web Client Authentication"));
	QCOMPARE(extText(ee, NID_subject_alt_name),
		QString("DNS:device.example, IP Address:10.0.0.7, "
			"URI:urn:bxc:device:7"));
	QVERIFY(extText(ee, NID_crl_distribution_points)
			.contains("URI:http://pki.example/root.crl"));
	/* AKI of each certificate is the SKI of its issuer */
	QVERIFY(extText(ee, NID_authority_key_identifier)
			.contains(extText(sub, NID_subject_key_identifier).trimmed()));

	writePem(root, dir.path() + "/root.pem");
	writePem(sub, dir.path() + "/sub.pem");
	writePem(ee, dir.path() + "/ee.pem");
	QString out = openssl({ "verify", "-x509_strict",
		"-purpose", "sslserver",
		"-CAfile", dir.path() + "/root.pem",
		"-untrusted", dir.path() + "/sub.pem",
		dir.path() + "/ee.pem" }, &rc);
	QVERIFY2(rc == 0, CCHAR(out));
	QVERIFY2(out.contains("ee.pem: OK"), CCHAR(out));

	/* One audit entry per issuance, chain intact */
	QList<AuditEntry> entries = AuditLog::entries();
	AuditEntry e = entries.last();
	QCOMPARE(e.action, QString("certificate.issue"));
	QCOMPARE(e.objectType, QString("certificate"));
	QCOMPARE(e.objectId, ee->getSqlItemId().toString());
	QCOMPARE(e.result, QString("success"));
	QCOMPARE(e.actor, QString("os:service-test"));
	QCOMPARE(e.channel, QString("cli"));
	QCOMPARE(e.params["serial"].toString(), ee->getSerial().toHex());
	QCOMPARE(e.params["issuer"].toString(), sub->getSubject().rfc4514());
	QCOMPARE(e.params["template"].toString(), QString("service-test"));
	QCOMPARE(e.params["fingerprint"].toString(),
		ee->fingerprint(EVP_sha256()));
	QVERIFY(AuditLog::verify().ok());

	/* Persisted */
	reopenDatabase();
	QCOMPARE(Store.getAll<pki_x509>().size(), 3);
	QVERIFY(AuditLog::verify().ok());
#endif
}

void test_service_issuance::auditOnRejectedSpec_data()
{
	QTest::addColumn<QString>("variant");
	QTest::addColumn<QString>("code");

	QTest::newRow("no key") << "nokey" << "missing_key";
	QTest::newRow("CSR self-signed") << "csr_selfsigned"
				<< "no_private_signing_key";
	QTest::newRow("signer without key") << "signer_pubonly"
				<< "no_private_signing_key";
}

void test_service_issuance::auditOnRejectedSpec()
{
	QFETCH(QString, variant);
	QFETCH(QString, code);
	IssuanceSpec spec;

	if (variant == "nokey") {
		spec = caSpec("No Key", nullptr, nullptr, 30);
	} else {
#ifndef OPENSSL_PROGRAM
		QSKIP("openssl program not found");
#else
		QTemporaryDir dir;
		pki_x509req *req = csrFromOpenssl(dir.path());
		QVERIFY(req);
		pki_x509 *signer = nullptr;
		if (variant == "signer_pubonly") {
			pki_key *k = newKey("ca-key");
			signer = issue(caSpec("Key Gone CA", k, nullptr, 30));
			QVERIFY(signer);
			/* keep the certificate, drop its private key */
			db_key *keys = Database.model<db_key>();
			keys->deleteItems(ctx, { k });
			QVERIFY(!signer->getRefKey());
		}
		spec = eeSpec(req, signer);
#endif
	}
	int certs = Store.getAll<pki_x509>().size();
	int before = AuditLog::entries().size();

	try {
		Database.model<db_x509>()->newCert(ctx, spec);
		QFAIL("newCert accepted the spec");
	} catch (serviceError &err) {
		QCOMPARE(err.code, code);
	}

	QCOMPARE(Store.getAll<pki_x509>().size(), certs);
	QList<AuditEntry> entries = AuditLog::entries();
	QCOMPARE(entries.size(), before + 1);
	QCOMPARE(entries.last().action, QString("certificate.issue"));
	QCOMPARE(entries.last().result, QString("failure"));
	QCOMPARE(entries.last().errorCode, code);
	QVERIFY(entries.last().objectId.isEmpty());
	QVERIFY(AuditLog::verify().ok());
}

/* 1000 serials of CAs and end entities; 250 in the AddressSanitizer
 * run, where the 1000 took 70 % of its 20 minutes per test function
 * under parallel load (BTD-230). The checks are the same: the format of
 * every serial, and no serial twice under one of the 10 issuers. */
#if defined(__SANITIZE_ADDRESS__)
static const int serialCount = 250;
#else
static const int serialCount = 1000;
#endif

void test_service_issuance::serials()
{
	QMap<QString, QSet<QString> > perIssuer;
	pki_key *caKey = newKey("ca-key"), *eeKey = newKey("ee-key");
	QList<pki_x509 *> cas;

	for (int i = 0; i < 10; i++) {
		pki_x509 *ca = issue(caSpec(QString("Root %1").arg(i), caKey,
					nullptr, 3650));
		QVERIFY(ca);
		cas << ca;
	}
	for (int i = 0; i < serialCount - 10; i++) {
		pki_x509 *signer = cas[i % 2];
		IssuanceSpec spec = caSpec(QString("ee-%1").arg(i), eeKey,
					signer, 30);
		spec.extensions = ExtensionSpec();
		QVERIFY(issue(spec));
	}
	QList<pki_x509 *> all = Store.getAll<pki_x509>();
	QCOMPARE(all.size(), serialCount);
	for (pki_x509 *c : all) {
		checkSerial(c->getSerial());
		QVERIFY(c->getSerial() != a1int(1L));
		QString issuer = c->getSigner()->getSqlItemId().toString();
		QString serial = c->getSerial().toHex();
		QVERIFY2(!perIssuer[issuer].contains(serial), CCHAR(serial));
		perIssuer[issuer] << serial;
	}
	QCOMPARE(perIssuer.size(), 10);
}

void test_service_issuance::forcedDuplicateSerial()
{
	db_x509 *certs = Database.model<db_x509>();
	pki_key *key = newKey("ca-key");
	pki_x509 *ca = issue(caSpec("Dup CA", key, nullptr, 3650));
	QVERIFY(ca);
	IssuanceSpec spec = caSpec("ee", key, ca, 30);
	spec.extensions = ExtensionSpec();
	pki_x509 *ee = issue(spec);
	QVERIFY(ee);
	a1int taken = ee->getSerial();

	/* Checked in the database, not only in memory */
	reopenDatabase();
	ca = nullptr;
	for (pki_x509 *c : Store.getAll<pki_x509>()) {
		if (c->getIntName() == "Dup CA")
			ca = c;
	}
	QVERIFY(ca);
	certs = Database.model<db_x509>();
	QVERIFY(certs->serialInUse(ca, taken));
	QVERIFY(certs->serialInUse(ca, ca->getSerial()));
	QVERIFY(!certs->serialInUse(ca, db_x509::randomSerial()));

	/* A colliding draw is rejected and replaced */
	int calls = 0;
	a1int fresh = certs->getUniqueSerial(ca, [&]() {
		return calls++ == 0 ? taken : db_x509::randomSerial();
	});
	QCOMPARE(calls, 2);
	QVERIFY(fresh != taken);

	/* A source that only collides fails instead of reusing the serial */
	try {
		certs->getUniqueSerial(ca, [&]() { return taken; });
		QFAIL("duplicate serial accepted");
	} catch (serviceError &err) {
		QCOMPARE(err.code, QString("serial_exhausted"));
	}
}

void test_service_issuance::edwardsSelfSigned_data()
{
	QTest::addColumn<QString>("type");

	QTest::newRow("Ed25519") << "ED25519";
	QTest::newRow("Ed448") << "ED448";
}

/* EdDSA keys sign without a digest: possibleHashNids() offers only
 * NID_undef, so the digest that NewX509 and crljob pick from it signs
 * a self-signed CA and its CRL (BTD-16; Ed448 had no entry and ended in
 * signing_failed) */
void test_service_issuance::edwardsSelfSigned()
{
	QFETCH(QString, type);

	pki_key *key = Database.model<db_key>()->newKey(ctx, keyjob(type),
							"edwards-key");
	QVERIFY(key);
	QCOMPARE(key->possibleHashNids(), QList<int>({ NID_undef }));

	IssuanceSpec spec = caSpec("Edwards CA", key, nullptr, 365);
	spec.hashAlgo = digest::getDefault();
	spec.hashAlgo.adjust(key->possibleHashNids());
	pki_x509 *ca = issue(spec);
	QVERIFY(ca);
	EVP_PKEY *pub = X509_get0_pubkey(ca->getCert());
	QCOMPARE(X509_verify(ca->getCert(), pub), 1);
	QCOMPARE(X509_get_signature_nid(ca->getCert()), key->getKeyType());

	crljob job(ca);
	QCOMPARE(job.hashAlgo.MD(), (const EVP_MD *)nullptr);
	pki_crl *crl = Database.model<db_crl>()->newCrl(ctx, job);
	QVERIFY(crl);
	QCOMPARE(X509_CRL_verify(const_cast<X509_CRL *>(crl->getCrl()), pub), 1);
}

XCA_SERVICE_TEST_MAIN(test_service_issuance)
#include "test_service_issuance.moc"

/* notAfter as encoded in the certificate, as GeneralizedTime: shows the
 * undefined date 99991231235959Z as it is, unlike a1time */
QString test_service_issuance::notAfterText(pki_x509 *cert)
{
	ASN1_GENERALIZEDTIME *gt = ASN1_TIME_to_generalizedtime(
			X509_get0_notAfter(cert->getCert()), nullptr);
	if (!gt)
		return QString("invalid");
	QString s = QString::fromLatin1(
			(const char *)ASN1_STRING_get0_data(gt),
			ASN1_STRING_get_length(gt));
	ASN1_GENERALIZEDTIME_free(gt);
	return s;
}

/* "unlimited" is the RFC 5280 undefined date */
a1time test_service_issuance::plainTime(const QString &plain)
{
	a1time t;
	if (plain == "unlimited")
		t.setUndefined();
	else
		t.fromPlain(plain);
	return t;
}

IssuanceSpec test_service_issuance::validitySpec(const QString &cn,
			pki_x509 *signer, const QString &notAfter)
{
	pki_key *key = newKey(cn + "-key");
	IssuanceSpec spec = caSpec(cn, key, signer, 1);
	spec.extensions.pathLen.clear();
	spec.notAfter = plainTime(notAfter);
	return spec;
}

/* Rule 6 of the certstrap triage (PLAN 8.4): the end date is the
 * requested one, capped at the issuer's notAfter; an issuer with the
 * undefined notAfter caps nothing; a cap is reported in the audit entry.
 * The dates cross 2038 (32-bit time_t), 2049/2050 (UTCTime to
 * GeneralizedTime) and reach 9998/9999. */
void test_service_issuance::validityUnderIssuer_data()
{
	QTest::addColumn<QString>("issuerEnd");
	QTest::addColumn<QString>("requested");
	QTest::addColumn<QString>("expected");
	QTest::addColumn<bool>("capped");

	const QString unl("unlimited"), und("99991231235959Z");

	QTest::newRow("9999 issuer, after 2038")
		<< unl << "20380119031408Z" << "20380119031408Z" << false;
	QTest::newRow("9999 issuer, last UTCTime")
		<< unl << "20491231235959Z" << "20491231235959Z" << false;
	QTest::newRow("9999 issuer, first GeneralizedTime")
		<< unl << "20500101000000Z" << "20500101000000Z" << false;
	QTest::newRow("9999 issuer, 9998")
		<< unl << "99981231235959Z" << "99981231235959Z" << false;
	QTest::newRow("9999 issuer, unlimited")
		<< unl << unl << und << false;
	QTest::newRow("finite issuer, earlier")
		<< "20400101000000Z" << "20300101000000Z"
		<< "20300101000000Z" << false;
	QTest::newRow("finite issuer, same")
		<< "20400101000000Z" << "20400101000000Z"
		<< "20400101000000Z" << false;
	QTest::newRow("finite issuer, later")
		<< "20400101000000Z" << "20500101000000Z"
		<< "20400101000000Z" << true;
	QTest::newRow("finite issuer, unlimited")
		<< "20400101000000Z" << unl << "20400101000000Z" << true;
}

void test_service_issuance::validityUnderIssuer()
{
	QFETCH(QString, issuerEnd);
	QFETCH(QString, requested);
	QFETCH(QString, expected);
	QFETCH(bool, capped);

	pki_x509 *ca = issue(validitySpec("Validity CA", nullptr, issuerEnd));
	QVERIFY(ca);
	QCOMPARE(notAfterText(ca), issuerEnd == "unlimited" ?
			QString("99991231235959Z") : issuerEnd);

	pki_x509 *cert = issue(validitySpec("Validity EE", ca, requested));
	QVERIFY(cert);
	QCOMPARE(notAfterText(cert), expected);
	/* no 1970 and no overflow, also not through a1time */
	QVERIFY2(cert->getNotAfter().isUndefined() ||
		cert->getNotAfter().date().year() >= 2030,
		CCHAR(cert->getNotAfter().toPlain()));
	QCOMPARE(cert->getNotAfter().toPlain(), expected);

	AuditEntry e = AuditLog::entries().last();
	QCOMPARE(e.action, QString("certificate.issue"));
	QCOMPARE(e.result, QString("success"));
	QCOMPARE(e.params["validity_capped"].toBool(), capped);
	QCOMPARE(e.params["not_after"].toString(), expected == "99991231235959Z" ?
		QString() : AuditLog::rfc3339(plainTime(expected)));
	if (capped) {
		QVERIFY(e.params.contains("requested_not_after"));
		QCOMPARE(e.params["requested_not_after"].toString(),
			requested == "unlimited" ? QString() :
			AuditLog::rfc3339(plainTime(requested)));
	} else {
		QVERIFY(!e.params.contains("requested_not_after"));
	}
	QVERIFY(AuditLog::verify().ok());
}

/* The cap follows the chain up to the root: a CA below a finite root
 * that asks for the undefined date ends with the root, and so does an
 * end entity below it that asks for more. */
void test_service_issuance::validityCappedByRoot()
{
	pki_x509 *root = issue(validitySpec("Finite Root", nullptr,
					"20400101000000Z"));
	QVERIFY(root);
	pki_x509 *sub = issue(validitySpec("Unlimited Sub", root, "unlimited"));
	QVERIFY(sub);
	QCOMPARE(notAfterText(sub), QString("20400101000000Z"));
	pki_x509 *ee = issue(validitySpec("Below Sub", sub, "20450101000000Z"));
	QVERIFY(ee);
	QCOMPARE(notAfterText(ee), QString("20400101000000Z"));
	QCOMPARE(AuditLog::entries().last().params["validity_capped"].toBool(),
		true);

	/* Under a 9999 root, an intermediate's finite end caps */
	pki_x509 *uroot = issue(validitySpec("Unlimited Root", nullptr,
					"unlimited"));
	QVERIFY(uroot);
	pki_x509 *fsub = issue(validitySpec("Finite Sub", uroot,
					"20350101000000Z"));
	QVERIFY(fsub);
	QCOMPARE(notAfterText(fsub), QString("20350101000000Z"));
	pki_x509 *ee2 = issue(validitySpec("Below Finite Sub", fsub,
					"unlimited"));
	QVERIFY(ee2);
	QCOMPARE(notAfterText(ee2), QString("20350101000000Z"));
}

/* A cap that leaves no validity window is an error, not a certificate
 * that ends before (or when) it starts: below an expired issuer chain,
 * or with a notBefore at or after the CA's end. The rows above keep
 * notBefore at now below CAs that end later, so the capped end always
 * came after the start. An issuer that has already expired is refused
 * before the cap with issuer_expired (BTD-55). */
void test_service_issuance::validityEndsBeforeStart_data()
{
	QTest::addColumn<QString>("caStart");
	QTest::addColumn<QString>("caEnd");
	QTest::addColumn<QString>("notBefore");   // empty: now
	QTest::addColumn<QString>("notAfter");
	QTest::addColumn<bool>("valid");
	QTest::addColumn<QString>("code");   // of a rejection

	QTest::newRow("expired issuer")
		<< "20000101000000Z" << "20100101000000Z" << QString()
		<< "20500101000000Z" << false << "issuer_expired";
	QTest::newRow("expired issuer, unlimited request")
		<< "20000101000000Z" << "20100101000000Z" << QString()
		<< "unlimited" << false << "issuer_expired";
	QTest::newRow("notBefore after CA end")
		<< "20200101000000Z" << "20400101000000Z" << "20410101000000Z"
		<< "20500101000000Z" << false << "invalid_validity";
	QTest::newRow("notBefore equal to CA end")
		<< "20200101000000Z" << "20400101000000Z" << "20400101000000Z"
		<< "20500101000000Z" << false << "invalid_validity";
	QTest::newRow("notBefore one second before CA end")
		<< "20200101000000Z" << "20400101000000Z" << "20391231235959Z"
		<< "20500101000000Z" << true << QString();
}

void test_service_issuance::validityEndsBeforeStart()
{
	QFETCH(QString, caStart);
	QFETCH(QString, caEnd);
	QFETCH(QString, notBefore);
	QFETCH(QString, notAfter);
	QFETCH(bool, valid);
	QFETCH(QString, code);

	IssuanceSpec caS = validitySpec("Window CA", nullptr, caEnd);
	caS.notBefore = plainTime(caStart);
	pki_x509 *ca = issue(caS);
	QVERIFY(ca);
	QCOMPARE(notAfterText(ca), caEnd);

	IssuanceSpec spec = validitySpec("Window EE", ca, notAfter);
	if (!notBefore.isEmpty())
		spec.notBefore = plainTime(notBefore);
	int certs = Store.getAll<pki_x509>().size();
	int before = AuditLog::entries().size();

	if (valid) {
		pki_x509 *cert = issue(spec);
		QVERIFY(cert);
		QCOMPARE(notAfterText(cert), caEnd);
		QCOMPARE(AuditLog::entries().last().result, QString("success"));
		return;
	}
	try {
		Database.model<db_x509>()->newCert(ctx, spec);
		QFAIL("newCert issued a certificate without a validity window");
	} catch (serviceError &err) {
		QCOMPARE(err.code, code);
	}
	QCOMPARE(Store.getAll<pki_x509>().size(), certs);
	QList<AuditEntry> entries = AuditLog::entries();
	QCOMPARE(entries.size(), before + 1);
	QCOMPARE(entries.last().action, QString("certificate.issue"));
	QCOMPARE(entries.last().result, QString("failure"));
	QCOMPARE(entries.last().errorCode, code);
	QCOMPARE(entries.last().params["validity_capped"].toBool(), true);
	QVERIFY(entries.last().objectId.isEmpty());
	QVERIFY(AuditLog::verify().ok());
}
