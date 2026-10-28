/* vi: set sw=4 ts=4:
 *
 * Certificate issuance through db_x509::newCert(ctx, IssuanceSpec)
 * (BTD-31): root CA, intermediate CA and an end entity from a CSR,
 * checked with openssl verify; one audit entry per issuance; the serial
 * number rule.
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
#include "lib/db_key.h"
#include "lib/db_x509.h"
#include "lib/db_x509req.h"
#include "lib/exception.h"
#include "lib/issuance.h"
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
	pki_x509req *csrFromOpenssl(const QString &dir);

  private slots:
	void chain();
	void auditOnRejectedSpec_data();
	void auditOnRejectedSpec();
	void serials();
	void forcedDuplicateSerial();
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
	/* Self-signed: no AKI (unchanged XCA behaviour, BTD-48) */
	QVERIFY(extText(root, NID_authority_key_identifier).isEmpty());
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
	QCOMPARE(e.params["issuer"].toString(), sub->getSubject().oneLine());
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
			keys->deletePKI(keys->index(k));
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

/* 1000 serials of CAs and end entities */
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
	for (int i = 0; i < 990; i++) {
		pki_x509 *signer = cas[i % 2];
		IssuanceSpec spec = caSpec(QString("ee-%1").arg(i), eeKey,
					signer, 30);
		spec.extensions = ExtensionSpec();
		QVERIFY(issue(spec));
	}
	QList<pki_x509 *> all = Store.getAll<pki_x509>();
	QCOMPARE(all.size(), 1000);
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

XCA_SERVICE_TEST_MAIN(test_service_issuance)
#include "test_service_issuance.moc"
