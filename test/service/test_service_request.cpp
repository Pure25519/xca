/* vi: set sw=4 ts=4:
 *
 * Key generation through db_key::newKey(ctx, keyjob, name) and request
 * creation through db_x509req::newRequest(ctx, RequestSpec) (BTD-32):
 * RSA and EC keys, a CSR with SAN and EKU for each, checked with
 * openssl req -verify; one audit entry per operation; rejected specs.
 */

#include <QFile>
#include <QProcess>
#include <QTemporaryDir>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "lib/headerlist.h"
#include "lib/BioByteArray.h"
#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/db_key.h"
#include "lib/db_x509.h"
#include "lib/db_x509req.h"
#include "lib/exception.h"
#include "lib/func.h"
#include "lib/issuance.h"
#include "lib/pki_evp.h"
#include "lib/pki_x509.h"
#include "lib/pki_x509req.h"
#include "lib/request.h"

#include "ServiceTestCase.h"

class test_service_request : public ServiceTestCase
{
	Q_OBJECT

	ServiceContext ctx{ ServiceContext::cli, "os:service-test" };

	static x509name dn(const QString &cn)
	{
		x509name n;
		n.addEntryByNid(NID_countryName, "DE");
		n.addEntryByNid(NID_organizationName, "BxC Security");
		n.addEntryByNid(NID_commonName, cn);
		return n;
	}
	static RequestSpec tlsSpec(pki_key *key);
	pki_key *generate(const QString &job, const QString &name);
	void writePem(pki_x509req *req, const QString &file);
	QString openssl(const QStringList &args, int *exitCode);
	pki_key *publicOnlyKey();
	static AuditEntry lastEntry()
	{
		QList<AuditEntry> list = AuditLog::entries();
		return list.isEmpty() ? AuditEntry() : list.last();
	}

  private slots:
	void keyAndRequest_data();
	void keyAndRequest();
	void keyRejected_data();
	void keyRejected();
	void requestRejected_data();
	void requestRejected();
	void requestFromCertificate();
	void challengePasswordNotShown();
};

RequestSpec test_service_request::tlsSpec(pki_key *key)
{
	RequestSpec spec;
	spec.name = "device-request";
	spec.subject = dn("device.example");
	spec.key = key;
	spec.hashAlgo = digest(NID_sha256);
	spec.extensions.basicCA = ExtensionSpec::bc_not_ca;
	spec.extensions.subjectKeyId = true;
	/* never in a request */
	spec.extensions.authorityKeyId = true;
	spec.extensions.issuerAltName = "issuer:copy";
	spec.extensions.keyUsage << "digitalSignature" << "keyAgreement";
	spec.extensions.keyUsageCritical = true;
	spec.extensions.extKeyUsage << "serverAuth" << "clientAuth";
	/* copycn needs the subject in the extension context;
	 * email:copy only means something in a certificate */
	spec.extensions.subjectAltName =
		"DNS:copycn, IP:10.0.0.7, URI:urn:bxc:device:7, email:copy";
	spec.unstructuredName = "line 7";
	spec.challengePassword = "challenge-pw-2468";
	spec.comment = "service test";
	spec.templateName = "service-test";
	return spec;
}

pki_key *test_service_request::generate(const QString &job,
				const QString &name)
{
	try {
		return Database.model<db_key>()->newKey(ctx, keyjob(job), name);
	} catch (errorEx &err) {
		qWarning() << "newKey failed:" << err.getString();
		return nullptr;
	}
}

void test_service_request::writePem(pki_x509req *req, const QString &file)
{
	BIO *b = BIO_new_file(QFile::encodeName(file).constData(), "w");
	QVERIFY(b);
	QVERIFY(PEM_write_bio_X509_REQ(b, req->getReq()));
	BIO_free(b);
}

QString test_service_request::openssl(const QStringList &args, int *exitCode)
{
#ifdef OPENSSL_PROGRAM
	QProcess p;
	p.setProcessChannelMode(QProcess::MergedChannels);
	p.start(OPENSSL_PROGRAM, args);
	if (!p.waitForFinished(30000))
		*exitCode = -1;
	else
		*exitCode = p.exitCode();
	return QString::fromUtf8(p.readAll());
#else
	(void)args;
	*exitCode = -1;
	return QString();
#endif
}

/* A key of which the database only knows the public part */
pki_key *test_service_request::publicOnlyKey()
{
	EVP_PKEY *full = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
	if (!full)
		return nullptr;
	unsigned char *der = NULL;
	int len = i2d_PUBKEY(full, &der);
	EVP_PKEY_free(full);
	const unsigned char *p = der;
	EVP_PKEY *pub = d2i_PUBKEY(NULL, &p, len);
	OPENSSL_free(der);
	if (!pub)
		return nullptr;
	pki_evp *key = new pki_evp(pub);
	key->setIntName("public-only");
	return dynamic_cast<pki_key*>(Database.model<db_key>()->insert(key));
}

void test_service_request::keyAndRequest_data()
{
	QTest::addColumn<QString>("job");
	QTest::addColumn<QString>("type");
	QTest::addColumn<int>("bits");
	QTest::addColumn<QString>("curve");

	QTest::newRow("RSA") << "RSA:2048" << "RSA" << 2048 << "";
#ifndef OPENSSL_NO_EC
	QTest::newRow("EC") << "EC:prime256v1" << "EC" << 256 << "prime256v1";
#endif
}

void test_service_request::keyAndRequest()
{
	QFETCH(QString, job);
	QFETCH(QString, type);
	QFETCH(int, bits);
	QFETCH(QString, curve);
	int before = AuditLog::entries().size();

	/* Key: one audit entry key.generate */
	pki_key *key = generate(job, "device-key");
	QVERIFY(key);
	QVERIFY(key->isPrivKey());
	QCOMPARE(key->getKeyType(), keytype::byName(type).type);
	QCOMPARE(AuditLog::entries().size(), before + 1);
	AuditEntry e = lastEntry();
	QCOMPARE(e.action, QString("key.generate"));
	QCOMPARE(e.objectType, QString("key"));
	QCOMPARE(e.objectId, key->getSqlItemId().toString());
	QCOMPARE(e.result, QString("success"));
	QCOMPARE(e.actor, QString("os:service-test"));
	QCOMPARE(e.channel, QString("cli"));
	QCOMPARE(e.params["name"].toString(), QString("device-key"));
	QCOMPARE(e.params["key_type"].toString(), type);
	QCOMPARE(e.params["key_size"].toInt(), bits);
	QCOMPARE(e.params["curve"].toString(), curve);
	QCOMPARE(e.params["fingerprint"].toString(),
		key->fingerprint("der sha256"));

	/* Request: one audit entry request.create */
	RequestSpec spec = tlsSpec(key);
	pki_x509req *req = Database.model<db_x509req>()->newRequest(ctx, spec);
	QVERIFY(req);
	QCOMPARE(AuditLog::entries().size(), before + 2);
	QCOMPARE(req->getIntName(), QString("device-request"));
	QCOMPARE(req->getComment(), QString("service test"));
	QCOMPARE(req->getRefKey(), key);
	QCOMPARE(req->getSubject().oneLine(),
		QString("C = DE, O = BxC Security, CN = device.example"));
	QVERIFY(req->verify());

	e = lastEntry();
	QCOMPARE(e.action, QString("request.create"));
	QCOMPARE(e.objectType, QString("request"));
	QCOMPARE(e.objectId, req->getSqlItemId().toString());
	QCOMPARE(e.result, QString("success"));
	QCOMPARE(e.params["name"].toString(), QString("device-request"));
	QCOMPARE(e.params["subject"].toString(), req->getSubject().oneLine());
	QCOMPARE(e.params["key_type"].toString(), type);
	QCOMPARE(e.params["key_size"].toInt(), bits);
	QCOMPARE(e.params["hash_algo"].toString(), QString("SHA256"));
	QCOMPARE(e.params["template"].toString(), QString("service-test"));
	QCOMPARE(e.params["fingerprint"].toString(),
		fingerprint(req->i2d(), EVP_sha256()));
	/* The challenge password is a request attribute, not an audit value */
	QVERIFY(!e.canonical().contains("challenge-pw-2468"));
	QVERIFY(AuditLog::verify().ok());

#ifdef OPENSSL_PROGRAM
	QTemporaryDir dir;
	QVERIFY(dir.isValid());
	QString file = dir.path() + "/device.csr";
	writePem(req, file);
	int rc;
	QString out = openssl({ "req", "-verify", "-noout", "-in", file }, &rc);
	QVERIFY2(rc == 0, CCHAR(out));
	QVERIFY2(out.contains("verify OK"), CCHAR(out));

	out = openssl({ "req", "-noout", "-text", "-in", file }, &rc);
	QVERIFY2(rc == 0, CCHAR(out));
	QVERIFY2(out.contains("DNS:device.example, IP Address:10.0.0.7, "
				"URI:urn:bxc:device:7\n"), CCHAR(out));
	QVERIFY2(out.contains("TLS Web Server Authentication, "
				"TLS Web Client Authentication"), CCHAR(out));
	QVERIFY2(out.contains("Digital Signature, Key Agreement"), CCHAR(out));
	QVERIFY2(out.contains("X509v3 Subject Key Identifier"), CCHAR(out));
	QVERIFY2(out.contains("CA:FALSE"), CCHAR(out));
	QVERIFY2(!out.contains("Authority Key Identifier"), CCHAR(out));
	QVERIFY2(!out.contains("Issuer Alternative Name"), CCHAR(out));
	QVERIFY2(out.contains("unstructuredName"), CCHAR(out));
	QVERIFY2(out.contains("challengePassword"), CCHAR(out));
#endif

	/* The SKI is the SHA-1 of this request's public key */
	STACK_OF(X509_EXTENSION) *exts = X509_REQ_get_extensions(req->getReq());
	QVERIFY(exts);
	ASN1_OCTET_STRING *ski = (ASN1_OCTET_STRING *)X509V3_get_d2i(exts,
				NID_subject_key_identifier, NULL, NULL);
	sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
	QVERIFY(ski);
	const unsigned char *pk;
	int pklen;
	QVERIFY(X509_PUBKEY_get0_param(NULL, &pk, &pklen, NULL,
				X509_REQ_get_X509_PUBKEY(req->getReq())));
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int mdlen;
	QVERIFY(EVP_Digest(pk, pklen, md, &mdlen, EVP_sha1(), NULL));
	QCOMPARE(QByteArray((const char *)ASN1_STRING_get0_data(ski),
				ASN1_STRING_get_length(ski)),
		QByteArray((const char *)md, mdlen));
	ASN1_OCTET_STRING_free(ski);

	/* Persisted, chain still intact */
	reopenDatabase();
	QCOMPARE(Store.getAll<pki_x509req>().size(), 1);
	QCOMPARE(Store.getAll<pki_key>().size(), 1);
	QVERIFY(Store.getAll<pki_x509req>()[0]->getRefKey());
	QVERIFY(AuditLog::verify().ok());
}

void test_service_request::keyRejected_data()
{
	QTest::addColumn<QString>("job");
	QTest::addColumn<QString>("code");

	QTest::newRow("RSA 16 bit") << "RSA:16" << "invalid_key_size";
	QTest::newRow("unknown type") << "FOO:2048" << "invalid_key_type";
#ifndef OPENSSL_NO_EC
	QTest::newRow("unknown curve") << "EC:nocurve" << "invalid_curve";
#endif
}

void test_service_request::keyRejected()
{
	QFETCH(QString, job);
	QFETCH(QString, code);
	int before = AuditLog::entries().size();

	try {
		Database.model<db_key>()->newKey(ctx, keyjob(job), "bad-key");
		QFAIL("newKey accepted the job");
	} catch (serviceError &err) {
		QCOMPARE(err.code, code);
	}
	QCOMPARE(Store.getAll<pki_key>().size(), 0);
	QCOMPARE(AuditLog::entries().size(), before + 1);
	AuditEntry e = lastEntry();
	QCOMPARE(e.action, QString("key.generate"));
	QCOMPARE(e.result, QString("failure"));
	QCOMPARE(e.errorCode, code);
	QVERIFY(e.objectId.isEmpty());
	QCOMPARE(e.params["name"].toString(), QString("bad-key"));
	QVERIFY(AuditLog::verify().ok());
}

void test_service_request::requestRejected_data()
{
	QTest::addColumn<QString>("variant");
	QTest::addColumn<QString>("code");

	QTest::newRow("no key") << "nokey" << "missing_key";
	QTest::newRow("public key only") << "pubonly" << "no_private_key";
	QTest::newRow("same request twice") << "duplicate"
				<< "duplicate_request";
}

void test_service_request::requestRejected()
{
	QFETCH(QString, variant);
	QFETCH(QString, code);
	db_x509req *reqs = Database.model<db_x509req>();
	RequestSpec spec = tlsSpec(nullptr);

	if (variant == "pubonly") {
		spec.key = publicOnlyKey();
		QVERIFY(spec.key);
		QVERIFY(spec.key->isPubKey());
	} else if (variant == "duplicate") {
		/* RSA PKCS#1 v1.5 signatures are deterministic */
		spec.key = generate("RSA:2048", "rsa-key");
		QVERIFY(spec.key);
		QVERIFY(reqs->newRequest(ctx, spec));
	}
	int requests = Store.getAll<pki_x509req>().size();
	int before = AuditLog::entries().size();

	try {
		reqs->newRequest(ctx, spec);
		QFAIL("newRequest accepted the spec");
	} catch (serviceError &err) {
		QCOMPARE(err.code, code);
	}
	QCOMPARE(Store.getAll<pki_x509req>().size(), requests);
	QCOMPARE(AuditLog::entries().size(), before + 1);
	AuditEntry e = lastEntry();
	QCOMPARE(e.action, QString("request.create"));
	QCOMPARE(e.result, QString("failure"));
	QCOMPARE(e.errorCode, code);
	QVERIFY(e.objectId.isEmpty());
	QVERIFY(!e.canonical().contains("challenge-pw-2468"));
	QVERIFY(AuditLog::verify().ok());
}

/* The challengePassword is an enrolment or revocation secret: the
 * properties (--print), the column and the search filter show or match
 * only a marker, the unstructuredName stays as it is (BTD-168) */
void test_service_request::challengePasswordNotShown()
{
	RequestSpec spec = tlsSpec(generate("EC:prime256v1", "ec-key"));
	QVERIFY(spec.key);
	pki_x509req *req = Database.model<db_x509req>()->newRequest(ctx, spec);
	QVERIFY(req);
	QCOMPARE(req->getAttribute(NID_pkcs9_challengePassword),
		QString("challenge-pw-2468"));

	dbheader chall(HD_req_chall_pass), unstr(HD_req_unstr_name);
	QCOMPARE(req->column_data(&chall).toString(),
		pki_x509req::challengePasswordMarker());
	QCOMPARE(req->column_data(&unstr).toString(), QString("line 7"));

	BioByteArray bba;
	req->print(bba, pki_base::print_coloured);
	req->print(bba, pki_base::print_openssl_txt);
	QString text = QString::fromUtf8(bba.byteArray());
	QVERIFY2(!text.contains("challenge-pw-2468"), qPrintable(text));
	QVERIFY(text.contains(pki_x509req::challengePasswordMarker()));
	QVERIFY(text.contains("line 7"));

	pki_base::limitPattern = QRegularExpression("challenge-pw");
	bool bySecret = req->visible();
	pki_base::limitPattern = QRegularExpression("line 7");
	bool byName = req->visible();
	pki_base::limitPattern = QRegularExpression();
	QVERIFY(!bySecret);
	QVERIFY(byName);
}

/* request.from_certificate: the certificate's extensions are copied */
void test_service_request::requestFromCertificate()
{
	pki_key *key = generate("EC:prime256v1", "cert-key");
	QVERIFY(key);
	IssuanceSpec is;
	is.name = "self-signed";
	is.subject = dn("cert.example");
	is.key = key;
	is.notBefore = a1time();
	is.notAfter = a1time(QDateTime::currentDateTimeUtc().addDays(30));
	is.hashAlgo = digest(NID_sha256);
	is.extensions.subjectKeyId = true;
	is.extensions.subjectAltName = "DNS:cert.example";
	is.extensions.extKeyUsage << "clientAuth";
	pki_x509 *cert = Database.model<db_x509>()->newCert(ctx, is);
	QVERIFY(cert);

	RequestSpec spec;
	spec.name = cert->getIntName();
	spec.subject = cert->getSubject();
	spec.key = cert->getRefKey();
	spec.hashAlgo = cert->getDigest();
	spec.copiedExtensions = cert->getV3ext();
	spec.source = transformed;
	pki_x509req *req = Database.model<db_x509req>()->newRequest(ctx, spec);
	QVERIFY(req);
	QVERIFY(req->verify());
	QCOMPARE(req->getSubject().oneLine(), cert->getSubject().oneLine());

	extList el = req->getV3ext();
	extList want = cert->getV3ext();
	QCOMPARE(el.count(), want.count());
	for (int i = 0; i < want.count(); i++)
		QCOMPARE(el[i].getValue(), want[i].getValue());
	QCOMPARE(lastEntry().action, QString("request.create"));
	QVERIFY(AuditLog::verify().ok());
}

XCA_SERVICE_TEST_MAIN(test_service_request)
#include "test_service_request.moc"
