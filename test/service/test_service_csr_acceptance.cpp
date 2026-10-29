/* vi: set sw=4 ts=4:
 *
 * Device CSR acceptance (BTD-65) with the IDIAL CSR corpus
 * (data/idial-csr/, provenance in data/idial-csr/PROVENANCE.json): the
 * proof of possession is checked for every declared algorithm, SHA-1
 * by policy with an audit warning, MD5 never; PKCS#10 quirks are
 * tolerated and never reach the certificate; keyCertSign in a leaf
 * request is a typed RFC 5280 error unless the profile overrides it;
 * the subject is copied byte for byte, the SAN keeps the CSR order and
 * the registered ApplicationUri.
 *
 * KU, EKU and basicConstraints are set from the golden files of BTD-64
 * (data/profiles/golden/) here; the profile engine (BTD-54) derives them
 * from the profile itself.
 */

#include <QFile>
#include <QJsonArray>
#include <QMap>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QTemporaryDir>

#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/db_key.h"
#include "lib/db_x509.h"
#include "lib/db_x509req.h"
#include "lib/exception.h"
#include "lib/issuance.h"
#include "lib/pki_x509.h"
#include "lib/pki_x509req.h"

#include "ServiceTestCase.h"

class test_service_csr_acceptance : public ServiceTestCase
{
	Q_OBJECT

	ServiceContext ctx{ ServiceContext::cli, "os:service-test" };
	QTemporaryDir dir{};

	pki_x509 *issuingCa(const QString &keyJob);
	pki_x509req *loadCsr(const QString &file, const QByteArray &der);
	static QByteArray corpus(const QString &name);
	static QJsonObject golden(const QString &name);
	static IssuanceSpec profileSpec(const QJsonObject &golden,
				pki_x509req *req, pki_x509 *ca);
	pki_x509 *issue(const IssuanceSpec &spec);
	void expectRejected(const IssuanceSpec &spec, const QString &code);
	QByteArray opensslCsr(const QStringList &args);
	static QString extText(pki_x509 *cert, int nid);
	static QByteArray extDer(const X509_EXTENSION *ext);
	/* A CSR built with the OpenSSL API, for what openssl req refuses
	 * to write: the subject and extensions as given, P-256, SHA-256 */
	static QByteArray apiCsr(X509_NAME *subject,
				STACK_OF(X509_EXTENSION) *exts);

  private slots:
	void corpusIssued_data();
	void corpusIssued();
	void tamperedCorpusRejected_data();
	void tamperedCorpusRejected();
	void md5Rejected();
	void sha1ByPolicy();
	void keyCertSignStrict_data();
	void keyCertSignStrict();
	void keyCertSignCopiedByGui();
	void registeredUri();
	void forbiddenCharacters();
	void missingOrganization();
	void sanRulesOfProfile_data();
	void sanRulesOfProfile();
	void sanCriticalityFromProfile();
	void duplicateAndMalformedExtensions();
	void pssSha1();
	void addedOrganizationChecked();
	void sha1IssuanceHashRefused();
};

pki_x509 *test_service_csr_acceptance::issuingCa(const QString &keyJob)
{
	IssuanceSpec spec;
	spec.name = "Issuing CA " + keyJob;
	x509name n;
	n.addEntryByNid(NID_countryName, "DE");
	n.addEntryByNid(NID_organizationName, "BxC Security");
	n.addEntryByNid(NID_commonName, spec.name);
	spec.subject = n;
	spec.key = Database.model<db_key>()->newKey(keyjob(keyJob), spec.name);
	spec.notBefore = a1time();
	spec.notAfter = a1time(QDateTime::currentDateTimeUtc().addDays(1000));
	spec.hashAlgo = digest(NID_sha256);
	spec.extensions.basicCA = ExtensionSpec::bc_ca;
	spec.extensions.basicCritical = true;
	spec.extensions.subjectKeyId = true;
	spec.extensions.keyUsage << "keyCertSign" << "cRLSign";
	spec.extensions.keyUsageCritical = true;
	return issue(spec);
}

QByteArray test_service_csr_acceptance::corpus(const QString &name)
{
	QFile f(QString(SERVICE_TEST_DATA "/idial-csr/%1.der").arg(name));
	if (!f.open(QIODevice::ReadOnly))
		return QByteArray();
	return f.readAll();
}

QJsonObject test_service_csr_acceptance::golden(const QString &name)
{
	QFile f(QString(SERVICE_TEST_DATA "/profiles/golden/%1.json").arg(name));
	if (!f.open(QIODevice::ReadOnly))
		return QJsonObject();
	return QJsonDocument::fromJson(f.readAll()).object();
}

pki_x509req *test_service_csr_acceptance::loadCsr(const QString &file,
				const QByteArray &der)
{
	QString path = dir.filePath(file + ".der");
	QFile f(path);
	if (!f.open(QIODevice::WriteOnly))
		return nullptr;
	f.write(der);
	f.close();
	pki_x509req *req = new pki_x509req(file);
	req->fload(path);
	return dynamic_cast<pki_x509req *>(
			Database.model<db_x509req>()->insert(req));
}

/* The issuance a device profile asks for: KU, EKU and basicConstraints
 * of the golden file, SKI and AKI computed, everything else of the CSR
 * ignored except the SAN */
IssuanceSpec test_service_csr_acceptance::profileSpec(const QJsonObject &g,
				pki_x509req *req, pki_x509 *ca)
{
	IssuanceSpec spec;
	spec.request = req;
	spec.subject = req->getSubject();
	spec.signer = ca;
	spec.notBefore = a1time();
	spec.notAfter = a1time(QDateTime::currentDateTimeUtc().addDays(365));
	spec.hashAlgo = digest(NID_sha256);
	spec.templateName = g["profile"].toString();
	spec.csrPolicy.profile = true;
	spec.csrPolicy.csrSha1 = CsrPolicy::sha1_accept_with_warning;
	spec.csrPolicy.keyCertSignRequest = CsrPolicy::keycertsign_override;
	/* no SAN in the golden file: the profile allows none */
	spec.csrPolicy.sanCounts[GEN_DNS] = qMakePair(0, 0);
	spec.csrPolicy.sanCounts[GEN_IPADD] = qMakePair(0, 0);
	foreach(QJsonValue v, g["extensions"].toArray()) {
		QJsonObject e = v.toObject();
		QString name = e["name"].toString();
		bool critical = e["critical"].toBool();
		if (name == "subjectAltName") {
			QJsonObject san = e["value"].toObject();
			for (int type : { GEN_DNS, GEN_IPADD }) {
				QJsonObject c = san[type == GEN_DNS ? "dns" : "ip"]
						.toObject();
				spec.csrPolicy.sanCounts[type] = qMakePair(
					c["min"].toInt(), c["max"].toInt());
			}
			spec.csrPolicy.sanCritical = critical;
		}
		if (name == "basicConstraints") {
			spec.extensions.basicCA = ExtensionSpec::bc_not_ca;
			spec.extensions.basicCritical = critical;
		} else if (name == "keyUsage") {
			foreach(QJsonValue b, e["value"].toArray())
				spec.extensions.keyUsage << b.toString();
			spec.extensions.keyUsageCritical = critical;
		} else if (name == "extendedKeyUsage") {
			foreach(QJsonValue p, e["value"].toArray())
				spec.extensions.extKeyUsage << p.toString();
			spec.extensions.extKeyUsageCritical = critical;
		} else if (name == "subjectKeyIdentifier") {
			spec.extensions.subjectKeyId = true;
		} else if (name == "authorityKeyIdentifier") {
			spec.extensions.authorityKeyId = true;
		}
	}
	return spec;
}

pki_x509 *test_service_csr_acceptance::issue(const IssuanceSpec &spec)
{
	try {
		return Database.model<db_x509>()->newCert(ctx, spec);
	} catch (errorEx &err) {
		qWarning() << "newCert failed:" << err.getString();
		return nullptr;
	}
}

void test_service_csr_acceptance::expectRejected(const IssuanceSpec &spec,
				const QString &code)
{
	int before = AuditLog::entries().size();
	QString got;
	try {
		Database.model<db_x509>()->newCert(ctx, spec);
		got = "<issued>";
	} catch (serviceError &err) {
		got = err.code;
	} catch (errorEx &err) {
		got = "<errorEx: " + err.getString() + ">";
	}
	QCOMPARE(got, code);
	QList<AuditEntry> entries = AuditLog::entries();
	QCOMPARE(entries.size(), before + 1);
	QCOMPARE(entries.last().result, QString("failure"));
	QCOMPARE(entries.last().errorCode, code);
	QVERIFY(AuditLog::verify().ok());
}

/* A CSR made by the openssl program, DER */
QByteArray test_service_csr_acceptance::opensslCsr(const QStringList &args)
{
#ifdef OPENSSL_PROGRAM
	QString out = dir.filePath("gen.der");
	QFile::remove(out);
	QProcess p;
	p.setProcessChannelMode(QProcess::MergedChannels);
	p.start(OPENSSL_PROGRAM, QStringList{ "req", "-new", "-nodes",
		"-keyout", dir.filePath("gen.key"), "-outform", "DER",
		"-out", out } + args);
	if (!p.waitForFinished(30000) || p.exitCode() != 0) {
		qWarning() << "openssl req failed:" << p.readAll();
		return QByteArray();
	}
	QFile f(out);
	if (!f.open(QIODevice::ReadOnly))
		return QByteArray();
	return f.readAll();
#else
	Q_UNUSED(args);
	return QByteArray();
#endif
}

QString test_service_csr_acceptance::extText(pki_x509 *c, int nid)
{
	X509 *x = c->getCert();
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

QByteArray test_service_csr_acceptance::extDer(const X509_EXTENSION *ext)
{
	if (!ext)
		return QByteArray();
	const ASN1_OCTET_STRING *v = X509_EXTENSION_get_data(ext);
	return QByteArray((const char *)ASN1_STRING_get0_data(v),
			ASN1_STRING_get_length(v));
}

void test_service_csr_acceptance::corpusIssued_data()
{
	QTest::addColumn<QString>("csr");
	QTest::addColumn<QString>("goldenName");
	QTest::addColumn<QString>("caKey");
	QTest::addColumn<QString>("uri");
	QTest::addColumn<QString>("sigAlg");

	QTest::newRow("plc10 S7 OPC UA, SHA-1, keyCertSign")
		<< "plc10_csr_sha1" << "opcua-server.rsa-2048" << "RSA:3072"
		<< "urn:SIMATIC.S7-1500.OPC-UA.Application:plc10"
		<< "sha256WithRSAEncryption";
	QTest::newRow("plc10 S7 OPC UA, DC first")
		<< "plc10_csr_uri_san" << "opcua-server.rsa-2048" << "RSA:3072"
		<< "urn:SIMATIC.S7-1500.OPC-UA.Application:plc10"
		<< "sha256WithRSAEncryption";
	QTest::newRow("plc12 S7 OPC UA V04, SHA-1")
		<< "plc12_csr_sha1" << "opcua-server.rsa-2048" << "RSA:3072"
		<< "urn:SIMATIC:plc12" << "sha256WithRSAEncryption";
	QTest::newRow("plc11 S7 web, ECDSA SHA-1, CA:TRUE")
		<< "plc11_web_csr_ecdsa_sha1" << "tls-server-web.ec-p256"
		<< "EC:prime256v1" << "" << "ecdsa-with-SHA256";
}

/* AC 2-4: every corpus CSR is issued under its profile; the profile, not
 * the CSR, decides KU, EKU and basicConstraints; subject and SAN are the
 * device's own bytes */
void test_service_csr_acceptance::corpusIssued()
{
	QFETCH(QString, csr);
	QFETCH(QString, goldenName);
	QFETCH(QString, caKey);
	QFETCH(QString, uri);
	QFETCH(QString, sigAlg);

	QJsonObject g = golden(goldenName);
	QVERIFY(!g.isEmpty());
	pki_x509 *ca = issuingCa(caKey);
	QVERIFY(ca);
	pki_x509req *req = loadCsr(csr, corpus(csr));
	QVERIFY(req);
	/* the proof of possession under OpenSSL 4 needs no setting for
	 * SHA-1 (AC 2) */
	QVERIFY(req->verify());

	IssuanceSpec spec = profileSpec(g, req, ca);
	spec.csrPolicy.registeredUri = uri;
	int before = AuditLog::entries().size();
	pki_x509 *cert = issue(spec);
	QVERIFY(cert);

	/* KU, EKU, basicConstraints as the golden file says */
	foreach(QJsonValue v, g["extensions"].toArray()) {
		QJsonObject e = v.toObject();
		QString name = e["name"].toString();
		QString crit = e["critical"].toBool() ? "critical: " : "";
		if (name == "basicConstraints")
			QCOMPARE(extText(cert, NID_basic_constraints),
				crit + "CA:FALSE");
		if (name == "keyUsage" || name == "extendedKeyUsage") {
			int nid = name == "keyUsage" ? NID_key_usage :
							NID_ext_key_usage;
			/* key usage bits as OpenSSL prints them */
			static const QMap<QString, QString> kuText {
				{ "digitalSignature", "Digital Signature" },
				{ "nonRepudiation", "Non Repudiation" },
				{ "keyEncipherment", "Key Encipherment" },
				{ "dataEncipherment", "Data Encipherment" },
				{ "keyAgreement", "Key Agreement" },
			};
			QStringList want;
			foreach(QJsonValue b, e["value"].toArray()) {
				QString v = b.toString();
				if (kuText.contains(v)) {
					want << kuText[v];
					continue;
				}
				int n = OBJ_txt2nid(CCHAR(v));
				want << (n == NID_undef ? v : QString(OBJ_nid2ln(n)));
			}
			QString got = extText(cert, nid);
			QVERIFY2(got.startsWith(crit), CCHAR(got));
			QCOMPARE(got.mid(crit.size()).split(", "), want);
		}
	}
	QVERIFY(!extText(cert, NID_key_usage).contains("Certificate Sign"));
	QVERIFY(!cert->isCA());
	QVERIFY(extText(cert, NID_netscape_comment).isEmpty());
	/* AKI is the issuer's key id, never the CSR's DirName and serial */
	QString aki = extText(cert, NID_authority_key_identifier);
	QVERIFY2(!aki.contains("DirName") && !aki.contains("serial"),
		CCHAR(aki));
	QVERIFY(aki.contains(extText(ca, NID_subject_key_identifier).trimmed()));
	QCOMPARE(QString(OBJ_nid2ln(X509_get_signature_nid(cert->getCert()))),
		sigAlg);

	/* subject DER identical to the CSR (AC 4) */
	unsigned char *a = nullptr, *b = nullptr;
	int la = i2d_X509_NAME(X509_REQ_get_subject_name(req->getReq()), &a);
	int lb = i2d_X509_NAME(X509_get_subject_name(cert->getCert()), &b);
	QByteArray reqSubject((char *)a, la), certSubject((char *)b, lb);
	OPENSSL_free(a);
	OPENSSL_free(b);
	QCOMPARE(certSubject, reqSubject);

	/* SAN: the CSR's entries in the CSR's order; the registered URI is
	 * already in each of these CSRs; no dNSName made from the CN */
	STACK_OF(X509_EXTENSION) *reqExts = X509_REQ_get_extensions(req->getReq());
	X509_EXTENSION *reqSan = nullptr;
	for (int i = 0; i < sk_X509_EXTENSION_num(reqExts); i++) {
		X509_EXTENSION *e = sk_X509_EXTENSION_value(reqExts, i);
		if (OBJ_obj2nid(X509_EXTENSION_get_object(e)) == NID_subject_alt_name)
			reqSan = e;
	}
	QVERIFY(reqSan);
	int i = X509_get_ext_by_NID(cert->getCert(), NID_subject_alt_name, -1);
	QVERIFY(i >= 0);
	QCOMPARE(extDer(X509_get_ext(cert->getCert(), i)), extDer(reqSan));
	sk_X509_EXTENSION_pop_free(reqExts, X509_EXTENSION_free);

	/* SHA-1 acceptance audited as a warning */
	QList<AuditEntry> entries = AuditLog::entries();
	QCOMPARE(entries.size(), before + 1);
	AuditEntry e = entries.last();
	QCOMPARE(e.result, QString("success"));
	QCOMPARE(e.params["warning"].toString(), QString("csr_sha1_accepted"));
	QVERIFY(e.params["csr_signature_algorithm"].toString()
			.contains("SHA1", Qt::CaseInsensitive));

	/* the record of AC 3: openssl x509 -text of the issued certificate */
	BIO *bio = BIO_new(BIO_s_mem());
	X509_print_ex(bio, cert->getCert(), XN_FLAG_ONELINE,
			X509_FLAG_NO_PUBKEY | X509_FLAG_NO_SIGDUMP);
	char *data;
	long len = BIO_get_mem_data(bio, &data);
	qInfo().noquote() << csr << "\n" << QString::fromUtf8(data, len);
	BIO_free(bio);
	QVERIFY(AuditLog::verify().ok());
}

void test_service_csr_acceptance::tamperedCorpusRejected_data()
{
	QTest::addColumn<QString>("csr");
	QTest::newRow("plc10_csr_sha1") << "plc10_csr_sha1";
	QTest::newRow("plc10_csr_uri_san") << "plc10_csr_uri_san";
	QTest::newRow("plc11_web_csr_ecdsa_sha1") << "plc11_web_csr_ecdsa_sha1";
	QTest::newRow("plc12_csr_sha1") << "plc12_csr_sha1";
}

/* AC 2: a tampered copy of each corpus CSR fails the proof of possession */
void test_service_csr_acceptance::tamperedCorpusRejected()
{
	QFETCH(QString, csr);
	pki_x509 *ca = issuingCa(csr.contains("web") ? "EC:prime256v1" :
							"RSA:3072");
	QVERIFY(ca);
	QByteArray der = corpus(csr);
	QVERIFY(der.size() > 100);
	/* one bit of the subject: the signature no longer matches */
	int pos = der.indexOf("plc1");
	QVERIFY(pos > 0);
	der[pos + 3] = der[pos + 3] ^ 0x01;
	pki_x509req *req = loadCsr(csr + "-tampered", der);
	QVERIFY(req);
	QVERIFY(!req->verify());
	IssuanceSpec spec = profileSpec(golden(csr.contains("web") ?
		"tls-server-web.ec-p256" : "opcua-server.rsa-2048"), req, ca);
	expectRejected(spec, "invalid_csr_signature");
}

/* AC 2: MD5 is never accepted, whatever the policy says */
void test_service_csr_acceptance::md5Rejected()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	pki_x509 *ca = issuingCa("RSA:3072");
	QVERIFY(ca);
	QByteArray der = opensslCsr({ "-newkey", "rsa:2048", "-md5",
			"-subj", "/CN=md5.example" });
	QVERIFY(!der.isEmpty());
	pki_x509req *req = loadCsr("md5", der);
	QVERIFY(req);
	IssuanceSpec spec = profileSpec(golden("opcua-server.rsa-2048"), req, ca);
	expectRejected(spec, "csr_digest_not_allowed");
	/* also without a profile (GUI) */
	spec.csrPolicy = CsrPolicy();
	expectRejected(spec, "csr_digest_not_allowed");
#endif
}

/* csr_sha1: reject refuses, accept-with-warning (also the GUI default)
 * accepts and audits a warning */
void test_service_csr_acceptance::sha1ByPolicy()
{
	pki_x509 *ca = issuingCa("RSA:3072");
	QVERIFY(ca);
	pki_x509req *req = loadCsr("plc12", corpus("plc12_csr_sha1"));
	QVERIFY(req);
	IssuanceSpec spec = profileSpec(golden("opcua-server.rsa-2048"), req, ca);
	spec.csrPolicy.registeredUri = "urn:SIMATIC:plc12";
	spec.csrPolicy.csrSha1 = CsrPolicy::sha1_reject;
	expectRejected(spec, "csr_sha1_rejected");

	/* GUI: no profile, no copied extensions */
	IssuanceSpec gui = spec;
	gui.csrPolicy = CsrPolicy();
	QVERIFY(issue(gui));
	QCOMPARE(AuditLog::entries().last().params["warning"].toString(),
		QString("csr_sha1_accepted"));
}

void test_service_csr_acceptance::keyCertSignStrict_data()
{
	QTest::addColumn<QString>("csr");
	QTest::addColumn<QString>("goldenName");
	QTest::newRow("keyCertSign with CA:FALSE") << "plc10_csr_sha1"
			<< "opcua-server.rsa-2048";
	QTest::newRow("CA:TRUE in a web CSR") << "plc11_web_csr_ecdsa_sha1"
			<< "tls-server-web.ec-p256";
}

/* AC 5: strict mode names RFC 5280 4.2.1.9, the device profile overrides */
void test_service_csr_acceptance::keyCertSignStrict()
{
	QFETCH(QString, csr);
	QFETCH(QString, goldenName);
	pki_x509 *ca = issuingCa(csr.contains("web") ? "EC:prime256v1" :
							"RSA:3072");
	QVERIFY(ca);
	pki_x509req *req = loadCsr(csr, corpus(csr));
	QVERIFY(req);
	IssuanceSpec spec = profileSpec(golden(goldenName), req, ca);
	if (!csr.contains("web"))
		spec.csrPolicy.registeredUri =
			"urn:SIMATIC.S7-1500.OPC-UA.Application:plc10";
	spec.csrPolicy.keyCertSignRequest = CsrPolicy::keycertsign_reject;
	try {
		Database.model<db_x509>()->newCert(ctx, spec);
		QFAIL("issued");
	} catch (serviceError &err) {
		QCOMPARE(err.code, QString("csr_keycertsign_not_ca"));
		QVERIFY2(err.getString().contains("RFC 5280"),
			CCHAR(err.getString()));
	}
	spec.csrPolicy.keyCertSignRequest = CsrPolicy::keycertsign_override;
	pki_x509 *cert = issue(spec);
	QVERIFY(cert);
	QVERIFY(!extText(cert, NID_key_usage).contains("Certificate Sign"));
	QVERIFY(!cert->isCA());
}

/* The GUI's "copy extensions from the request" copied keyCertSign with
 * CA:FALSE into the certificate (seen at bxc-main 9121ddcd); now a typed
 * error, as in strict mode */
void test_service_csr_acceptance::keyCertSignCopiedByGui()
{
	pki_x509 *ca = issuingCa("RSA:3072");
	QVERIFY(ca);
	pki_x509req *req = loadCsr("plc10", corpus("plc10_csr_sha1"));
	QVERIFY(req);
	IssuanceSpec spec;
	spec.request = req;
	spec.subject = req->getSubject();
	spec.signer = ca;
	spec.notBefore = a1time();
	spec.notAfter = a1time(QDateTime::currentDateTimeUtc().addDays(90));
	spec.hashAlgo = digest(NID_sha256);
	spec.copyRequestExtensions = true;
	spec.extensions.basicCA = ExtensionSpec::bc_not_ca;
	spec.extensions.subjectKeyId = true;
	spec.extensions.authorityKeyId = true;
	expectRejected(spec, "csr_keycertsign_not_ca");

	/* plc12 asks for no keyCertSign: copied as before */
	pki_x509req *req12 = loadCsr("plc12", corpus("plc12_csr_sha1"));
	QVERIFY(req12);
	spec.request = req12;
	spec.subject = req12->getSubject();
	pki_x509 *cert = issue(spec);
	QVERIFY(cert);
	QCOMPARE(extText(cert, NID_ext_key_usage),
		QString("critical: TLS Web Server Authentication"));
}

/* The ApplicationUri comes from the registration: a different CSR URI is
 * rejected like Bad_CertificateUriInvalid, a CSR without one gets it
 * after its own entries */
void test_service_csr_acceptance::registeredUri()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	pki_x509 *ca = issuingCa("RSA:3072");
	QVERIFY(ca);
	QJsonObject g = golden("opcua-server.rsa-2048");

	pki_x509req *req = loadCsr("plc12", corpus("plc12_csr_sha1"));
	QVERIFY(req);
	IssuanceSpec spec = profileSpec(g, req, ca);
	spec.csrPolicy.registeredUri = "urn:SIMATIC:plc99";
	expectRejected(spec, "csr_uri_mismatch");

	QByteArray der = opensslCsr({ "-newkey", "rsa:2048",
		"-subj", "/C=DE/O=BxC/CN=dev7",
		"-addext", "subjectAltName=DNS:dev7.example,IP:10.0.0.7" });
	QVERIFY(!der.isEmpty());
	pki_x509req *noUri = loadCsr("dev7", der);
	QVERIFY(noUri);
	spec = profileSpec(g, noUri, ca);
	spec.csrPolicy.registeredUri = "urn:bxc:dev7";
	pki_x509 *cert = issue(spec);
	QVERIFY(cert);
	QCOMPARE(extText(cert, NID_subject_alt_name),
		QString("DNS:dev7.example, IP Address:10.0.0.7, URI:urn:bxc:dev7"));

	/* a web profile allows no URI at all */
	spec = profileSpec(golden("tls-server-web.rsa-2048"), req, ca);
	expectRejected(spec, "csr_uri_not_allowed");
#endif
}

/* '/' and '=' in subject values brick S7-1500 V02.09.08/V02.09.09 */
void test_service_csr_acceptance::forbiddenCharacters()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	pki_x509 *ca = issuingCa("RSA:3072");
	QVERIFY(ca);
	QByteArray der = opensslCsr({ "-newkey", "rsa:2048",
		"-subj", "/C=DE/O=Line 1\\/2/CN=plc13",
		"-addext", "subjectAltName=URI:urn:SIMATIC:plc13" });
	QVERIFY(!der.isEmpty());
	pki_x509req *req = loadCsr("plc13", der);
	QVERIFY(req);
	IssuanceSpec spec = profileSpec(golden("opcua-server.rsa-2048"), req, ca);
	spec.csrPolicy.registeredUri = "urn:SIMATIC:plc13";
	spec.csrPolicy.forbiddenCharacters = "/=";
	expectRejected(spec, "csr_subject_forbidden_character");
	spec.csrPolicy.forbiddenCharacters.clear();
	QVERIFY(issue(spec));
#endif
}

/* add_missing_o: off by default (the device mirrors its DN); on, the O
 * of the registration is appended and nothing else moves */
void test_service_csr_acceptance::missingOrganization()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	pki_x509 *ca = issuingCa("RSA:3072");
	QVERIFY(ca);
	QByteArray der = opensslCsr({ "-newkey", "rsa:2048",
		"-subj", "/C=DE/CN=plc14",
		"-addext", "subjectAltName=URI:urn:SIMATIC:plc14" });
	QVERIFY(!der.isEmpty());
	pki_x509req *req = loadCsr("plc14", der);
	QVERIFY(req);
	IssuanceSpec spec = profileSpec(golden("opcua-server.rsa-2048"), req, ca);
	spec.csrPolicy.registeredUri = "urn:SIMATIC:plc14";
	pki_x509 *plain = issue(spec);
	QVERIFY(plain);
	QCOMPARE(plain->getSubject().oneLine(), QString("C = DE, CN = plc14"));
	spec.name = "plc14-o";
	spec.csrPolicy.missingO = "BxC";
	pki_x509 *withO = issue(spec);
	QVERIFY(withO);
	QCOMPARE(withO->getSubject().oneLine(),
		QString("C = DE, CN = plc14, O = BxC"));
#endif
}

QByteArray test_service_csr_acceptance::apiCsr(X509_NAME *subject,
				STACK_OF(X509_EXTENSION) *exts)
{
	EVP_PKEY *key = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256");
	X509_REQ *req = X509_REQ_new();
	X509_REQ_set_version(req, X509_REQ_VERSION_1);
	X509_REQ_set_subject_name(req, subject);
	X509_REQ_set_pubkey(req, key);
	if (exts)
		X509_REQ_add_extensions(req, exts);
	X509_REQ_sign(req, key, EVP_sha256());
	unsigned char *der = nullptr;
	int len = i2d_X509_REQ(req, &der);
	QByteArray out(len > 0 ? (const char *)der : "", qMax(len, 0));
	OPENSSL_free(der);
	X509_REQ_free(req);
	EVP_PKEY_free(key);
	return out;
}

/* mr-processor review of xca#44, blocker 2: under a profile the CSR SAN
 * carries only the name types and counts of the profile, no wildcard,
 * one URI at most */
void test_service_csr_acceptance::sanRulesOfProfile_data()
{
	QTest::addColumn<QString>("profile");
	QTest::addColumn<QString>("san");
	QTest::addColumn<QString>("uri");
	QTest::addColumn<int>("dnsOrIpMin");
	QTest::addColumn<QString>("code");

	QString web = "tls-server-web.rsa-2048", opc = "opcua-server.rsa-2048";
	QTest::newRow("web, one name") << web << "DNS:a.example" << "" << 1 << "";
	QTest::newRow("web, two names") << web << "DNS:a.example,DNS:b.example"
		<< "" << 0 << "csr_san_count";
	QTest::newRow("otherName") << web << "otherName:1.2.3.4;UTF8:x,DNS:a.example"
		<< "" << 0 << "csr_san_type_not_allowed";
	QTest::newRow("e-mail") << web << "email:a@b.example,DNS:a.example"
		<< "" << 0 << "csr_san_type_not_allowed";
	QTest::newRow("dirName") << web << "dirName:dir,DNS:a.example"
		<< "" << 0 << "csr_san_type_not_allowed";
	QTest::newRow("wildcard") << web << "DNS:*.example.com" << "" << 0
		<< "csr_san_wildcard";
	QTest::newRow("OPC, URI and name") << opc << "URI:urn:x:plc,DNS:plc.example"
		<< "urn:x:plc" << 1 << "";
	QTest::newRow("OPC, URI twice") << opc
		<< "URI:urn:x:plc,URI:urn:x:plc,DNS:plc.example" << "urn:x:plc" << 1
		<< "csr_uri_duplicate";
	QTest::newRow("OPC, no name or address") << opc << "URI:urn:x:plc"
		<< "urn:x:plc" << 1 << "csr_san_count";
	QTest::newRow("OPC, five names") << opc
		<< "URI:urn:x:plc,DNS:a.x,DNS:b.x,DNS:c.x,DNS:d.x,DNS:e.x"
		<< "urn:x:plc" << 1 << "csr_san_count";
}

void test_service_csr_acceptance::sanRulesOfProfile()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	QFETCH(QString, profile);
	QFETCH(QString, san);
	QFETCH(QString, uri);
	QFETCH(int, dnsOrIpMin);
	QFETCH(QString, code);
	pki_x509 *ca = issuingCa("RSA:3072");
	QVERIFY(ca);
	QFile cnf(dir.filePath("dir.cnf"));
	QVERIFY(cnf.open(QIODevice::WriteOnly));
	cnf.write("[req]\ndistinguished_name=dn\n[dn]\n[dir]\nCN=other\n");
	cnf.close();
	QByteArray der = opensslCsr({ "-newkey", "rsa:2048", "-config",
		cnf.fileName(), "-subj", "/C=DE/O=BxC/CN=dev8",
		"-addext", "subjectAltName=" + san });
	QVERIFY(!der.isEmpty());
	pki_x509req *req = loadCsr("dev8", der);
	QVERIFY(req);
	IssuanceSpec spec = profileSpec(golden(profile), req, ca);
	spec.csrPolicy.registeredUri = uri;
	spec.csrPolicy.dnsOrIpMin = dnsOrIpMin;
	if (code.isEmpty())
		QVERIFY(issue(spec));
	else
		expectRejected(spec, code);
#endif
}

/* The SAN keeps the device's bytes, but the profile decides whether it
 * is critical */
void test_service_csr_acceptance::sanCriticalityFromProfile()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	pki_x509 *ca = issuingCa("RSA:3072");
	QByteArray der = opensslCsr({ "-newkey", "rsa:2048",
		"-subj", "/C=DE/O=BxC/CN=dev9",
		"-addext", "subjectAltName=critical,DNS:dev9.example" });
	pki_x509req *req = loadCsr("dev9", der);
	QVERIFY(req);
	IssuanceSpec spec = profileSpec(golden("tls-server-web.rsa-2048"), req, ca);
	QVERIFY(!spec.csrPolicy.sanCritical);
	pki_x509 *cert = issue(spec);
	QVERIFY(cert);
	QCOMPARE(extText(cert, NID_subject_alt_name), QString("DNS:dev9.example"));
	STACK_OF(X509_EXTENSION) *exts = X509_REQ_get_extensions(req->getReq());
	QByteArray asked;
	for (int i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
		X509_EXTENSION *e = sk_X509_EXTENSION_value(exts, i);
		if (OBJ_obj2nid(X509_EXTENSION_get_object(e)) == NID_subject_alt_name)
			asked = extDer(e);
	}
	sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
	X509 *x = cert->getCert();
	QCOMPARE(extDer(X509_get_ext(x, X509_get_ext_by_NID(x,
			NID_subject_alt_name, -1))), asked);
#endif
}

/* Blocker 1: a CSR with an extension twice or a SAN that does not decode
 * is refused, with or without a profile, and the failure entry names
 * the CSR's signature algorithm */
void test_service_csr_acceptance::duplicateAndMalformedExtensions()
{
	pki_x509 *ca = issuingCa("RSA:3072");
	X509_NAME *name = X509_NAME_new();
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
			(const unsigned char *)"dev10", -1, -1, 0);
	STACK_OF(X509_EXTENSION) *twice = sk_X509_EXTENSION_new_null();
	for (const char *v : { "URI:urn:x:dev10", "URI:urn:x:other" }) {
		X509_EXTENSION *e = X509V3_EXT_conf_nid(nullptr, nullptr,
				NID_subject_alt_name, v);
		QVERIFY(e);
		sk_X509_EXTENSION_push(twice, e);
	}
	QByteArray dup = apiCsr(name, twice);
	sk_X509_EXTENSION_pop_free(twice, X509_EXTENSION_free);

	ASN1_OCTET_STRING *garbage = ASN1_OCTET_STRING_new();
	ASN1_OCTET_STRING_set(garbage, (const unsigned char *)"\x30\x05\x82", 3);
	STACK_OF(X509_EXTENSION) *broken = sk_X509_EXTENSION_new_null();
	sk_X509_EXTENSION_push(broken, X509_EXTENSION_create_by_NID(nullptr,
			NID_subject_alt_name, 0, garbage));
	ASN1_OCTET_STRING_free(garbage);
	QByteArray bad = apiCsr(name, broken);
	sk_X509_EXTENSION_pop_free(broken, X509_EXTENSION_free);
	X509_NAME_free(name);
	QVERIFY(!dup.isEmpty() && !bad.isEmpty());

	QJsonObject g = golden("opcua-server.rsa-2048");
	pki_x509req *req = loadCsr("dev10-dup", dup);
	QVERIFY(req);
	IssuanceSpec spec = profileSpec(g, req, ca);
	spec.csrPolicy.registeredUri = "urn:x:dev10";
	expectRejected(spec, "csr_duplicate_extension");
	QCOMPARE(AuditLog::entries().last().params.value(
		"csr_signature_algorithm").toString(), QString("ecdsa-with-SHA256"));
	IssuanceSpec plain = spec;
	plain.csrPolicy = CsrPolicy();
	expectRejected(plain, "csr_duplicate_extension");

	pki_x509req *malformed = loadCsr("dev10-bad", bad);
	QVERIFY(malformed);
	spec = profileSpec(g, malformed, ca);
	spec.csrPolicy.registeredUri = "urn:x:dev10";
	expectRejected(spec, "csr_san_invalid");
}

/* MINOR 3: RSASSA-PSS names its hash in the parameters; SHA-1 there is
 * SHA-1 for the policy */
void test_service_csr_acceptance::pssSha1()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	pki_x509 *ca = issuingCa("RSA:3072");
	QByteArray der = opensslCsr({ "-newkey", "rsa:2048", "-sha1",
		"-sigopt", "rsa_padding_mode:pss",
		"-subj", "/C=DE/O=BxC/CN=dev11",
		"-addext", "subjectAltName=URI:urn:x:dev11,DNS:dev11.example" });
	QVERIFY(!der.isEmpty());
	pki_x509req *req = loadCsr("dev11", der);
	QVERIFY(req);
	IssuanceSpec spec = profileSpec(golden("opcua-server.rsa-2048"), req, ca);
	spec.csrPolicy.registeredUri = "urn:x:dev11";
	spec.csrPolicy.csrSha1 = CsrPolicy::sha1_reject;
	expectRejected(spec, "csr_sha1_rejected");
	spec.csrPolicy.csrSha1 = CsrPolicy::sha1_accept_with_warning;
	QVERIFY(issue(spec));
	QVERIFY(AuditLog::entries().last().params.value("warning").toString()
		.contains("csr_sha1_accepted"));
#endif
}

/* MINOR 5: the O a profile adds is checked like the device's values */
void test_service_csr_acceptance::addedOrganizationChecked()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	pki_x509 *ca = issuingCa("RSA:3072");
	QByteArray der = opensslCsr({ "-newkey", "rsa:2048",
		"-subj", "/C=DE/CN=plc15",
		"-addext", "subjectAltName=URI:urn:SIMATIC:plc15" });
	pki_x509req *req = loadCsr("plc15", der);
	QVERIFY(req);
	IssuanceSpec spec = profileSpec(golden("opcua-server.rsa-2048"), req, ca);
	spec.csrPolicy.registeredUri = "urn:SIMATIC:plc15";
	spec.csrPolicy.dnsOrIpMin = 0;
	spec.csrPolicy.forbiddenCharacters = "/=";
	spec.csrPolicy.missingO = "Line 1/2";
	expectRejected(spec, "csr_subject_forbidden_character");
#endif
}

/* MINOR 9: a SHA-1 CSR accepted by the profile is never signed with
 * SHA-1 itself */
void test_service_csr_acceptance::sha1IssuanceHashRefused()
{
	pki_x509 *ca = issuingCa("RSA:3072");
	pki_x509req *req = loadCsr("plc12", corpus("plc12_csr_sha1"));
	QVERIFY(req);
	IssuanceSpec spec = profileSpec(golden("opcua-server.rsa-2048"), req, ca);
	spec.csrPolicy.registeredUri = "urn:SIMATIC:plc12";
	spec.hashAlgo = digest(NID_sha1);
	expectRejected(spec, "signature_hash_not_allowed");
}

XCA_SERVICE_TEST_MAIN(test_service_csr_acceptance)
#include "test_service_csr_acceptance.moc"
