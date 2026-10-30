/* vi: set sw=4 ts=4:
 *
 * Signing with the key types without a digest (BTD-164): Ed25519, Ed448,
 * ML-DSA-44/65/87 and the twelve SLH-DSA parameter sets sign a CSR, a
 * self-signed CA certificate, an end-entity certificate of that CA and a
 * CRL of it. Each object is checked with the openssl program, its
 * AlgorithmIdentifier carries the OID of RFC 8410, RFC 9881 or RFC 9909
 * without parameters, the SHA-256 of the "template" is ignored and the
 * audit entries name the effective signature algorithm.
 */

#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QTemporaryDir>

#include <openssl/pem.h>
#include <openssl/x509.h>

#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/db_crl.h"
#include "lib/db_key.h"
#include "lib/db_x509.h"
#include "lib/db_x509req.h"
#include "lib/exception.h"
#include "lib/issuance.h"
#include "lib/json_report.h"
#include "lib/pki_crl.h"
#include "lib/pki_evp.h"
#include "lib/pki_x509.h"
#include "lib/pki_x509req.h"
#include "lib/request.h"

#include "ServiceTestCase.h"

/* Key type, the OID of its signature algorithm (RFC 8410, RFC 9881,
 * RFC 9909) and the name XCA records for it */
static const struct {
	const char *type, *oid, *name;
} signers[] = {
	{ "ED25519", "1.3.101.112", "ED25519" },
	{ "ED448", "1.3.101.113", "ED448" },
	{ "ML-DSA-44", "2.16.840.1.101.3.4.3.17", "ML-DSA-44" },
	{ "ML-DSA-65", "2.16.840.1.101.3.4.3.18", "ML-DSA-65" },
	{ "ML-DSA-87", "2.16.840.1.101.3.4.3.19", "ML-DSA-87" },
	{ "SLH-DSA-SHA2-128s", "2.16.840.1.101.3.4.3.20", "SLH-DSA-SHA2-128s" },
	{ "SLH-DSA-SHA2-128f", "2.16.840.1.101.3.4.3.21", "SLH-DSA-SHA2-128f" },
	{ "SLH-DSA-SHA2-192s", "2.16.840.1.101.3.4.3.22", "SLH-DSA-SHA2-192s" },
	{ "SLH-DSA-SHA2-192f", "2.16.840.1.101.3.4.3.23", "SLH-DSA-SHA2-192f" },
	{ "SLH-DSA-SHA2-256s", "2.16.840.1.101.3.4.3.24", "SLH-DSA-SHA2-256s" },
	{ "SLH-DSA-SHA2-256f", "2.16.840.1.101.3.4.3.25", "SLH-DSA-SHA2-256f" },
	{ "SLH-DSA-SHAKE-128s", "2.16.840.1.101.3.4.3.26", "SLH-DSA-SHAKE-128s" },
	{ "SLH-DSA-SHAKE-128f", "2.16.840.1.101.3.4.3.27", "SLH-DSA-SHAKE-128f" },
	{ "SLH-DSA-SHAKE-192s", "2.16.840.1.101.3.4.3.28", "SLH-DSA-SHAKE-192s" },
	{ "SLH-DSA-SHAKE-192f", "2.16.840.1.101.3.4.3.29", "SLH-DSA-SHAKE-192f" },
	{ "SLH-DSA-SHAKE-256s", "2.16.840.1.101.3.4.3.30", "SLH-DSA-SHAKE-256s" },
	{ "SLH-DSA-SHAKE-256f", "2.16.840.1.101.3.4.3.31", "SLH-DSA-SHAKE-256f" },
};

class test_service_pqc_signing : public ServiceTestCase
{
	Q_OBJECT

	ServiceContext ctx{ ServiceContext::cli, "os:service-test" };
	QTemporaryDir dir{};

	QString file(const QString &name) const
	{
		return dir.filePath(name);
	}
	static x509name dn(const QString &cn)
	{
		x509name n;
		n.addEntryByNid(NID_organizationName, "BxC Lab");
		n.addEntryByNid(NID_commonName, cn);
		return n;
	}
	QString openssl(const QStringList &args, int *rc);
	static bool writePem(const QString &name,
			int (*write)(BIO *, const void *), const void *obj);
	/* OID and parameter type of an AlgorithmIdentifier */
	static QString oid(const X509_ALGOR *alg, int *ptype);
	static QList<AuditEntry> entries(const QString &action)
	{
		QList<AuditEntry> list;
		for (const AuditEntry &e : AuditLog::entries()) {
			if (e.action == action)
				list << e;
		}
		return list;
	}

  private slots:
	void signAll_data();
	void signAll();
	void classicTypesKeepTheirDigest();
};

QString test_service_pqc_signing::openssl(const QStringList &args, int *rc)
{
	*rc = -1;
#ifdef OPENSSL_PROGRAM
	QProcess p;
	p.setProcessChannelMode(QProcess::MergedChannels);
	p.start(OPENSSL_PROGRAM, args);
	if (p.waitForFinished(120000))
		*rc = p.exitCode();
	return QString::fromUtf8(p.readAll());
#else
	(void)args;
	return QString();
#endif
}

bool test_service_pqc_signing::writePem(const QString &name,
			int (*write)(BIO *, const void *), const void *obj)
{
	BIO *b = BIO_new_file(QFile::encodeName(name).constData(), "w");
	bool ok = b && write(b, obj);
	BIO_free(b);
	return ok;
}

QString test_service_pqc_signing::oid(const X509_ALGOR *alg, int *ptype)
{
	const ASN1_OBJECT *obj = nullptr;
	const void *pval = nullptr;
	X509_ALGOR_get0(&obj, ptype, &pval, alg);
	char buf[80];
	OBJ_obj2txt(buf, sizeof buf, obj, 1);
	return QString(buf);
}

static int writeReq(BIO *b, const void *o)
{
	return PEM_write_bio_X509_REQ(b, (X509_REQ *)o);
}
static int writeCert(BIO *b, const void *o)
{
	return PEM_write_bio_X509(b, (X509 *)o);
}
static int writeCrl(BIO *b, const void *o)
{
	return PEM_write_bio_X509_CRL(b, (X509_CRL *)o);
}

void test_service_pqc_signing::signAll_data()
{
	QTest::addColumn<QString>("type");
	QTest::addColumn<QString>("oid");
	QTest::addColumn<QString>("name");

	for (const auto &s : signers)
		QTest::newRow(s.type) << s.type << s.oid << s.name;
}

/* CSR, self-signed CA, end-entity certificate and CRL with a signer key
 * of the type; every spec asks for SHA-256, as a template would */
void test_service_pqc_signing::signAll()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	QFETCH(QString, type);
	QFETCH(QString, oid);
	QFETCH(QString, name);
	int rc, ptype;

	pki_key *caKey = Database.model<db_key>()->newKey(ctx, keyjob(type),
							"signer");
	QVERIFY(caKey);
	QCOMPARE(caKey->possibleHashNids(), QList<int>({ NID_undef }));

	/* CSR */
	RequestSpec rs;
	rs.name = "request";
	rs.subject = dn("BTD-164 request");
	rs.key = caKey;
	rs.hashAlgo = digest(NID_sha256);
	pki_x509req *req = Database.model<db_x509req>()->newRequest(ctx, rs);
	QVERIFY(req);
	const X509_ALGOR *alg = nullptr;
	X509_REQ_get0_signature(req->getReq(), nullptr, &alg);
	QCOMPARE(this->oid(alg, &ptype), oid);
	QCOMPARE(ptype, V_ASN1_UNDEF);
	QVERIFY(writePem(file("req.pem"), writeReq, req->getReq()));
	QString out = openssl({ "req", "-in", file("req.pem"), "-verify",
				"-noout" }, &rc);
	QVERIFY2(rc == 0 && out.contains("verify OK"), CCHAR(out));

	/* Self-signed CA */
	IssuanceSpec ca;
	ca.name = "ca";
	ca.subject = dn("BTD-164 CA");
	ca.key = caKey;
	ca.notBefore = a1time();
	ca.notAfter = a1time(QDateTime::currentDateTimeUtc().addDays(30));
	ca.hashAlgo = digest(NID_sha256);
	ca.extensions.basicCA = ExtensionSpec::bc_ca;
	ca.extensions.basicCritical = true;
	ca.extensions.subjectKeyId = true;
	ca.extensions.keyUsage << "keyCertSign" << "cRLSign";
	ca.extensions.keyUsageCritical = true;
	pki_x509 *caCert = Database.model<db_x509>()->newCert(ctx, ca);
	QVERIFY(caCert);
	X509_get0_signature(nullptr, &alg, caCert->getCert());
	QCOMPARE(this->oid(alg, &ptype), oid);
	QCOMPARE(ptype, V_ASN1_UNDEF);
	QCOMPARE(this->oid(X509_get0_tbs_sigalg(caCert->getCert()), &ptype),
			oid);
	QCOMPARE(ptype, V_ASN1_UNDEF);
	QVERIFY(writePem(file("ca.pem"), writeCert, caCert->getCert()));
	out = openssl({ "verify", "-CAfile", file("ca.pem"), file("ca.pem") },
			&rc);
	QVERIFY2(rc == 0 && out.contains("OK"), CCHAR(out));
	/* the CLI result: the JSON document names the algorithm (BTD-39) */
	QJsonObject json = JsonReport::certificate(caCert);
	QVERIFY2(json["signature_algorithm"].toObject()["oid"].toString() == oid,
		CCHAR(QString(QJsonDocument(json).toJson())));

	/* End entity issued by the CA, with an EC key */
	pki_key *eeKey = Database.model<db_key>()->newKey(ctx,
				keyjob("EC:prime256v1"), "ee-key");
	QVERIFY(eeKey);
	IssuanceSpec ee;
	ee.name = "ee";
	ee.subject = dn("BTD-164 end entity");
	ee.key = eeKey;
	ee.signer = caCert;
	ee.notBefore = a1time();
	ee.notAfter = a1time(QDateTime::currentDateTimeUtc().addDays(10));
	ee.hashAlgo = digest(NID_sha256);
	ee.extensions.basicCA = ExtensionSpec::bc_not_ca;
	ee.extensions.authorityKeyId = true;
	ee.extensions.keyUsage << "digitalSignature";
	pki_x509 *eeCert = Database.model<db_x509>()->newCert(ctx, ee);
	QVERIFY(eeCert);
	X509_get0_signature(nullptr, &alg, eeCert->getCert());
	QCOMPARE(this->oid(alg, &ptype), oid);
	QCOMPARE(ptype, V_ASN1_UNDEF);
	QVERIFY(writePem(file("ee.pem"), writeCert, eeCert->getCert()));
	out = openssl({ "verify", "-CAfile", file("ca.pem"), file("ee.pem") },
			&rc);
	QVERIFY2(rc == 0 && out.contains("OK"), CCHAR(out));

	/* CRL; the job asks for SHA-256 like a CA property would */
	crljob job(caCert);
	job.hashAlgo = digest(NID_sha256);
	pki_crl *crl = Database.model<db_crl>()->newCrl(ctx, job);
	QVERIFY(crl);
	X509_CRL_get0_signature(crl->getCrl(), nullptr, &alg);
	QCOMPARE(this->oid(alg, &ptype), oid);
	QCOMPARE(ptype, V_ASN1_UNDEF);
	QVERIFY(writePem(file("crl.pem"), writeCrl, crl->getCrl()));
	out = openssl({ "crl", "-in", file("crl.pem"), "-CAfile",
			file("ca.pem"), "-noout" }, &rc);
	QVERIFY2(rc == 0 && out.contains("verify OK"), CCHAR(out));

	/* The audit: the requested digest and the effective algorithm */
	QList<AuditEntry> e = entries("request.create") +
		entries("certificate.issue") + entries("crl.generate");
	QCOMPARE(e.size(), 4);
	for (const AuditEntry &a : e) {
		QCOMPARE(a.result, QString("success"));
		QCOMPARE(a.params.value("signature_algorithm").toString(), name);
		QCOMPARE(a.params.value("hash_algo").toString(), QString("SHA256"));
	}
	QVERIFY(AuditLog::verify().ok());
#endif
}

/* RSA and EC still sign with the digest they are given, and the audit
 * names the combined algorithm */
void test_service_pqc_signing::classicTypesKeepTheirDigest()
{
	for (const char *job : { "RSA:2048", "EC:prime256v1" }) {
		pki_key *key = Database.model<db_key>()->newKey(ctx,
					keyjob(job), job);
		QVERIFY(key);
		IssuanceSpec ca;
		ca.name = QString("ca ") + job;
		ca.subject = dn(ca.name);
		ca.key = key;
		ca.notBefore = a1time();
		ca.notAfter = a1time(QDateTime::currentDateTimeUtc().addDays(30));
		ca.hashAlgo = digest(NID_sha384);
		ca.extensions.basicCA = ExtensionSpec::bc_ca;
		ca.extensions.keyUsage << "keyCertSign" << "cRLSign";
		pki_x509 *cert = Database.model<db_x509>()->newCert(ctx, ca);
		QVERIFY(cert);
		int expected = QString(job).startsWith("RSA") ?
			NID_sha384WithRSAEncryption : NID_ecdsa_with_SHA384;
		QCOMPARE(X509_get_signature_nid(cert->getCert()), expected);
		QCOMPARE(entries("certificate.issue").last().params.value(
			"signature_algorithm").toString(),
			QString(OBJ_nid2ln(expected)));
	}
}

XCA_SERVICE_TEST_MAIN(test_service_pqc_signing)
#include "test_service_pqc_signing.moc"
