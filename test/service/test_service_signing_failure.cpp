/* vi: set sw=4 ts=4:
 *
 * A failed signature is an error, never a stored object (BTD-171): before
 * the fix the certificate was stored with an empty DER and audited as
 * success. Each service call must throw signing_failed, write a failure
 * entry, store no row and advance no CRL number. ServiceTestCase::cleanup()
 * checks for every test that no stored object has an empty DER.
 *
 * The trigger (BTD-181) is an RSA-512 key with SHA-512: the PKCS#1 v1.5
 * DigestInfo of SHA-512 is 83 bytes, an RSA-512 block holds 53, so
 * X509_sign, X509_CRL_sign and X509_REQ_sign fail whatever the digest
 * rules for digest-less keys say (BTD-164), and SHA-512 is no insecure
 * digest the checks of BTD-55 would refuse before. SHA-256 (51 bytes)
 * still fits, so the same key signs with it.
 */

#include <QSqlQuery>

#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/db_crl.h"
#include "lib/db_key.h"
#include "lib/db_x509.h"
#include "lib/db_x509req.h"
#include "lib/exception.h"
#include "lib/issuance.h"
#include "lib/pki_crl.h"
#include "lib/pki_x509.h"
#include "lib/pki_x509req.h"
#include "lib/request.h"
#include "lib/sql.h"

#include "ServiceTestCase.h"

class test_service_signing_failure : public ServiceTestCase
{
	Q_OBJECT

	ServiceContext ctx{ ServiceContext::cli, "os:service-test" };

	/* XCA asks before it makes a key that small (key.size) */
	pki_key *rsa512(const QString &name)
	{
		warning->expectQuestion(true);
		return Database.model<db_key>()->newKey(keyjob("RSA:512"), name);
	}
	static x509name dn(const QString &cn)
	{
		x509name n;
		n.addEntryByNid(NID_commonName, cn);
		return n;
	}
	static int rows(const QString &table);
	static IssuanceSpec rootSpec(pki_key *key, int md);
	pki_x509 *smallRoot();
	void expectFailure(const QString &action, int auditBefore);

  private slots:
	void certificate();
	void selfSigned();
	void crl();
	void request();
};

int test_service_signing_failure::rows(const QString &table)
{
	QSqlQuery q;
	if (!q.exec(QString("SELECT COUNT(*) FROM %1").arg(table)) || !q.next())
		return -1;
	return q.value(0).toInt();
}

IssuanceSpec test_service_signing_failure::rootSpec(pki_key *key, int md)
{
	IssuanceSpec spec;
	spec.name = "RSA-512 Root";
	spec.subject = dn(spec.name);
	spec.key = key;
	spec.notBefore = a1time();
	spec.notAfter = a1time(QDateTime::currentDateTimeUtc().addDays(365));
	spec.hashAlgo = digest(md);
	spec.extensions.basicCA = ExtensionSpec::bc_ca;
	spec.extensions.basicCritical = true;
	spec.extensions.subjectKeyId = true;
	spec.extensions.keyUsage << "keyCertSign" << "cRLSign";
	return spec;
}

/* A self-signed RSA-512 root, signed with SHA-256 (that fits) */
pki_x509 *test_service_signing_failure::smallRoot()
{
	pki_key *key = rsa512("small-root");
	if (!key) {
		qWarning() << "OpenSSL refused an RSA-512 key";
		return nullptr;
	}
	try {
		return Database.model<db_x509>()->newCert(ctx,
				rootSpec(key, NID_sha256));
	} catch (errorEx &err) {
		qWarning() << "root failed:" << err.getString();
		return nullptr;
	}
}

void test_service_signing_failure::expectFailure(const QString &action,
				int auditBefore)
{
	QList<AuditEntry> entries = AuditLog::entries();
	QCOMPARE(entries.size(), auditBefore + 1);
	QCOMPARE(entries.last().action, action);
	QCOMPARE(entries.last().result, QString("failure"));
	QCOMPARE(entries.last().errorCode, QString("signing_failed"));
	QVERIFY(AuditLog::verify().ok());
}

/* The end entity under the RSA-512 CA with SHA-512 */
void test_service_signing_failure::certificate()
{
	pki_x509 *root = smallRoot();
	QVERIFY(root);
	/* the keys and the root are stored; only the leaf must not be */
	pki_key *leafKey = Database.model<db_key>()->newKey(
				keyjob("EC:prime256v1"), "leaf");
	int certRows = rows("certs");
	int stored = Store.getAll<pki_x509>().size();
	int before = AuditLog::entries().size();

	IssuanceSpec spec;
	spec.name = "leaf";
	spec.subject = dn("leaf.example");
	spec.key = leafKey;
	spec.signer = root;
	spec.notBefore = a1time();
	spec.notAfter = a1time(QDateTime::currentDateTimeUtc().addDays(30));
	spec.hashAlgo = digest(NID_sha512);
	spec.extensions.basicCA = ExtensionSpec::bc_not_ca;
	QString code;
	try {
		pki_x509 *c = Database.model<db_x509>()->newCert(ctx, spec);
		code = QString("<issued, DER %1 bytes>").arg(c->i2d().size());
	} catch (serviceError &err) {
		code = err.code;
		QVERIFY2(!err.getString().isEmpty(), "no OpenSSL reason");
	}
	QCOMPARE(code, QString("signing_failed"));
	expectFailure("certificate.issue", before);
	QCOMPARE(rows("certs"), certRows);
	QCOMPARE(Store.getAll<pki_x509>().size(), stored);
}

/* A self-signed certificate whose own key cannot sign with SHA-512 */
void test_service_signing_failure::selfSigned()
{
	pki_key *key = rsa512("small-self");
	QVERIFY(key);
	int certRows = rows("certs");
	int stored = Store.getAll<pki_x509>().size();
	int before = AuditLog::entries().size();
	QString code;
	try {
		Database.model<db_x509>()->newCert(ctx, rootSpec(key, NID_sha512));
		code = "<issued>";
	} catch (serviceError &err) {
		code = err.code;
	}
	QCOMPARE(code, QString("signing_failed"));
	expectFailure("certificate.issue", before);
	QCOMPARE(rows("certs"), certRows);
	QCOMPARE(Store.getAll<pki_x509>().size(), stored);
}

/* X509_CRL_sign fails; no CRL row, CRL number unchanged */
void test_service_signing_failure::crl()
{
	pki_x509 *root = smallRoot();
	QVERIFY(root);
	a1int number = root->getCrlNumber();
	int crlRows = rows("crls");
	int before = AuditLog::entries().size();

	crljob job(root);
	job.hashAlgo = digest(NID_sha512);
	QString code;
	try {
		Database.model<db_crl>()->newCrl(ctx, job);
		code = "<generated>";
	} catch (serviceError &err) {
		code = err.code;
	}
	QCOMPARE(code, QString("signing_failed"));
	expectFailure(AuditLog::actionCrlGenerate, before);
	QCOMPARE(rows("crls"), crlRows);
	QCOMPARE(root->getCrlNumber().toDec(), number.toDec());
	QSqlQuery q;
	QVERIFY(q.exec(QString("SELECT crlNo FROM authority WHERE item=%1")
			.arg(root->getSqlItemId().toLongLong())) && q.next());
	QCOMPARE(q.value(0).toString(), number.toDec());

	/* with a digest that fits the same CRL works */
	job.hashAlgo = digest(NID_sha256);
	QVERIFY(Database.model<db_crl>()->newCrl(ctx, job));
}

/* X509_REQ_sign fails; no request row */
void test_service_signing_failure::request()
{
	RequestSpec spec;
	spec.name = "small-request";
	spec.subject = dn("device.example");
	spec.key = rsa512("small-device");
	QVERIFY(spec.key);
	spec.hashAlgo = digest(NID_sha512);
	int reqRows = rows("requests");
	int before = AuditLog::entries().size();
	QString code;
	try {
		Database.model<db_x509req>()->newRequest(ctx, spec);
		code = "<created>";
	} catch (serviceError &err) {
		code = err.code;
	}
	QCOMPARE(code, QString("signing_failed"));
	expectFailure("request.create", before);
	QCOMPARE(rows("requests"), reqRows);
}

XCA_SERVICE_TEST_MAIN(test_service_signing_failure)
#include "test_service_signing_failure.moc"
