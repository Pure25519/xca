/* vi: set sw=4 ts=4:
 *
 * A failed signature is an error, never a stored object (BTD-171): an
 * Ed25519 key takes no digest, so signing with SHA-256 fails in
 * X509_sign, X509_CRL_sign and X509_REQ_sign. Before the fix the
 * certificate was stored with an empty DER and audited as success.
 * Each service call must throw signing_failed, write a failure entry,
 * store no row and advance no CRL number. ServiceTestCase::cleanup()
 * checks for every test that no stored object has an empty DER.
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

	static pki_key *ed25519(const QString &name)
	{
		return Database.model<db_key>()->newKey(keyjob("ED25519"), name);
	}
	static x509name dn(const QString &cn)
	{
		x509name n;
		n.addEntryByNid(NID_commonName, cn);
		return n;
	}
	static int rows(const QString &table);
	pki_x509 *edRoot();
	void expectFailure(const QString &action, int auditBefore);

  private slots:
	void certificate();
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

/* A self-signed Ed25519 root, signed without a digest (that works) */
pki_x509 *test_service_signing_failure::edRoot()
{
	IssuanceSpec spec;
	spec.name = "Ed25519 Root";
	spec.subject = dn(spec.name);
	spec.key = ed25519("ed-root");
	spec.notBefore = a1time();
	spec.notAfter = a1time(QDateTime::currentDateTimeUtc().addDays(365));
	spec.hashAlgo = digest(NID_undef);
	spec.extensions.basicCA = ExtensionSpec::bc_ca;
	spec.extensions.basicCritical = true;
	spec.extensions.subjectKeyId = true;
	spec.extensions.keyUsage << "keyCertSign" << "cRLSign";
	try {
		return Database.model<db_x509>()->newCert(ctx, spec);
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

/* AC 1 and 2: the end entity under an Ed25519 CA with SHA-256 */
void test_service_signing_failure::certificate()
{
	pki_x509 *root = edRoot();
	QVERIFY(root);
	/* the key and the root are stored; only the leaf must not be */
	int certRows = rows("certs");
	int stored = Store.getAll<pki_x509>().size();

	IssuanceSpec spec;
	spec.name = "leaf";
	spec.subject = dn("leaf.example");
	spec.key = Database.model<db_key>()->newKey(keyjob("EC:prime256v1"),
				"leaf");
	int before = AuditLog::entries().size();
	spec.signer = root;
	spec.notBefore = a1time();
	spec.notAfter = a1time(QDateTime::currentDateTimeUtc().addDays(30));
	spec.hashAlgo = digest(NID_sha256);
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

/* AC 3: X509_CRL_sign fails; no CRL row, CRL number unchanged */
void test_service_signing_failure::crl()
{
	pki_x509 *root = edRoot();
	QVERIFY(root);
	a1int number = root->getCrlNumber();
	int crlRows = rows("crls");
	int before = AuditLog::entries().size();

	crljob job(root);
	job.hashAlgo = digest(NID_sha256);
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

	/* without the digest the same CRL works */
	job.hashAlgo = digest(NID_undef);
	QVERIFY(Database.model<db_crl>()->newCrl(ctx, job));
}

/* AC 3: X509_REQ_sign fails; no request row */
void test_service_signing_failure::request()
{
	RequestSpec spec;
	spec.name = "ed-request";
	spec.subject = dn("device.example");
	spec.key = ed25519("ed-device");
	spec.hashAlgo = digest(NID_sha256);
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
