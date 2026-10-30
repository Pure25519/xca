/* vi: set sw=4 ts=4:
 *
 * A certificate or request is complete, or it is not stored (BTD-200,
 * group 9 of the BTD-95 review list). The setters of serial, validity,
 * subject, issuer and public key were not checked: pki_openssl_error()
 * only prints, so a failed setter left a certificate without the field
 * that was signed, stored and audited as success. The test hook
 * certBuild::fail() (lib/pki_x509super.h) skips one setter as if it had
 * failed.
 */

#include <QSqlQuery>

#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/db_key.h"
#include "lib/db_x509.h"
#include "lib/db_x509req.h"
#include "lib/exception.h"
#include "lib/issuance.h"
#include "lib/pki_x509.h"
#include "lib/pki_x509req.h"
#include "lib/request.h"

#include "ServiceTestCase.h"

class test_service_cert_build : public ServiceTestCase
{
	Q_OBJECT

	ServiceContext ctx{ ServiceContext::cli, "os:service-test" };

	static int rows(const QString &table)
	{
		QSqlQuery q;
		if (!q.exec(QString("SELECT COUNT(*) FROM %1").arg(table)) ||
		    !q.next())
			return -1;
		return q.value(0).toInt();
	}
	pki_key *key(const QString &name)
	{
		return Database.model<db_key>()->newKey(ctx,
			keyjob("EC:prime256v1"), name);
	}
	/* The step fails, nothing of the kind is stored, and the one new
	 * audit entry is a failure with certificate_build_failed */
	void refused(const QString &step, const QString &table,
			const QString &action, std::function<void()> build);

  private slots:
	void cleanup();
	void certStepFails_data();
	void certStepFails();
	void requestStepFails_data();
	void requestStepFails();
	void withoutInjection();
};

void test_service_cert_build::cleanup()
{
	certBuild::injected.clear();
	ServiceTestCase::cleanup();
}

void test_service_cert_build::refused(const QString &step,
		const QString &table, const QString &action,
		std::function<void()> build)
{
	int stored = rows(table);
	int audit = AuditLog::entries().size();
	certBuild::injected = step;
	try {
		build();
		certBuild::injected.clear();
		QFAIL(qPrintable(QString("stored and audited as success "
			"without %1").arg(step)));
	} catch (serviceError &err) {
		certBuild::injected.clear();
		QCOMPARE(err.code, QString("certificate_build_failed"));
		QVERIFY2(err.getString().contains(step),
			qPrintable(err.getString()));
	}
	QCOMPARE(rows(table), stored);
	QList<AuditEntry> entries = AuditLog::entries();
	QCOMPARE(entries.size(), audit + 1);
	QCOMPARE(entries.last().action, action);
	QCOMPARE(entries.last().result, QString("failure"));
	QCOMPARE(entries.last().errorCode, QString("certificate_build_failed"));
}

void test_service_cert_build::certStepFails_data()
{
	QTest::addColumn<QString>("step");
	for (const char *s : { "serial", "not_before", "not_after",
			"subject", "issuer", "public_key" })
		QTest::newRow(s) << QString(s);
}

void test_service_cert_build::certStepFails()
{
	QFETCH(QString, step);
	IssuanceSpec spec;
	spec.name = "BTD-200 " + step;
	spec.subject.addEntryByNid(NID_commonName, spec.name);
	spec.key = key(spec.name + " key");
	QVERIFY(spec.key);
	spec.notBefore = a1time(QDateTime::currentDateTimeUtc().addDays(-1));
	spec.notAfter = a1time(QDateTime::currentDateTimeUtc().addDays(30));
	spec.hashAlgo = digest(NID_sha256);
	refused(step, "certs", "certificate.issue", [&]() {
		Database.model<db_x509>()->newCert(ctx, spec);
	});
}

void test_service_cert_build::requestStepFails_data()
{
	QTest::addColumn<QString>("step");
	for (const char *s : { "request_version", "request_public_key",
			"request_subject" })
		QTest::newRow(s) << QString(s);
}

void test_service_cert_build::requestStepFails()
{
	QFETCH(QString, step);
	RequestSpec spec;
	spec.name = "BTD-200 " + step;
	spec.subject.addEntryByNid(NID_commonName, spec.name);
	spec.key = key(spec.name + " key");
	QVERIFY(spec.key);
	spec.hashAlgo = digest(NID_sha256);
	refused(step, "requests", "request.create", [&]() {
		Database.model<db_x509req>()->newRequest(ctx, spec);
	});
}

/* Without an injected step the same specs are built and stored */
void test_service_cert_build::withoutInjection()
{
	IssuanceSpec spec;
	spec.name = "BTD-200 complete";
	spec.subject.addEntryByNid(NID_commonName, spec.name);
	spec.key = key(spec.name + " key");
	spec.notBefore = a1time(QDateTime::currentDateTimeUtc().addDays(-1));
	spec.notAfter = a1time(QDateTime::currentDateTimeUtc().addDays(30));
	spec.hashAlgo = digest(NID_sha256);
	pki_x509 *cert = Database.model<db_x509>()->newCert(ctx, spec);
	QVERIFY(cert);
	QCOMPARE(cert->getSubject().getEntryByNid(NID_commonName),
		spec.name);
	QCOMPARE(cert->getIssuerName().getEntryByNid(NID_commonName), spec.name);

	RequestSpec req;
	req.name = "BTD-200 request";
	req.subject.addEntryByNid(NID_commonName, req.name);
	req.key = key(req.name + " key");
	req.hashAlgo = digest(NID_sha256);
	pki_x509req *r = Database.model<db_x509req>()->newRequest(ctx, req);
	QVERIFY(r);
	QCOMPARE(r->getSubject().getEntryByNid(NID_commonName), req.name);
}

XCA_SERVICE_TEST_MAIN(test_service_cert_build)
#include "test_service_cert_build.moc"
