/* vi: set sw=4 ts=4:
 *
 * The content of a CRL matches the database, or the CRL is not signed
 * (BTD-198, group 4 of the BTD-95 review list). The CRL build did not
 * check its OpenSSL calls: a revoked entry, a reason, the CRL number or
 * the AKI could be missing from a CRL that was signed and audited as
 * success. The test hook crlBuild::fail() (lib/x509rev.h) skips one step
 * as if its OpenSSL call had failed.
 */

#include <QSet>
#include <QSqlQuery>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/db_crl.h"
#include "lib/db_key.h"
#include "lib/db_x509.h"
#include "lib/exception.h"
#include "lib/issuance.h"
#include "lib/pki_crl.h"
#include "lib/pki_x509.h"
#include "lib/x509rev.h"

#include "ServiceTestCase.h"

class test_service_crl_build : public ServiceTestCase
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
	pki_x509 *issue(const QString &cn, pki_x509 *signer);
	pki_x509 *ca{};
	/* serial (hex) -> reason name of the revocations made */
	QMap<QString, QString> revoked{};
	QString invalidSerial{};
	/* A CA with a SAN (for the IAN) and count revoked end entities,
	 * reasons in turn, the first with an invalidity date */
	void setupCa(int count);

  private slots:
	void cleanup();
	void stepFails_data();
	void stepFails();
	void tenRevocations();
};

void test_service_crl_build::cleanup()
{
	crlBuild::injected.clear();
	revoked.clear();
	ServiceTestCase::cleanup();
}

pki_x509 *test_service_crl_build::issue(const QString &cn, pki_x509 *signer)
{
	IssuanceSpec spec;
	spec.name = cn;
	spec.subject.addEntryByNid(NID_commonName, cn);
	spec.key = key(cn + " key");
	spec.signer = signer;
	spec.notBefore = a1time(QDateTime::currentDateTimeUtc().addDays(-1));
	spec.notAfter = a1time(QDateTime::currentDateTimeUtc().addDays(
		signer ? 30 : 365));
	spec.hashAlgo = digest(NID_sha256);
	spec.extensions.subjectKeyId = true;
	if (signer) {
		spec.extensions.basicCA = ExtensionSpec::bc_not_ca;
		spec.extensions.authorityKeyId = true;
		spec.extensions.keyUsage << "digitalSignature";
	} else {
		spec.extensions.basicCA = ExtensionSpec::bc_ca;
		spec.extensions.basicCritical = true;
		spec.extensions.keyUsage << "keyCertSign" << "cRLSign";
		spec.extensions.subjectAltName = "DNS:ca.btd198.example";
	}
	return Database.model<db_x509>()->newCert(ctx, spec);
}

void test_service_crl_build::setupCa(int count)
{
	static const QStringList reasons { "Key Compromise", "Superseded",
		"Cessation Of Operation", "Affiliation Changed",
		"Privilege Withdrawn" };
	ca = issue("BTD-198 CA", nullptr);
	QVERIFY(ca);
	for (int i = 0; i < count; i++) {
		pki_x509 *ee = issue(QString("BTD-198 EE %1").arg(i), ca);
		QVERIFY(ee);
		x509rev rev;
		rev.setReason(reasons[i % reasons.size()]);
		/* x509rev() sets the invalidity date to now: only the first
		 * revocation has one here */
		a1time inval(QDateTime::currentDateTimeUtc().addDays(-2));
		if (i == 0)
			invalidSerial = ee->getSerial().toHex();
		else
			inval.setUndefined();
		rev.setInvalDate(inval);
		Database.model<db_x509>()->revoke(ctx, ee, rev);
		revoked[ee->getSerial().toHex()] = reasons[i % reasons.size()];
	}
}

void test_service_crl_build::stepFails_data()
{
	QTest::addColumn<QString>("step");
	for (const char *s : { "version", "issuer", "serial",
			"revocation_date", "invalidity_date", "reason",
			"revoked", "aki", "ian", "crl_number", "last_update",
			"next_update", "drop_entry" })
		QTest::newRow(s) << QString(s);
}

/* Each failed step refuses the CRL before signing: no CRL, the CRL
 * number unchanged, a failure entry with crl_build_failed */
void test_service_crl_build::stepFails()
{
	QFETCH(QString, step);
	setupCa(2);
	QVERIFY(ca);
	int crls = rows("crls");
	a1int number = ca->getCrlNumber();
	int audit = AuditLog::entries().size();

	crlBuild::injected = step;
	try {
		pki_crl *crl = Database.model<db_crl>()->newCrl(ctx,
						crljob(ca));
		crlBuild::injected.clear();
		QFAIL(qPrintable(QString("signed and audited as success with "
			"%1 entries").arg(crl ? crl->numRev() : -1)));
	} catch (serviceError &err) {
		crlBuild::injected.clear();
		QCOMPARE(err.code, QString("crl_build_failed"));
	}
	QCOMPARE(rows("crls"), crls);
	QCOMPARE(ca->getCrlNumber().toHex(), number.toHex());
	QList<AuditEntry> entries = AuditLog::entries();
	QCOMPARE(entries.size(), audit + 1);
	QCOMPARE(entries.last().action, QString("crl.generate"));
	QCOMPARE(entries.last().result, QString("failure"));
	QCOMPARE(entries.last().errorCode, QString("crl_build_failed"));
}

/* A CRL of ten revocations lists exactly the database's serials,
 * reasons and the invalidity date, with CRL number and AKI */
void test_service_crl_build::tenRevocations()
{
	setupCa(10);
	QVERIFY(ca);
	crljob job(ca);
	pki_crl *crl = Database.model<db_crl>()->newCrl(ctx, job);
	QVERIFY(crl);
	const X509_CRL *c = crl->getCrl();
	const STACK_OF(X509_REVOKED) *list = X509_CRL_get_REVOKED(c);
	QCOMPARE(sk_X509_REVOKED_num(list), 10);
	QSet<QString> serials;
	int withInvalidity = 0;
	for (int i = 0; i < sk_X509_REVOKED_num(list); i++) {
		const X509_REVOKED *r = sk_X509_REVOKED_value(list, i);
		a1int sn(X509_REVOKED_get0_serialNumber(r));
		QString hex = sn.toHex();
		serials << hex;
		QVERIFY(revoked.contains(hex));
		int crit;
		ASN1_ENUMERATED *reason = (ASN1_ENUMERATED *)
			X509_REVOKED_get_ext_d2i(r, NID_crl_reason, &crit,
						nullptr);
		QVERIFY(reason);
		x509rev expected;
		expected.setReason(revoked[hex]);
		QCOMPARE(ASN1_ENUMERATED_get(reason),
			(long)expected.getReasonBit());
		ASN1_ENUMERATED_free(reason);
		ASN1_GENERALIZEDTIME *inval = (ASN1_GENERALIZEDTIME *)
			X509_REVOKED_get_ext_d2i(r, NID_invalidity_date,
						&crit, nullptr);
		if (inval) {
			withInvalidity++;
			QCOMPARE(hex, invalidSerial);
			ASN1_GENERALIZEDTIME_free(inval);
		}
	}
	QCOMPARE(serials, QSet<QString>(revoked.keyBegin(),
					revoked.keyEnd()));
	QCOMPARE(withInvalidity, 1);
	QCOMPARE(crl->getCrlNumber().toHex(), job.crlNumber.toHex());
	QVERIFY(X509_CRL_get_ext_by_NID(c, NID_authority_key_identifier,
					-1) >= 0);
	QVERIFY(X509_CRL_get_ext_by_NID(c, NID_issuer_alt_name, -1) >= 0);
}

XCA_SERVICE_TEST_MAIN(test_service_crl_build)
#include "test_service_crl_build.moc"
