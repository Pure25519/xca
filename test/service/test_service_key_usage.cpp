/* vi: set sw=4 ts=4:
 *
 * Key usage by the type of the subject key, for every issuance (BTD-195;
 * RFC 5480 3, RFC 8410 5, RFC 9881): EC keys never encipher, EdDSA and
 * the post-quantum signature keys only sign, RSA never agrees on keys. A
 * forbidden bit is a typed error naming bit and key type; no row, no
 * serial, one failure entry.
 */

#include <QSqlQuery>

#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/db_key.h"
#include "lib/db_x509.h"
#include "lib/exception.h"
#include "lib/issuance.h"
#include "lib/pki_x509.h"

#include "ServiceTestCase.h"

class test_service_key_usage : public ServiceTestCase
{
	Q_OBJECT

	ServiceContext ctx{ ServiceContext::cli, "os:service-test" };
	pki_x509 *ca();

  private slots:
	void bitsByKeyType_data();
	void bitsByKeyType();
};

pki_x509 *test_service_key_usage::ca()
{
	IssuanceSpec s;
	s.name = "KU CA";
	s.subject.addEntryByNid(NID_commonName, s.name);
	s.key = Database.model<db_key>()->newKey(keyjob("RSA:2048"), "KU CA key");
	s.notBefore = a1time(QDateTime::currentDateTimeUtc().addDays(-1));
	s.notAfter = a1time(QDateTime::currentDateTimeUtc().addYears(2));
	s.hashAlgo = digest(NID_sha256);
	s.extensions.basicCA = ExtensionSpec::bc_ca;
	s.extensions.keyUsage << "keyCertSign" << "cRLSign";
	return Database.model<db_x509>()->newCert(ctx, s);
}

void test_service_key_usage::bitsByKeyType_data()
{
	QTest::addColumn<QString>("job");
	QTest::addColumn<QString>("bit");
	QTest::addColumn<bool>("allowed");

	const QStringList bits { "digitalSignature", "nonRepudiation",
		"keyEncipherment", "dataEncipherment", "keyAgreement",
		"keyCertSign", "cRLSign", "encipherOnly", "decipherOnly" };
	const QList<std::pair<QString, QStringList>> families {
		{ "RSA:2048", { "digitalSignature", "nonRepudiation",
			"keyEncipherment", "dataEncipherment", "keyCertSign",
			"cRLSign" } },
		{ "EC:prime256v1", { "digitalSignature", "nonRepudiation",
			"keyAgreement", "keyCertSign", "cRLSign", "encipherOnly",
			"decipherOnly" } },
		{ "ED25519", { "digitalSignature", "nonRepudiation",
			"keyCertSign", "cRLSign" } },
		{ "ED448", { "digitalSignature", "nonRepudiation",
			"keyCertSign", "cRLSign" } },
		{ "ML-DSA-44", { "digitalSignature", "nonRepudiation",
			"keyCertSign", "cRLSign" } },
		{ "SLH-DSA-SHA2-128f", { "digitalSignature", "nonRepudiation",
			"keyCertSign", "cRLSign" } },
	};
	for (const auto &f : families)
		for (const QString &b : bits)
			QTest::newRow(CCHAR(f.first + " " + b)) << f.first << b
				<< f.second.contains(b);
}

void test_service_key_usage::bitsByKeyType()
{
	QFETCH(QString, job);
	QFETCH(QString, bit);
	QFETCH(bool, allowed);
	pki_x509 *issuer = ca();
	QVERIFY(issuer);
	IssuanceSpec s;
	s.name = "leaf " + job + " " + bit;
	s.subject.addEntryByNid(NID_commonName, "leaf");
	s.key = Database.model<db_key>()->newKey(keyjob(job), "leaf key");
	QVERIFY(s.key);
	s.signer = issuer;
	s.notBefore = a1time();
	s.notAfter = a1time(QDateTime::currentDateTimeUtc().addDays(30));
	s.hashAlgo = digest(NID_sha256);
	s.extensions.basicCA = bit == "keyCertSign" || bit == "cRLSign" ?
		ExtensionSpec::bc_ca : ExtensionSpec::bc_not_ca;
	s.extensions.keyUsage << bit;

	int stored = Store.getAll<pki_x509>().size();
	int audit = AuditLog::entries().size();
	QString code, message;
	try {
		Database.model<db_x509>()->newCert(ctx, s);
	} catch (serviceError &err) {
		code = err.code;
		message = err.getString();
	}
	if (allowed) {
		QCOMPARE(code, QString());
		return;
	}
	QCOMPARE(code, QString("key_usage_not_for_key_type"));
	QVERIFY2(message.contains(bit), CCHAR(message));
	QCOMPARE(Store.getAll<pki_x509>().size(), stored);
	QList<AuditEntry> e = AuditLog::entries();
	QCOMPARE(e.size(), audit + 1);
	QCOMPARE(e.last().result, QString("failure"));
	QCOMPARE(e.last().errorCode, code);
}

XCA_SERVICE_TEST_MAIN(test_service_key_usage)
#include "test_service_key_usage.moc"
