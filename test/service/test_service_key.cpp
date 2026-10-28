/* vi: set sw=4 ts=4:
 *
 * Sample service test: key generation through db_key::newKey(keyjob, name),
 * the GUI-free path behind "New key".
 */

#include <openssl/evp.h>

#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/db_key.h"
#include "lib/pki_evp.h"

#include "ServiceTestCase.h"

class test_service_key : public ServiceTestCase
{
	Q_OBJECT

	static pki_key *onlyKey()
	{
		QList<pki_key*> keys = Store.getAll<pki_key>();
		return keys.size() == 1 ? keys[0] : nullptr;
	}

  private slots:
	void newKey_data();
	void newKey();
	void newKeySmallRsaConfirmed();
	void newKeySmallRsaDeclined();
	void newKeySmallRsaHeadless_data();
	void newKeySmallRsaHeadless();
	void newKeySmallRsaHeadlessUnconfirmed_data();
	void newKeySmallRsaHeadlessUnconfirmed();
	void newKeyTooSmall();
};

void test_service_key::newKey_data()
{
	QTest::addColumn<QString>("job");
	QTest::addColumn<QString>("type");

	QTest::newRow("RSA") << "RSA:2048" << "RSA";
#ifndef OPENSSL_NO_EC
	QTest::newRow("EC") << "EC:prime256v1" << "EC";
#ifdef EVP_PKEY_ED25519
	QTest::newRow("ED25519") << "ED25519" << "ED25519";
#endif
#endif
}

void test_service_key::newKey()
{
	QFETCH(QString, job);
	QFETCH(QString, type);

	db_key *keys = Database.model<db_key>();
	QVERIFY(keys);
	QCOMPARE(Store.getAll<pki_key>().size(), 0);

	pki_key *key = keys->newKey(keyjob(job), "service-key");
	QVERIFY(key);
	QCOMPARE(key->getIntName(), QString("service-key"));
	QCOMPARE(key->getKeyType(), keytype::byName(type).type);
	QVERIFY(key->isPrivKey());
	QCOMPARE(Store.getAll<pki_key>().size(), 1);

	/* Persisted, and the private key decrypts with the database password */
	reopenDatabase();
	key = onlyKey();
	QVERIFY(key);
	QCOMPARE(key->getIntName(), QString("service-key"));
	QVERIFY(key->isPrivKey());
	EVP_PKEY *pkey = key->decryptKey();
	QVERIFY(pkey);
	QCOMPARE(EVP_PKEY_get_id(pkey), keytype::byName(type).type);
	EVP_PKEY_free(pkey);
}

void test_service_key::newKeySmallRsaConfirmed()
{
	/* Below 1024 bit, newKey() asks before generating */
	warning->expectQuestion(true);
	pki_key *key = Database.model<db_key>()->newKey(
				keyjob("RSA:768"), "small-key");
	QVERIFY(key);
	QCOMPARE(key->getIntName(), QString("small-key"));
	QCOMPARE(Store.getAll<pki_key>().size(), 1);
	/* The audit entry names the confirmed question (BTD-71) */
	AuditEntry e = AuditLog::entries().last();
	QCOMPARE(e.result, QString("success"));
	QCOMPARE(e.params["confirmed"].toString(), QString("key.size:dialog"));
}

void test_service_key::newKeySmallRsaDeclined()
{
	warning->expectQuestion(false);
	pki_key *key = Database.model<db_key>()->newKey(
				keyjob("RSA:768"), "small-key");
	QVERIFY(!key);
	QCOMPARE(Store.getAll<pki_key>().size(), 0);
}

/* xca --no-gui (BTD-71): the headless xcaWarningCore answers the
 * question only if --yes or --confirm key.size confirmed it */
void test_service_key::newKeySmallRsaHeadless_data()
{
	QTest::addColumn<bool>("all");
	QTest::addColumn<QStringList>("ids");
	QTest::addColumn<QString>("source");

	QTest::newRow("--yes") << true << QStringList() << "--yes";
	QTest::newRow("--confirm") << false << QStringList{ "item.delete",
				"key.size" } << "--confirm";
	QTest::newRow("both") << true << QStringList{ "key.size" }
				<< "--confirm";
}

void test_service_key::newKeySmallRsaHeadless()
{
	QFETCH(bool, all);
	QFETCH(QStringList, ids);
	QFETCH(QString, source);

	warning->delegateTo(new xcaWarningCore());
	xcaWarningCore::setConfirmations(all, ids);
	pki_key *key = Database.model<db_key>()->newKey(
				keyjob("RSA:768"), "small-key");
	QVERIFY(key);
	QCOMPARE(Store.getAll<pki_key>().size(), 1);
	AuditEntry e = AuditLog::entries().last();
	QCOMPARE(e.action, QString("key.generate"));
	QCOMPARE(e.result, QString("success"));
	QCOMPARE(e.params["confirmed"].toString(), "key.size:" + source);
}

void test_service_key::newKeySmallRsaHeadlessUnconfirmed_data()
{
	QTest::addColumn<QStringList>("ids");

	QTest::newRow("no answer") << QStringList();
	QTest::newRow("other question") << QStringList{ "item.delete" };
}

void test_service_key::newKeySmallRsaHeadlessUnconfirmed()
{
	QFETCH(QStringList, ids);

	warning->delegateTo(new xcaWarningCore());
	xcaWarningCore::setConfirmations(false, ids);
	int before = AuditLog::entries().size();
	try {
		Database.model<db_key>()->newKey(keyjob("RSA:768"),
					"small-key");
		QFAIL("the unconfirmed question did not stop newKey()");
	} catch (confirmationError &err) {
		QCOMPARE(err.question, QString("key.size"));
		QVERIFY(err.getString().contains("--confirm key.size"));
	}
	/* Nothing generated, one "denied" entry */
	QCOMPARE(Store.getAll<pki_key>().size(), 0);
	QList<AuditEntry> entries = AuditLog::entries();
	QCOMPARE(entries.size(), before + 1);
	AuditEntry e = entries.last();
	QCOMPARE(e.action, QString("key.generate"));
	QCOMPARE(e.result, QString("denied"));
	QCOMPARE(e.errorCode, QString("confirmation_required"));
	QCOMPARE(e.params["question"].toString(), QString("key.size"));
	QCOMPARE(e.params["key_size"].toLongLong(), qint64(768));
	QVERIFY(!e.params.contains("confirmed"));
	QVERIFY(AuditLog::verify().ok());
}

void test_service_key::newKeyTooSmall()
{
	warning->expectMessage("Key size too small");
	pki_key *key = Database.model<db_key>()->newKey(
				keyjob("RSA:16"), "tiny-key");
	QVERIFY(!key);
	QCOMPARE(Store.getAll<pki_key>().size(), 0);
}

XCA_SERVICE_TEST_MAIN(test_service_key)
#include "test_service_key.moc"
