/* vi: set sw=4 ts=4:
 *
 * Sample service test: key generation through db_key::newKey(keyjob, name),
 * the GUI-free path behind "New key".
 */

#include <openssl/evp.h>

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
}

void test_service_key::newKeySmallRsaDeclined()
{
	warning->expectQuestion(false);
	pki_key *key = Database.model<db_key>()->newKey(
				keyjob("RSA:768"), "small-key");
	QVERIFY(!key);
	QCOMPARE(Store.getAll<pki_key>().size(), 0);
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
