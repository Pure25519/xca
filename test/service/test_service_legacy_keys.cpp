/* vi: set sw=4 ts=4:
 *
 * The conversion of legacy-encrypted private keys when a database is
 * opened (db_key::updateKeyEncryptionScheme(), BTD-269). The fixture
 * schema8-legacy-keys.sql is schema8-fork.sql with both private keys in the
 * legacy format of XCA 1.x and without the marker legacy-keys-updated; it
 * is synthesised by data/make_legacy_key_fixture.py (data/README.md).
 */

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QMap>
#include <QSqlDatabase>
#include <QSqlError>
#include <QSqlQuery>

#include <openssl/evp.h>
#include <openssl/x509.h>

#include "lib/BioByteArray.h"
#include "lib/database_model.h"
#include "lib/db_key.h"
#include "lib/pki_evp.h"
#include "lib/settings.h"

#include "ServiceTestCase.h"

class test_service_legacy_keys : public ServiceTestCase
{
	Q_OBJECT

	/* the dump into dbFile instead of the database of init(), opened;
	 * with marker the settings row legacy-keys-updated is 'yes' first,
	 * so the open converts nothing */
	void openDump(const QString &name, bool marker);
	/* item id -> private_keys.private, read from dbFile */
	QMap<int, QByteArray> blobs();
	/* item id -> the decrypted private key in its type-specific DER */
	static QMap<int, QByteArray> keys();
	static QByteArray der(EVP_PKEY *pkey);
	static bool isPkcs8(const QByteArray &blob);
	static void sql(const QString &statement);

  private slots:
	void fixtureMatchesReader();
	void openConvertsLegacyKeys();
	void conversionCommitFails();
};

void test_service_legacy_keys::openDump(const QString &name, bool marker)
{
	Database.close();
	QVERIFY(QFile::remove(dbFile));
	/* The copy before the schema upgrade (BTD-70) is named by the second;
	 * two upgrades within one second would collide on that name */
	QDir dir(QFileInfo(dbFile).absolutePath());
	for (const QString &bak : dir.entryList(
			{ QFileInfo(dbFile).fileName() + ".bak-*" }, QDir::Files))
		QVERIFY(dir.remove(bak));
	{
		QFile dump(QString(SERVICE_TEST_DATA "/") + name);
		QVERIFY(dump.open(QIODevice::ReadOnly));
		QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "fixture");
		db.setDatabaseName(dbFile);
		QVERIFY(db.open());
		QSqlQuery q(db);
		QString statement;
		while (!dump.atEnd()) {
			statement += QString::fromUtf8(dump.readLine());
			if (!statement.trimmed().endsWith(';'))
				continue;
			QVERIFY2(q.exec(statement), CCHAR(q.lastError().text()));
			statement.clear();
		}
		if (marker)
			QVERIFY(q.exec("INSERT OR REPLACE INTO settings (key_, value) "
				"VALUES ('legacy-keys-updated', 'yes')"));
		db.close();
	}
	QSqlDatabase::removeDatabase("fixture");
	openDatabase();
}

QMap<int, QByteArray> test_service_legacy_keys::blobs()
{
	QMap<int, QByteArray> m;
	QSqlQuery q("SELECT item, private FROM private_keys");
	while (q.next())
		m[q.value(0).toInt()] =
			QByteArray::fromBase64(q.value(1).toByteArray());
	return m;
}

QByteArray test_service_legacy_keys::der(EVP_PKEY *pkey)
{
	unsigned char *p = nullptr;
	int n = pkey ? i2d_PrivateKey(pkey, &p) : 0;
	QByteArray d = n > 0 ? QByteArray((const char *)p, n) : QByteArray();
	OPENSSL_free(p);
	return d;
}

QMap<int, QByteArray> test_service_legacy_keys::keys()
{
	QMap<int, QByteArray> m;
	for (pki_evp *k : Store.sqlSELECTpki<pki_evp>(
				"SELECT item FROM private_keys")) {
		EVP_PKEY *pkey = k->decryptKey();
		m[k->getSqlItemId().toInt()] = der(pkey);
		EVP_PKEY_free(pkey);
	}
	return m;
}

bool test_service_legacy_keys::isPkcs8(const QByteArray &blob)
{
	X509_SIG *p8 = d2i_PKCS8_bio(BioByteArray(blob).ro(), nullptr);
	X509_SIG_free(p8);
	return p8 != nullptr;
}

void test_service_legacy_keys::sql(const QString &statement)
{
	QSqlQuery q;
	QVERIFY2(q.exec(statement), CCHAR(q.lastError().text()));
}

/* The fixture is what the reader reads: pki_evp::legacyDecryptKey() turns
 * each legacy blob into the key that schema8-fork.sql holds as PKCS#8 */
void test_service_legacy_keys::fixtureMatchesReader()
{
	openDump("schema8-fork.sql", true);
	QMap<int, QByteArray> source = keys();
	QCOMPARE(source.keys(), QList<int>({ 1, 3 }));

	openDump("schema8-legacy-keys.sql", true);
	QMap<int, QByteArray> legacy = blobs();
	QCOMPARE(legacy.keys(), source.keys());
	for (pki_evp *k : Store.sqlSELECTpki<pki_evp>(
				"SELECT item FROM private_keys")) {
		int id = k->getSqlItemId().toInt();
		QByteArray blob = legacy[id];
		QVERIFY2(!isPkcs8(blob), CCHAR(QString::number(id)));
		EVP_PKEY *pkey = k->legacyDecryptKey(blob, KeyContext::session()->password);
		QVERIFY2(pkey, CCHAR(QString::number(id)));
		QCOMPARE(der(pkey), source[id]);
		EVP_PKEY_free(pkey);
	}
}

/* The normal open converts every legacy key to PKCS#8; the keys stay the
 * same and the marker is set */
void test_service_legacy_keys::openConvertsLegacyKeys()
{
	openDump("schema8-fork.sql", true);
	QMap<int, QByteArray> source = keys();

	openDump("schema8-legacy-keys.sql", false);
	QMap<int, QByteArray> rows = blobs();
	QCOMPARE(rows.keys(), source.keys());
	for (int id : rows.keys())
		QVERIFY2(isPkcs8(rows[id]), CCHAR(QString::number(id)));
	QCOMPARE(keys(), source);
	QVERIFY((bool)Settings["legacy-keys-updated"]);

	/* and after the next open, from the rows */
	reopenDatabase();
	QCOMPARE(keys(), source);
}

/* A failed COMMIT of the conversion (a deferred foreign key, checked only
 * at COMMIT) changes no row and leaves the marker unset; the next open
 * converts. The open runs the same updateKeyEncryptionScheme(), which is
 * called here directly, after the open with the marker set, so that the
 * failure can be set up on the connection of XCA first. */
void test_service_legacy_keys::conversionCommitFails()
{
	openDump("schema8-legacy-keys.sql", true);
	QMap<int, QByteArray> before = blobs();
	for (const QByteArray &b : before)
		QVERIFY(!isPkcs8(b));

	Settings["legacy-keys-updated"] = false;
	sql("PRAGMA foreign_keys=ON");
	sql("CREATE TEMP TABLE btd269_parent (id INTEGER PRIMARY KEY)");
	sql("CREATE TEMP TABLE btd269_child (p INTEGER REFERENCES "
		"btd269_parent(id) DEFERRABLE INITIALLY DEFERRED)");
	sql("CREATE TEMP TRIGGER btd269_commit AFTER UPDATE ON private_keys "
		"BEGIN INSERT INTO btd269_child VALUES (42); END");
	Database.model<db_key>()->updateKeyEncryptionScheme();
	QCOMPARE(blobs(), before);
	QVERIFY(!(bool)Settings["legacy-keys-updated"]);
	sql("DROP TRIGGER btd269_commit");
	sql("PRAGMA foreign_keys=OFF");

	/* the retry: the next open converts */
	reopenDatabase();
	for (const QByteArray &b : blobs())
		QVERIFY(isPkcs8(b));
	QVERIFY((bool)Settings["legacy-keys-updated"]);
}

XCA_SERVICE_TEST_MAIN(test_service_legacy_keys)
#include "test_service_legacy_keys.moc"
