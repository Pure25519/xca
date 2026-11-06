/* vi: set sw=4 ts=4:
 *
 * The rows of the BTD-142 caller table whose failed COMMIT no test
 * reached (BTD-151, MINOR 9 of the review of xca#31). Each test makes
 * exactly the COMMIT of its row fail: a TEMP trigger on the table that
 * row writes adds a child row with a dangling deferred foreign key, and
 * SQLite refuses only the COMMIT. That does not depend on how many
 * nested commits run before (injectNestedRollback(skip) does).
 *
 * The other rows are tested elsewhere: insertEntry()
 * (test_service_transaction::appendCommitFails), writeCheckpoint()
 * (test_service_checkpoint), the schema update
 * (schemaUpdateFailureStopsOpen), removeItem()
 * (test_service_memory::deleteSecondFailsKeepsAll), the password change
 * (passwordChangeRollbackKeepsOld), and with an SQL error the helpers of
 * BTD-50 (test_service_sql_errors: privateKeyUpdate, taKeyNotStored,
 * requestMarkSigned, revocationListWrite).
 */

#include <functional>

#include <QSqlError>
#include <QSqlQuery>

#include <openssl/evp.h>

#include "lib/audit.h"
#include "lib/db_crl.h"
#include "lib/db_key.h"
#include "lib/db_x509.h"
#include "lib/digest.h"
#include "lib/exception.h"
#include "lib/issuance.h"
#include "lib/pki_crl.h"
#include "lib/pki_evp.h"
#include "lib/pki_x509.h"
#include "lib/settings.h"
#include "lib/sql.h"

#include "ServiceTestCase.h"

class test_service_commit_rows : public ServiceTestCase
{
	Q_OBJECT

	ServiceContext ctx{ ServiceContext::cli, "os:service-test" };

	static void sql(const QString &statement)
	{
		QSqlQuery q;
		if (!q.exec(statement))
			qFatal("%s: %s", qPrintable(statement),
				qPrintable(q.lastError().text()));
	}
	static int count(const QString &statement)
	{
		QSqlQuery q;
		return q.exec(statement) && q.next() ? q.value(0).toInt() : -1;
	}
	/* the COMMIT of every transaction that writes to table (rows that
	 * match when, if given) fails */
	static void commitFailsOn(const QString &table, const QString &when =
				QString())
	{
		sql("PRAGMA foreign_keys=ON");
		sql("CREATE TEMP TABLE btd151_parent (id INTEGER PRIMARY KEY)");
		sql("CREATE TEMP TABLE btd151_child (p INTEGER REFERENCES "
			"btd151_parent(id) DEFERRABLE INITIALLY DEFERRED)");
		for (const char *op : { "INSERT", "UPDATE" })
			sql(QString("CREATE TEMP TRIGGER btd151_%1 AFTER %1 ON %2 "
				"%3 BEGIN INSERT INTO btd151_child VALUES (42); "
				"END").arg(op, table, when.isEmpty() ? QString() :
					"WHEN " + when));
	}
	static void commitWorksAgain()
	{
		sql("DROP TRIGGER IF EXISTS temp.btd151_INSERT");
		sql("DROP TRIGGER IF EXISTS temp.btd151_UPDATE");
		sql("DROP TABLE IF EXISTS temp.btd151_child");
		sql("DROP TABLE IF EXISTS temp.btd151_parent");
	}
	/* "" on success, the serviceError code, or "errorEx: <text>" */
	static QString errorCode(std::function<void()> call)
	{
		try {
			call();
		} catch (serviceError &err) {
			return err.code + ": " + err.getString();
		} catch (errorEx &err) {
			return "errorEx: " + err.getString();
		}
		return QString();
	}
	pki_x509 *selfSigned(const QString &cn)
	{
		IssuanceSpec spec;
		spec.name = cn;
		spec.subject.addEntryByNid(NID_commonName, cn);
		spec.key = Database.model<db_key>()->newKey(ctx,
				keyjob("EC:prime256v1"), cn + " key");
		spec.notBefore = a1time(QDateTime::currentDateTimeUtc()
					.addDays(-1));
		spec.notAfter = a1time(QDateTime::currentDateTimeUtc()
					.addDays(365));
		spec.hashAlgo = digest(NID_sha256);
		spec.extensions.subjectKeyId = true;
		spec.extensions.basicCA = ExtensionSpec::bc_ca;
		spec.extensions.keyUsage << "keyCertSign" << "cRLSign";
		return Database.model<db_x509>()->newCert(ctx, spec);
	}

  private slots:
	void cleanup();
	void writeBaselineCommitFails();
	void insertPKICommitFails();
	void crlInsertCommitFails();
	void importTaKeyCommitFails();
	void settingCommitFails();
};

void test_service_commit_rows::cleanup()
{
	commitWorksAgain();
	ServiceTestCase::cleanup();
}

/* writeBaseline(): the baseline of the existing revocations and audit.init
 * in one transaction; a failed COMMIT throws and leaves no entry */
void test_service_commit_rows::writeBaselineCommitFails()
{
	sql("INSERT INTO revocations (caId, serial, date, invaldate, crlNo, "
		"reasonBit) VALUES (1, '0151', '20260101000000Z', "
		"'20260101000000Z', NULL, 0)");
	int entries = AuditLog::entries().size();
	commitFailsOn("audit_log", "NEW.action='revocation.baseline'");
	QString code = errorCode([&]() { AuditLog::writeBaseline(); });
	commitWorksAgain();
	QVERIFY2(code.contains("baseline was not committed",
		Qt::CaseInsensitive), CCHAR(code));
	QCOMPARE(AuditLog::entries().size(), entries);
	/* the revocation is still without its baseline entry */
	QCOMPARE(AuditLog::verify().unauditedRevocations, qint64(1));
}

/* insertPKI() outside a transaction: a failed COMMIT throws, the object
 * is not in the store and stays with the caller */
void test_service_commit_rows::insertPKICommitFails()
{
	pki_evp *k = new pki_evp(EVP_PKEY_Q_keygen(nullptr, nullptr, "EC",
						"P-256"));
	k->setIntName("BTD-151 key");
	commitFailsOn("items", "NEW.name='BTD-151 key'");
	QString code = errorCode([&]() {
		Database.model<db_key>()->insertPKI(k);
	});
	commitWorksAgain();
	QVERIFY2(code.startsWith("database_error"), CCHAR(code));
	QCOMPARE(Store.getAll<pki_key>().size(), 0);
	QCOMPARE(count("SELECT COUNT(*) FROM items WHERE name='BTD-151 key'"), 0);
	QVERIFY(!k->getSqlItemId().isValid());
	/* the caller's object can be stored once the database takes it */
	QVERIFY(Database.model<db_key>()->insertPKI(k) == k);
	QCOMPARE(Store.getAll<pki_key>().size(), 1);
}

/* db_crl::insert() outside a transaction: the CRL and the revocations it
 * adds to its CA, all rolled back with the failed COMMIT */
void test_service_commit_rows::crlInsertCommitFails()
{
	pki_x509 *ca = selfSigned("BTD-151 CA");
	QVERIFY(ca);
	pki_crl *made = Database.model<db_crl>()->newCrl(ctx, crljob(ca));
	QVERIFY(made);
	QByteArray der = made->i2d();
	Database.model<db_crl>()->deleteItems(ctx, { made });
	QCOMPARE(Store.getAll<pki_crl>().size(), 0);

	pki_crl *crl = new pki_crl("BTD-151 CRL");
	crl->d2i(der);
	commitFailsOn("crls");
	QString code = errorCode([&]() {
		Database.model<db_crl>()->insert(crl);
	});
	commitWorksAgain();
	QVERIFY2(code.startsWith("database_error"), CCHAR(code));
	QCOMPARE(Store.getAll<pki_crl>().size(), 0);
	QCOMPARE(count("SELECT COUNT(*) FROM crls"), 0);
	QVERIFY(!crl->getSqlItemId().isValid());
	delete crl;
}

/* importTaKey(): a failed COMMIT reports the error and returns false, no
 * tls-auth key is stored */
void test_service_commit_rows::importTaKeyCommitFails()
{
	pki_x509 *source = selfSigned("BTD-151 TA source");
	QVERIFY(source);
	QString text = source->getTaKey();
	QVERIFY(text.contains("OpenVPN Static key V1"));
	pki_x509 *target = selfSigned("BTD-151 TA target");
	QVERIFY(target);
	int stored = count("SELECT COUNT(*) FROM takeys");

	commitFailsOn("takeys");
	warning->expectMessage("Failed to import tls-auth key");
	bool imported = target->importTaKey(text.toLatin1());
	commitWorksAgain();
	QVERIFY(!imported);
	QCOMPARE(count("SELECT COUNT(*) FROM takeys"), stored);
	/* once the database takes it, the same key is stored */
	warning->expectMessage("successfully imported");
	QVERIFY(target->importTaKey(text.toLatin1()));
	QCOMPARE(count("SELECT COUNT(*) FROM takeys"), stored + 1);
}

/* settings::set() outside a transaction: a failed COMMIT keeps the stored
 * value in memory and in the database */
void test_service_commit_rows::settingCommitFails()
{
	QString before = Settings["default_hash"];
	QString other = before == "SHA512" ? "SHA384" : "SHA512";
	commitFailsOn("settings", "NEW.key_='default_hash'");
	Settings["default_hash"] = other;
	commitWorksAgain();
	QCOMPARE(QString(Settings["default_hash"]), before);
	QCOMPARE(digest::getDefault().name(), before);
	Settings.clear();
	QCOMPARE(QString(Settings["default_hash"]), before);
	/* and the next set works */
	Settings["default_hash"] = other;
	QCOMPARE(QString(Settings["default_hash"]), other);
}

XCA_SERVICE_TEST_MAIN(test_service_commit_rows)
#include "test_service_commit_rows.moc"
