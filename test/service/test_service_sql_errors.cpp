/* vi: set sw=4 ts=4:
 *
 * A write that does not reach the database is a typed service error
 * (BTD-50): read_only_database or disk_full where SQLite says so,
 * database_error otherwise, with SQLite's reason in the text. No SQL
 * message box in a service path, no partial change, and an object whose
 * store step failed stays with the caller instead of being deleted.
 *
 * Faults: PRAGMA query_only (read-only database), PRAGMA max_page_count
 * (full disk), the database file removed while open, and a TEMP trigger
 * that refuses one statement of one helper.
 */

#include <QFile>
#include <QRegularExpression>
#include <QSqlError>
#include <QSqlQuery>

#include <openssl/evp.h>

#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/db_key.h"
#include "lib/db_x509.h"
#include "lib/db_x509req.h"
#include "lib/exception.h"
#include "lib/issuance.h"
#include "lib/pki_evp.h"
#include "lib/pki_x509.h"
#include "lib/pki_x509req.h"
#include "lib/request.h"
#include "lib/settings.h"
#include "lib/x509rev.h"

#include "ServiceTestCase.h"

#define INJECTED "btd50 injected"

class test_service_sql_errors : public ServiceTestCase
{
	Q_OBJECT

	ServiceContext ctx{ ServiceContext::cli, "os:service-test" };

	static QString sql(const QString &stmt)
	{
		QSqlQuery q;
		return q.exec(stmt) ? QString() : q.lastError().text();
	}
	static int rows(const QString &table)
	{
		QSqlQuery q;
		if (!q.exec(QString("SELECT COUNT(*) FROM %1").arg(table)) ||
		    !q.next())
			return -1;
		return q.value(0).toInt();
	}
	/* refuses statement ("INSERT", "UPDATE") on table */
	static QString fault(const QString &stmt, const QString &table)
	{
		return sql(QString("CREATE TEMP TRIGGER btd50_fault BEFORE %1 "
			"ON %2 BEGIN SELECT RAISE(ABORT, '" INJECTED "'); END")
			.arg(stmt, table));
	}
	/* no success entry without its object: the entries after count are
	 * failures only, the code of the last one is code (none if the
	 * database could not take one either) */
	static void noOrphanEntry(int count, const QString &code)
	{
		QList<AuditEntry> e = AuditLog::entries();
		for (int i = count; i < e.size(); i++)
			QVERIFY2(e[i].result != "success", CCHAR(e[i].action));
		if (!code.isEmpty()) {
			QVERIFY(e.size() > count);
			QCOMPARE(e.last().errorCode, code);
		}
		QVERIFY(AuditLog::verify().ok());
	}
	static void clearFault()
	{
		sql("DROP TRIGGER IF EXISTS temp.btd50_fault");
	}
	pki_key *key(const QString &name)
	{
		return Database.model<db_key>()->newKey(ctx,
			keyjob("EC:prime256v1"), name);
	}
	pki_x509 *issue(const QString &cn, pki_x509 *signer,
			pki_x509req *req = nullptr);
	pki_x509req *request(const QString &cn);
	/* runs f, returns the serviceError code and text ("" if none) */
	template <class F> static QPair<QString, QString> codeOf(F f)
	{
		try {
			f();
		} catch (serviceError &err) {
			return qMakePair(err.code, err.getString());
		} catch (errorEx &err) {
			return qMakePair(QString("errorEx"), err.getString());
		}
		return qMakePair(QString(), QString());
	}

  private slots:
	void cleanup();
	void readOnlyDatabase();
	void failedVacuumLogged();
	void diskFull();
	void removedWhileOpen();
	void insertKeepsObject();
	void importHandsBack();
	void revocationListWrite();
	void revokeStops();
	void requestMarkSigned();
	void issueFromRequestStops();
	void privateKeyUpdate();
	void taKeyNotStored();
	void noStatementInText();
	void codePerDriver_data();
	void codePerDriver();
	void commitErrorReachesCaller();
};

void test_service_sql_errors::cleanup()
{
	clearFault();
	sql("PRAGMA query_only = OFF");
	ServiceTestCase::cleanup();
}

pki_x509 *test_service_sql_errors::issue(const QString &cn, pki_x509 *signer,
				pki_x509req *req)
{
	IssuanceSpec spec;
	spec.name = cn;
	spec.request = req;
	if (req)
		spec.subject = req->getSubject();
	else
		spec.subject.addEntryByNid(NID_commonName, cn);
	if (!req)
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
		spec.extensions.keyUsage << "keyCertSign" << "cRLSign";
	}
	return Database.model<db_x509>()->newCert(ctx, spec);
}

pki_x509req *test_service_sql_errors::request(const QString &cn)
{
	RequestSpec spec;
	spec.name = cn;
	spec.subject.addEntryByNid(NID_commonName, cn);
	spec.key = key(cn + " key");
	spec.hashAlgo = digest(NID_sha256);
	spec.extensions.basicCA = ExtensionSpec::bc_not_ca;
	return Database.model<db_x509req>()->newRequest(ctx, spec);
}

/* Before: the INSERT showed an SQL message box (also in the CLI), and the
 * service error was the generic database_error */
void test_service_sql_errors::readOnlyDatabase()
{
	int keys = rows("items");
	int entries = AuditLog::entries().size();
	QCOMPARE(sql("PRAGMA query_only = ON"), QString());
	auto r = codeOf([&]() { key("read-only key"); });
	QCOMPARE(sql("PRAGMA query_only = OFF"), QString());
	/* the failure entry could not be written either (BTD-138) */
	QCOMPARE(AuditLog::entries().size(), entries);
	noOrphanEntry(entries, QString());
	QCOMPARE(r.first, QString("read_only_database"));
	QVERIFY2(r.second.contains("readonly"), CCHAR(r.second));
	QCOMPARE(rows("items"), keys);
	QCOMPARE(Store.getAll<pki_key>().size(), 0);
}

/* After a run that wrote, the close vacuums; a failed VACUUM is logged
 * with its SQL error and the close goes on (BTD-225: the result was not
 * checked) */
void test_service_sql_errors::failedVacuumLogged()
{
	QVERIFY(key("vacuum key"));
	QCOMPARE(sql("PRAGMA query_only = ON"), QString());
	QTest::ignoreMessage(QtWarningMsg, QRegularExpression(
		"VACUUM after the writes of this run failed:.*readonly"));
	reopenDatabase();
	QCOMPARE(Store.getAll<pki_key>().size(), 1);
}

void test_service_sql_errors::diskFull()
{
	QCOMPARE(sql("VACUUM"), QString());
	QSqlQuery q;
	QVERIFY(q.exec("PRAGMA page_count") && q.next());
	QCOMPARE(sql(QString("PRAGMA max_page_count = %1")
			.arg(q.value(0).toInt())), QString());
	QPair<QString, QString> r;
	/* the free space of the last pages takes a few keys */
	for (int i = 0; i < 50 && r.first.isEmpty(); i++) {
		int before = rows("items");
		r = codeOf([&]() {
			Database.model<db_key>()->newKey(ctx,
				keyjob("RSA:2048"), QString("full %1").arg(i));
		});
		if (!r.first.isEmpty())
			QCOMPARE(rows("items"), before);
	}
	QCOMPARE(r.first, QString("disk_full"));
	QVERIFY2(r.second.contains("full"), CCHAR(r.second));
}

/* On Linux SQLite keeps the unlinked file open and refuses to write to it
 * (SQLITE_READONLY_DBMOVED) */
void test_service_sql_errors::removedWhileOpen()
{
	QVERIFY(QFile::remove(dbFile));
	auto r = codeOf([&]() { key("orphan key"); });
	QCOMPARE(r.first, QString("read_only_database"));
	QCOMPARE(Store.getAll<pki_key>().size(), 0);
	/* cleanup() closes the database; the file is gone either way */
}

/* insertPKI() used to delete the object; now the caller keeps it, e.g.
 * the import dialog for the item that could not be stored (BTD-114) */
void test_service_sql_errors::insertKeepsObject()
{
	pki_evp *k = new pki_evp(EVP_PKEY_Q_keygen(nullptr, nullptr, "EC",
						"P-256"));
	k->setIntName("kept");
	QCOMPARE(sql("PRAGMA query_only = ON"), QString());
	auto r = codeOf([&]() { Database.model<db_key>()->insertPKI(k); });
	QCOMPARE(sql("PRAGMA query_only = OFF"), QString());
	QCOMPARE(r.first, QString("read_only_database"));
	/* still the caller's: valid, not in the store, not in the database */
	QCOMPARE(k->getIntName(), QString("kept"));
	QVERIFY(!k->getSqlItemId().isValid());
	QCOMPARE(Store.getAll<pki_key>().size(), 0);
	QCOMPARE(rows("items"), 0);
	/* and it can be stored once the database is writable again */
	QVERIFY(Database.model<db_key>()->insertPKI(k) == k);
	QCOMPARE(rows("private_keys"), 1);
}

void test_service_sql_errors::importHandsBack()
{
	pki_evp *k = new pki_evp(EVP_PKEY_Q_keygen(nullptr, nullptr, "EC",
						"P-256"));
	k->setIntName("import me");
	QList<pki_base *> unstored;
	ImportSpec spec;
	spec.items << k;
	spec.unstored = &unstored;
	QCOMPARE(sql("PRAGMA query_only = ON"), QString());
	auto r = codeOf([&]() { Database.importItems(ctx, spec); });
	QCOMPARE(sql("PRAGMA query_only = OFF"), QString());
	QCOMPARE(r.first, QString("read_only_database"));
	QCOMPARE(unstored.size(), 1);
	QVERIFY(unstored.first() == k);
	QVERIFY(!k->getSqlItemId().isValid());
	delete k;
}

/* Before: sqlUpdate() returned false, its callers carried on in a
 * transaction that could only roll back */
void test_service_sql_errors::revocationListWrite()
{
	pki_x509 *ca = issue("BTD-50 CA", nullptr);
	QVERIFY(ca);
	x509rev rev;
	rev.setSerial(a1int(0x5050L));
	rev.setDate(a1time());
	x509revList list(rev);
	QCOMPARE(fault("INSERT", "revocations"), QString());
	auto r = codeOf([&]() { list.sqlUpdate(ca->getSqlItemId()); });
	clearFault();
	QCOMPARE(r.first, QString("database_error"));
	QVERIFY2(r.second.contains(INJECTED), CCHAR(r.second));
	QCOMPARE(rows("revocations"), 0);
}

void test_service_sql_errors::revokeStops()
{
	pki_x509 *ca = issue("BTD-50 CA", nullptr);
	QVERIFY(ca);
	pki_x509 *ee = issue("BTD-50 EE", ca);
	QVERIFY(ee);
	QCOMPARE(fault("INSERT", "revocations"), QString());
	int entries = AuditLog::entries().size();
	auto r = codeOf([&]() {
		x509rev rev;
		rev.setReason("Key Compromise");
		Database.model<db_x509>()->revoke(ctx, ee, rev);
	});
	clearFault();
	noOrphanEntry(entries, "database_error");
	QCOMPARE(r.first, QString("database_error"));
	QVERIFY2(r.second.contains(INJECTED), CCHAR(r.second));
	QVERIFY(!ee->isRevoked());
	QCOMPARE(rows("revocations"), 0);
}

/* Before: the failed UPDATE returned silently and the request was shown
 * as unchanged without an error */
void test_service_sql_errors::requestMarkSigned()
{
	pki_x509req *req = request("BTD-50 request");
	QVERIFY(req);
	QVERIFY(!req->getDone());
	QCOMPARE(fault("UPDATE", "requests"), QString());
	auto r = codeOf([&]() { req->markSigned(true); });
	clearFault();
	QCOMPARE(r.first, QString("database_error"));
	QVERIFY2(r.second.contains(INJECTED), CCHAR(r.second));
	QVERIFY(!req->getDone());
}

/* Before: db_x509::markRequestSigned() did not check its two UPDATEs; the
 * certificate was stored while the request stayed unsigned */
void test_service_sql_errors::issueFromRequestStops()
{
	pki_x509 *ca = issue("BTD-50 CA", nullptr);
	QVERIFY(ca);
	pki_x509req *req = request("BTD-50 device");
	QVERIFY(req);
	int certs = rows("certs");
	int entries = AuditLog::entries().size();
	QCOMPARE(fault("UPDATE", "requests"), QString());
	auto r = codeOf([&]() { issue("BTD-50 device", ca, req); });
	clearFault();
	noOrphanEntry(entries, "database_error");
	QCOMPARE(r.first, QString("database_error"));
	QVERIFY2(r.second.contains(INJECTED), CCHAR(r.second));
	QCOMPARE(rows("certs"), certs);
	QVERIFY(!req->getDone());
}

/* Before: sqlUpdatePrivateKey() answered a failed UPDATE with "false",
 * the same as "nothing to store", and the password change threw an
 * untyped errorEx */
void test_service_sql_errors::privateKeyUpdate()
{
	QVERIFY(key("re-encrypted"));
	QString hash = Settings["pwhash"];
	Passwd pass;
	pass = "btd50 new password";
	QCOMPARE(fault("UPDATE", "private_keys"), QString());
	auto r = codeOf([&]() {
		Database.model<db_key>()->changeDatabasePassword(pass);
	});
	clearFault();
	QCOMPARE(r.first, QString("database_error"));
	QVERIFY2(r.second.contains(INJECTED), CCHAR(r.second));
	QCOMPARE(QString(Settings["pwhash"]), hash);
}

/* Before: the INSERT of a new tls-auth key failed unnoticed, the commit
 * succeeded and the caller got a key that was never stored: every export
 * made a different one */
void test_service_sql_errors::taKeyNotStored()
{
	pki_x509 *ca = issue("BTD-50 VPN CA", nullptr);
	QVERIFY(ca);
	QCOMPARE(fault("INSERT", "takeys"), QString());
	auto r = codeOf([&]() { ca->getTaKey(); });
	clearFault();
	QCOMPARE(r.first, QString("database_error"));
	QVERIFY2(r.second.contains(INJECTED), CCHAR(r.second));
	QCOMPARE(rows("takeys"), 0);
}

/* The text of a typed SQL error never carries the statement or its bound
 * values: the driver text of XSqlQuery holds both, and a value may be a
 * tls-auth key or an encrypted private key (review of xca#68, blocker 2).
 * An empty databaseText(), e.g. "Parameter count mismatch" after a failed
 * prepare, used to put the driver text into the message. */
void test_service_sql_errors::noStatementInText()
{
	const char secret[] = "BTD50-SECRET-tls-auth-0123456789abcdef";
	XSqlQuery q;
	Transaction;
	QVERIFY(TransBegin());
	SQL_PREPARE(q, "SELECT 1");
	q.bindValue(0, QString(secret));
	q.bindValue(1, QString(secret));
	auto r = codeOf([&]() { execOrThrow(q, "BTD-50 statement"); });
	TransRollback();
	QVERIFY2(!r.first.isEmpty(), "the statement did not fail");
	QVERIFY2(!r.second.contains(secret), CCHAR(r.second));
	QVERIFY2(!r.second.contains("SELECT"), CCHAR(r.second));
	QVERIFY2(r.second.startsWith("BTD-50 statement"), CCHAR(r.second));

	/* the same for an error without databaseText at all */
	QSqlError e(QString("driver - sql.cpp:1 (INSERT INTO takeys "
		"VALUES (?)[%1])").arg(secret), QString(),
		QSqlError::StatementError, "1");
	r = codeOf([&]() { throwSqlError(e, "BTD-50 driver text"); });
	QCOMPARE(r.first, QString("database_error"));
	QCOMPARE(r.second, QString("BTD-50 driver text"));
}

void test_service_sql_errors::codePerDriver_data()
{
	QTest::addColumn<QString>("driver");
	QTest::addColumn<QString>("native");
	QTest::addColumn<QString>("code");

	QTest::newRow("SQLite read-only") << "QSQLITE" << "8"
		<< "read_only_database";
	QTest::newRow("SQLite file moved") << "QSQLITE" << "1032"
		<< "read_only_database";
	QTest::newRow("SQLite full") << "QSQLITE" << "13" << "disk_full";
	QTest::newRow("SQLite constraint") << "QSQLITE" << "19"
		<< "database_error";
	/* the low-byte rule of SQLite would make these 8 and 13 */
	QTest::newRow("PostgreSQL 53000") << "QPSQL" << "53000"
		<< "database_error";
	QTest::newRow("PostgreSQL read-only") << "QPSQL" << "25006"
		<< "read_only_database";
	QTest::newRow("PostgreSQL disk full") << "QPSQL" << "53100"
		<< "disk_full";
	QTest::newRow("MySQL 1032") << "QMYSQL" << "1032" << "database_error";
	QTest::newRow("MySQL 1037") << "QMYSQL" << "1037" << "database_error";
	QTest::newRow("MySQL read-only") << "QMYSQL" << "1290"
		<< "read_only_database";
	QTest::newRow("MariaDB disk full") << "QMARIADB" << "1021"
		<< "disk_full";
	QTest::newRow("ODBC") << "QODBC" << "8" << "database_error";
}

/* read_only_database and disk_full per driver, not the low byte of any
 * native code (review of xca#68, MINOR 3) */
void test_service_sql_errors::codePerDriver()
{
	QFETCH(QString, driver);
	QFETCH(QString, native);
	QFETCH(QString, code);
	QCOMPARE(sqlErrorCode(driver, native), code);
}

/* SQLite reports some errors only at COMMIT (a full disk, a deferred
 * constraint): the service functions threw a generic "Failed to commit"
 * without the reason. A deferred foreign key stands in for the full disk
 * (review of xca#68, MINOR 4). */
void test_service_sql_errors::commitErrorReachesCaller()
{
	QCOMPARE(sql("PRAGMA foreign_keys=ON"), QString());
	QCOMPARE(sql("CREATE TEMP TABLE btd50_parent (id INTEGER PRIMARY KEY)"),
		QString());
	QCOMPARE(sql("CREATE TEMP TABLE btd50_child (p INTEGER REFERENCES "
		"btd50_parent(id) DEFERRABLE INITIALLY DEFERRED)"), QString());
	QCOMPARE(sql("CREATE TEMP TRIGGER btd50_commit AFTER INSERT ON items "
		"BEGIN INSERT INTO btd50_child VALUES (42); END"), QString());
	int items = rows("items");
	auto r = codeOf([&]() { key("commit refused"); });
	sql("DROP TRIGGER temp.btd50_commit");
	sql("PRAGMA foreign_keys=OFF");
	QCOMPARE(r.first, QString("database_error"));
	QVERIFY2(r.second.contains("FOREIGN KEY constraint failed"),
		CCHAR(r.second));
	QCOMPARE(rows("items"), items);
	QCOMPARE(Store.getAll<pki_key>().size(), 0);
}

XCA_SERVICE_TEST_MAIN(test_service_sql_errors)
#include "test_service_sql_errors.moc"
