/* vi: set sw=4 ts=4:
 *
 * DbTransaction::commit() after a nested rollback (BTD-142): the outer
 * commit of a transaction that an inner helper rolled back without
 * throwing reports failure, nothing is in the database, and every caller
 * group turns that into a typed error with a failure audit entry instead
 * of a silent success. The import case needs no injection: a CRL whose
 * revocation rows cannot be written (x509revList::sqlUpdate() returns
 * false and its caller carries on). The others use
 * DbTransaction::injectNestedRollback(), which turns a nested commit into
 * the same kind of swallowed rollback. Follow-up of the review of xca#31:
 * a failed schema update stops the open, a failed password change keeps
 * the old password in memory too, a stray rollback after a commit does
 * not fail the next transaction.
 */

#include <functional>

#include <QFile>
#include <QSqlError>
#include <QSqlQuery>
#include <QTemporaryDir>

#include <openssl/x509.h>

#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/db_crl.h"
#include "lib/db_key.h"
#include "lib/db_temp.h"
#include "lib/db_x509.h"
#include "lib/exception.h"
#include "lib/importexport.h"
#include "lib/issuance.h"
#include "lib/pki_crl.h"
#include "lib/pki_evp.h"
#include "lib/pki_temp.h"
#include "lib/pki_x509.h"
#include "lib/settings.h"
#include "lib/sql.h"
#include "lib/template.h"

#include "ServiceTestCase.h"

class test_service_transaction : public ServiceTestCase
{
	Q_OBJECT

	ServiceContext ctx{ ServiceContext::cli, "os:service-test" };
	QTemporaryDir dir{};

	static void sql(const QString &statement)
	{
		QSqlQuery q(QSqlDatabase::database());
		QVERIFY2(q.exec(statement), CCHAR(q.lastError().text()));
	}
	static QVariant sqlValue(const QString &statement)
	{
		QSqlQuery q(QSqlDatabase::database());
		q.exec(statement);
		return q.next() ? q.value(0) : QVariant();
	}
	/* "" on success, the serviceError code, or "errorEx: <text>" */
	static QString errorCode(std::function<void()> call);
	static pki_key *newKey(const QString &name)
	{
		return Database.model<db_key>()->newKey(
				keyjob("EC:prime256v1"), name);
	}
	pki_x509 *issue(const QString &cn, pki_x509 *signer);
	/* The last entry of the log is action with result failure and
	 * error code database_error */
	static void lastFailure(const QString &action);
	static int entries(const QString &action, const QString &result);

  private slots:
	void cleanup();
	void nestedRollbackFailsCommit();
	void innerExceptionFailsCommit();
	void cleanCommitSucceeds();
	void rollbackKeepsMeaning();
	void importCrlRevocationsFail();
	void exportNestedRollback();
	void deleteNestedRollback();
	void renameNestedRollback();
	void templateNestedRollback();
	void checkpointNestedRollback();
	void appendCommitFails();
	void schemaUpdateFailureStopsOpen();
	void passwordChangeRollbackKeepsOld();
	void strayRollbackDoesNotLeak();
};

QString test_service_transaction::errorCode(std::function<void()> call)
{
	try {
		call();
	} catch (serviceError &err) {
		return err.code;
	} catch (errorEx &err) {
		return "errorEx: " + err.getString();
	}
	return QString();
}

pki_x509 *test_service_transaction::issue(const QString &cn, pki_x509 *signer)
{
	QDateTime now = QDateTime::currentDateTimeUtc();
	IssuanceSpec spec;
	spec.name = cn;
	spec.subject.addEntryByNid(NID_commonName, cn);
	spec.key = newKey(cn + " key");
	spec.signer = signer;
	spec.notBefore = a1time(now.addDays(-1));
	spec.notAfter = a1time(now.addYears(1));
	spec.hashAlgo = digest(NID_sha256);
	spec.extensions.subjectKeyId = true;
	spec.extensions.authorityKeyId = true;
	if (signer) {
		spec.extensions.basicCA = ExtensionSpec::bc_not_ca;
		spec.extensions.keyUsage << "digitalSignature";
	} else {
		spec.extensions.basicCA = ExtensionSpec::bc_ca;
		spec.extensions.basicCritical = true;
		spec.extensions.keyUsage << "keyCertSign" << "cRLSign";
	}
	return Database.model<db_x509>()->newCert(ctx, spec);
}

void test_service_transaction::lastFailure(const QString &action)
{
	AuditEntry e = AuditLog::entries().last();
	QCOMPARE(e.action, action);
	QCOMPARE(e.result, QString("failure"));
	QCOMPARE(e.errorCode, QString("database_error"));
}

int test_service_transaction::entries(const QString &action,
			const QString &result)
{
	int n = 0;
	for (const AuditEntry &e : AuditLog::entries())
		if (e.action == action && e.result == result)
			n++;
	return n;
}

void test_service_transaction::cleanup()
{
	/* every injection was consumed by the call it was meant for */
	bool pending = DbTransaction::injectionPending();
	DbTransaction::injectNestedRollback(-1);
	ServiceTestCase::cleanup();
	QVERIFY(!pending);
}

/* An inner helper that rolls back and returns normally */
static void innerRollback()
{
	Transaction;
	QVERIFY(TransBegin());
	QVERIFY(TransRollback());
}

/* An inner helper left by an exception that the outer code catches;
 * its destructor rolls back */
static void innerThrows()
{
	Transaction;
	QVERIFY(TransBegin());
	throw errorEx("BTD-142 test: inner failure");
}

static void innerCommits()
{
	Transaction;
	QVERIFY(TransBegin());
	QVERIFY(TransCommit());
}

/* Acceptance criterion 1: outer begin, inner begin + rollback, outer
 * commit. On 8dc1c2cf the commit returned true with nothing stored. */
void test_service_transaction::nestedRollbackFailsCommit()
{
	sql("CREATE TABLE btd142 (x INTEGER)");
	{
		Transaction;
		QVERIFY(TransBegin());
		sql("INSERT INTO btd142 VALUES (1)");
		innerRollback();
		QVERIFY(!TransCommit());
	}
	QCOMPARE(sqlValue("SELECT COUNT(*) FROM btd142").toInt(), 0);
	QVERIFY(!DbTransaction::active());
}

void test_service_transaction::innerExceptionFailsCommit()
{
	sql("CREATE TABLE btd142 (x INTEGER)");
	{
		Transaction;
		QVERIFY(TransBegin());
		sql("INSERT INTO btd142 VALUES (1)");
		try {
			innerThrows();
			QFAIL("the inner helper did not throw");
		} catch (errorEx &) {
		}
		QVERIFY(!TransCommit());
	}
	QCOMPARE(sqlValue("SELECT COUNT(*) FROM btd142").toInt(), 0);
}

/* Without an inner rollback the commit still succeeds, also right after
 * a failed one: the error counter does not leak into the next
 * transaction */
void test_service_transaction::cleanCommitSucceeds()
{
	sql("CREATE TABLE btd142 (x INTEGER)");
	{
		Transaction;
		QVERIFY(TransBegin());
		innerRollback();
		QVERIFY(!TransCommit());
	}
	{
		Transaction;
		QVERIFY(TransBegin());
		sql("INSERT INTO btd142 VALUES (1)");
		innerCommits();
		QVERIFY(TransCommit());
	}
	QCOMPARE(sqlValue("SELECT COUNT(*) FROM btd142").toInt(), 1);
}

/* rollback() keeps its meaning: true when the rollback worked */
void test_service_transaction::rollbackKeepsMeaning()
{
	sql("CREATE TABLE btd142 (x INTEGER)");
	{
		Transaction;
		QVERIFY(TransBegin());
		sql("INSERT INTO btd142 VALUES (1)");
		innerRollback();
		QVERIFY(TransRollback());
	}
	QCOMPARE(sqlValue("SELECT COUNT(*) FROM btd142").toInt(), 0);
}

/* Import, without injection: the CA's revocation rows cannot be written
 * while the CRL is imported. x509revList::sqlUpdate() returns false,
 * its destructor rolls back, pki_x509::mergeRevList() carries on. On
 * 8dc1c2cf importItems() reported the CRL as created and nothing was
 * stored, not even an audit entry. */
void test_service_transaction::importCrlRevocationsFail()
{
	pki_x509 *ca = issue("BTD-142 CA", nullptr);
	QVERIFY(ca);
	pki_x509 *ee = issue("BTD-142 device", ca);
	QVERIFY(ee);
	x509rev rev;
	rev.setReason("Key Compromise");
	Database.model<db_x509>()->revoke(ctx, ee, rev);
	pki_crl *crl = Database.model<db_crl>()->newCrl(ctx, crljob(ca));
	QVERIFY(crl);
	QByteArray der = crl->i2d();
	Database.model<db_crl>()->deleteItems(ctx, { crl });
	Database.model<db_x509>()->unrevoke(ctx, ee);
	QCOMPARE(sqlValue("SELECT COUNT(*) FROM revocations").toInt(), 0);
	QCOMPARE(sqlValue("SELECT COUNT(*) FROM crls").toInt(), 0);
	int imports = entries("object.import", "success");

	sql("CREATE TEMP TRIGGER btd142_revocations BEFORE INSERT ON "
		"revocations BEGIN SELECT RAISE(ABORT, "
		"'BTD-142 test: revocation refused'); END");
	ImportSpec spec;
	spec.data = der;
	spec.dataName = "btd142.crl";
	QCOMPARE(errorCode([&]() { Database.importItems(ctx, spec); }),
		QString("database_error"));
	sql("DROP TRIGGER temp.btd142_revocations");

	QCOMPARE(sqlValue("SELECT COUNT(*) FROM crls").toInt(), 0);
	QCOMPARE(sqlValue("SELECT COUNT(*) FROM revocations").toInt(), 0);
	QCOMPARE(entries("object.import", "success"), imports);
	lastFailure("object.import");
	QVERIFY(AuditLog::verify().ok());
}

/* Export: the nested commit of its first audit entry rolls back. On
 * 8dc1c2cf exportItems() returned the bytes, renamed the file into
 * place and left no audit entry. */
void test_service_transaction::exportNestedRollback()
{
	pki_key *key = newKey("BTD-142 export");
	QVERIFY(key);
	QString name = dir.filePath("export.pem");
	int exports = entries("object.export", "success");

	ExportSpec spec;
	spec.items << key;
	spec.clipboard = true;
	spec.fileName = name;
	DbTransaction::injectNestedRollback();
	QCOMPARE(errorCode([&]() {
		Database.model<db_key>()->exportItems(ctx, spec); }),
		QString("database_error"));

	QVERIFY(!QFile::exists(name));
	QCOMPARE(entries("object.export", "success"), exports);
	lastFailure("object.export");
}

/* A db_base write: removeItem()'s nested commit rolls back. On 8dc1c2cf
 * deleteItems() reported the key as deleted and it stayed in the
 * database. The key is gone from memory all the same (BTD-130). */
void test_service_transaction::deleteNestedRollback()
{
	pki_key *key = newKey("BTD-142 delete");
	QVERIFY(key);
	QCOMPARE(sqlValue("SELECT COUNT(*) FROM items "
		"WHERE name='BTD-142 delete'").toInt(), 1);

	DbTransaction::injectNestedRollback();
	QCOMPARE(errorCode([&]() {
		Database.model<db_key>()->deleteItems(ctx, { key }); }),
		QString("database_error"));

	QCOMPARE(sqlValue("SELECT COUNT(*) FROM items "
		"WHERE name='BTD-142 delete'").toInt(), 1);
	QCOMPARE(entries("object.delete", "success"), 0);
	lastFailure("object.delete");
}

/* A service function through auditedTransaction() */
void test_service_transaction::renameNestedRollback()
{
	pki_key *key = newKey("BTD-142 old");
	QVERIFY(key);

	DbTransaction::injectNestedRollback();
	QCOMPARE(errorCode([&]() {
		Database.model<db_key>()->rename(ctx, key, "BTD-142 new"); }),
		QString("database_error"));

	QCOMPARE(key->getIntName(), QString("BTD-142 old"));
	QCOMPARE(sqlValue("SELECT COUNT(*) FROM items "
		"WHERE name='BTD-142 new'").toInt(), 0);
	QCOMPARE(entries("object.rename", "success"), 0);
	lastFailure("object.rename");
}

/* The template stays in memory until BTD-130 */
void test_service_transaction::templateNestedRollback()
{
	TemplateSpec spec;
	spec.name = "BTD-142 template";

	DbTransaction::injectNestedRollback();
	QCOMPARE(errorCode([&]() {
		Database.model<db_temp>()->newTemplate(ctx, spec); }),
		QString("database_error"));

	QCOMPARE(sqlValue("SELECT COUNT(*) FROM templates").toInt(), 0);
	QCOMPARE(entries("template.create", "success"), 0);
	lastFailure("template.create");
}

/* The automatic checkpoint behind the rename's entry: its nested commit
 * rolls back (the entry's own commit is skipped). The failure entry
 * that follows gets its checkpoint. */
void test_service_transaction::checkpointNestedRollback()
{
	pki_key *key = newKey("BTD-142 old");
	QVERIFY(key);
	QVERIFY(AuditLog::entries().last().action !=
		QString(AuditLog::actionCheckpoint));
	Settings["audit_checkpoint_interval"] =
		(int)AuditLog::entries().size() + 1;

	DbTransaction::injectNestedRollback(1);
	QCOMPARE(errorCode([&]() {
		Database.model<db_key>()->rename(ctx, key, "BTD-142 new"); }),
		QString("database_error"));

	QCOMPARE(sqlValue("SELECT COUNT(*) FROM items "
		"WHERE name='BTD-142 new'").toInt(), 0);
	QCOMPARE(entries("object.rename", "success"), 0);
	QCOMPARE(entries("object.rename", "failure"), 1);
	AuditVerifyResult r = AuditLog::verify();
	QVERIFY2(r.ok(), r.toJson().constData());
}

/* An audit append outside any transaction whose COMMIT fails (a
 * deferred foreign key, checked only at COMMIT): append() threw nothing
 * on 8dc1c2cf and returned an entry that was rolled back. */
void test_service_transaction::appendCommitFails()
{
	sql("PRAGMA foreign_keys=ON");
	sql("CREATE TEMP TABLE btd142_parent (id INTEGER PRIMARY KEY)");
	sql("CREATE TEMP TABLE btd142_child (p INTEGER REFERENCES "
		"btd142_parent(id) DEFERRABLE INITIALLY DEFERRED)");
	sql("CREATE TEMP TRIGGER btd142_commit AFTER INSERT ON audit_log "
		"BEGIN INSERT INTO btd142_child VALUES (42); END");
	int before = AuditLog::entries().size();

	warning->expectMessage("FOREIGN KEY");
	QString code = errorCode([&]() {
		AuditLog::append(ctx, "object.rename", "key", "1",
			AuditParams().set("name", "BTD-142"));
	});
	sql("DROP TRIGGER temp.btd142_commit");
	QVERIFY2(code.startsWith("errorEx: "), CCHAR(code));
	QCOMPARE(AuditLog::entries().size(), before);
	QCOMPARE(sqlValue("SELECT COUNT(*) FROM btd142_child").toInt(), 0);
}

/* A failing statement of the fork's schema update: initSqlDB() rolls back
 * and returns the error. On 31a33a95 both callers in
 * database_model::open() ignored it and the database opened half
 * upgraded. */
void test_service_transaction::schemaUpdateFailureStopsOpen()
{
	Database.close();
	{
		QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "btd142");
		db.setDatabaseName(dbFile);
		QVERIFY(db.open());
		QSqlQuery q(db);
		for (const char *statement : {
			"DROP INDEX i_audit_log_action",
			"DROP TABLE audit_keys",
			"UPDATE settings SET value='1' WHERE key_='bxc_schema'",
			"CREATE TRIGGER btd142_schema BEFORE UPDATE ON settings "
			"WHEN NEW.key_='bxc_schema' BEGIN SELECT RAISE(ABORT, "
			"'BTD-142 test: schema update refused'); END" })
			QVERIFY2(q.exec(statement), CCHAR(q.lastError().text()));
		db.close();
	}
	QSqlDatabase::removeDatabase("btd142");

	pwdialog->expect(dbPassword);
	QString code = errorCode([&]() { Database.open(dbFile); });
	QVERIFY2(code.contains("schema update refused"), CCHAR(code));
	QVERIFY(!Database.isOpen());

	QString version;
	bool keysTable = true;
	{
		QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "btd142");
		db.setDatabaseName(dbFile);
		QVERIFY(db.open());
		QSqlQuery q(db);
		q.exec("SELECT value FROM settings WHERE key_='bxc_schema'");
		if (q.next())
			version = q.value(0).toString();
		q.exec("SELECT COUNT(*) FROM sqlite_master WHERE name='audit_keys'");
		keysTable = q.next() && q.value(0).toInt() > 0;
		db.close();
	}
	QSqlDatabase::removeDatabase("btd142");
	QCOMPARE(version, QString("1"));
	QVERIFY(!keysTable);
}

/* The nested settings::set() of the new hash commits at once in memory;
 * on 31a33a95 a rolled-back password change left Settings["pwhash"] at
 * the new hash while the database kept the old one, so the next change
 * asked for a password that was never applied. */
void test_service_transaction::passwordChangeRollbackKeepsOld()
{
	QVERIFY(newKey("BTD-142 key"));
	QString oldHash = Settings["pwhash"];
	QVERIFY(!oldHash.isEmpty());
	Passwd pass;
	pass = "BTD-142-new-password";

	DbTransaction::injectNestedRollback();
	QString code = errorCode([&]() {
		Database.model<db_key>()->changeDatabasePassword(pass); });
	QVERIFY2(code.startsWith("errorEx: "), CCHAR(code));

	QCOMPARE(QString(Settings["pwhash"]), oldHash);
	QCOMPARE(pki_evp::passHash, oldHash);
	QCOMPARE(sqlValue("SELECT value FROM settings WHERE key_='pwhash'")
		.toString(), oldHash);
}

/* A TransRollback() after the commit of the same transaction: on
 * 31a33a95 it raised the error counter anyway, and the next, unrelated
 * transaction rolled back */
void test_service_transaction::strayRollbackDoesNotLeak()
{
	sql("CREATE TABLE btd142 (x INTEGER)");
	{
		Transaction;
		QVERIFY(TransBegin());
		QVERIFY(TransCommit());
		QVERIFY(TransRollback());
	}
	{
		Transaction;
		QVERIFY(TransBegin());
		sql("INSERT INTO btd142 VALUES (1)");
		QVERIFY(TransCommit());
	}
	QCOMPARE(sqlValue("SELECT COUNT(*) FROM btd142").toInt(), 1);
}

XCA_SERVICE_TEST_MAIN(test_service_transaction)
#include "test_service_transaction.moc"
