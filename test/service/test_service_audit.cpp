/* vi: set sw=4 ts=4:
 *
 * Audit log core (BTD-29): schema upgrade, hash chain, tamper detection,
 * secret protection, JSON Lines export and the revocation cross-check.
 */

#include <openssl/evp.h>
#include <openssl/pem.h>

#include <QCryptographicHash>
#include <QDirIterator>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QSqlDatabase>
#include <QSqlQuery>

#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/db_key.h"
#include "lib/exception.h"
#include "lib/pki_evp.h"

#include "ServiceTestCase.h"

class test_service_audit : public ServiceTestCase
{
	Q_OBJECT

	/* Direct SQL on the open database, bypassing XCA: what an attacker
	 * with sqlite3 can do */
	static void sql(const QString &statement)
	{
		QSqlQuery q(QSqlDatabase::database());
		QVERIFY2(q.exec(statement), CCHAR(q.lastError().text() +
					": " + statement));
	}
	static QVariant sqlValue(const QString &statement)
	{
		QSqlQuery q(QSqlDatabase::database());
		if (!q.exec(statement) || !q.next())
			return QVariant();
		return q.value(0);
	}
	static QMap<QString, QStringList> tableRows(QSqlDatabase db);
	static void appendSample(int count);
	static QDateTime utc(const QString &iso)
	{
		return QDateTime::fromString(iso, Qt::ISODate);
	}
	void insertRevocation();

  private slots:
	void upgradeForkDatabase();
	void canonicalJson();
	void chainHashVector();
	void chainValid();
	void tamper_data();
	void tamper();
	void appendRejectsInvalidEntries();
	void noSecretsInEntryOrExport();
	void allowListCarriesNoSecrets();
	void exportJsonLines();
	void revocationCrossCheck_data();
	void revocationCrossCheck();
	void revocationAfterUnrevoke();
	void unauditedRevocationIsNoMismatch();
	void libHasNoAuditUpdateOrDelete();
};

static const ServiceContext cliAlice(ServiceContext::cli, "os:alice");

/* Every row of every table as text, sorted per table */
QMap<QString, QStringList> test_service_audit::tableRows(QSqlDatabase db)
{
	QMap<QString, QStringList> rows;
	QStringList tables;
	QSqlQuery q(db);

	q.exec("SELECT name FROM sqlite_master WHERE type='table'");
	while (q.next())
		tables << q.value(0).toString();
	for (const QString &t : tables) {
		QSqlQuery c(db);
		c.exec(QString("SELECT * FROM %1").arg(t));
		rows[t] = QStringList();
		while (c.next()) {
			QStringList cols;
			for (int i = 0; i < c.record().count(); i++)
				cols << c.value(i).toString();
			rows[t] << cols.join("|");
		}
		rows[t].sort();
	}
	return rows;
}

void test_service_audit::appendSample(int count)
{
	for (int i = 1; i <= count; i++) {
		AuditParams p;
		p.set("name", QString("key-%1").arg(i)).set("key_size", 2048);
		AuditLog::append(cliAlice, "key.generate", "key",
				QString::number(i), p);
	}
}

void test_service_audit::upgradeForkDatabase()
{
	/* service.xdb is replaced by the dump of a database that the
	 * unmodified fork (bxc-main 119d539, schema 8) created: two keys,
	 * a CA certificate, a CRL and one revocation (data/README.md) */
	Database.close();
	QVERIFY(QFile::remove(dbFile));

	QMap<QString, QStringList> before;
	{
		QFile dump(SERVICE_TEST_DATA "/schema8-fork.sql");
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
		QSqlQuery s(db);
		QVERIFY(s.exec("SELECT value FROM settings WHERE key_='schema'"));
		QVERIFY(s.next());
		QCOMPARE(s.value(0).toString(), QString("8"));
		before = tableRows(db);
		db.close();
	}
	QSqlDatabase::removeDatabase("fixture");
	QVERIFY(!before.contains("audit_log"));
	QCOMPARE(before["items"].size(), 4);
	QCOMPARE(before["revocations"].size(), 1);

	openDatabase();
	QCOMPARE(sqlValue("SELECT value FROM settings WHERE key_='schema'")
			.toString(), QString("9"));

	/* Every row is unchanged. In settings only the schema version
	 * differs, plus the option the harness sets on each open. */
	QMap<QString, QStringList> after = tableRows(QSqlDatabase::database());
	QCOMPARE(after.take("audit_log"), QStringList());
	QStringList settingsBefore = before.take("settings");
	QStringList settingsAfter = after.take("settings");
	QCOMPARE(after, before);
	settingsBefore.replaceInStrings(QRegularExpression("^schema\\|8$"),
			"schema|9");
	settingsAfter.removeIf([](const QString &s) {
		return s.startsWith("suppress_messages|");
	});
	QCOMPARE(settingsAfter, settingsBefore);

	/* The items load and the private keys still decrypt */
	QStringList names;
	for (pki_base *pki : Store.getAll<pki_base>())
		names << pki->getIntName();
	names.sort();
	QCOMPARE(names, QStringList({ "fixture-ca", "fixture-ca-key",
				"fixture-crl", "fixture-rsa" }));
	QList<pki_key*> keys = Store.getAll<pki_key>();
	QCOMPARE(keys.size(), 2);
	for (pki_key *key : keys) {
		QVERIFY(key->isPrivKey());
		EVP_PKEY *pkey = key->decryptKey();
		QVERIFY(pkey);
		EVP_PKEY_free(pkey);
	}

	/* The upgraded database takes audit entries; the old revocation
	 * has no entry and is counted, not reported as a mismatch */
	appendSample(2);
	reopenDatabase();
	AuditVerifyResult r = AuditLog::verify();
	QVERIFY(r.ok());
	QCOMPARE(r.entries, qint64(2));
	QCOMPARE(r.unauditedRevocations, qint64(1));
}

void test_service_audit::canonicalJson()
{
	QVariantMap m;
	m["b"] = 1;
	m["a"] = QString("x\n\"\\\x1f\xc3\xa4");
	m["c"] = QVariantList({ true, QVariant(), (qint64)-7 });
	m["B"] = QVariantMap({ { "z", false }, { "y", 2.0 } });
	QCOMPARE(AuditLog::canonicalJson(m), QByteArray(
		"{\"B\":{\"y\":2,\"z\":false},\"a\":\"x\\n\\\"\\\\\\u001f\xc3\xa4\","
		"\"b\":1,\"c\":[true,null,-7]}"));
	QCOMPARE(AuditLog::canonicalJson(QVariant((qint64)9007199254740991LL)),
		QByteArray("9007199254740991"));

	QVERIFY_THROWS_EXCEPTION(errorEx,
		AuditLog::canonicalJson(QVariant(1.5)));
	QVERIFY_THROWS_EXCEPTION(errorEx,
		AuditLog::canonicalJson(QVariant((qint64)9007199254740992LL)));
	QVERIFY_THROWS_EXCEPTION(errorEx,
		AuditLog::canonicalJson(QVariant(QByteArray("raw"))));
}

void test_service_audit::chainHashVector()
{
	/* Pins the hash input: raw 32 byte predecessor, then the JSON bytes.
	 * Values computed independently with Python hashlib. */
	QCOMPARE(AuditLog::chainHash(AuditLog::genesisHash, "{}"),
		QByteArray("fb1634c4e6cd4b1f1afe3ce2d6ef080f"
			   "7ac5d1f357d723ad4dfca782733b62db"));

	AuditEntry e;
	e.seq = 1;
	e.time = "2026-10-28T10:00:00Z";
	e.actor = "os:alice";
	e.channel = "cli";
	e.action = "key.generate";
	e.objectType = "key";
	e.objectId = "1";
	e.params = QVariantMap({ { "name", "k" } });
	e.result = "success";
	e.prevHash = AuditLog::genesisHash;
	QCOMPARE(e.canonical(), QByteArray("{\"action\":\"key.generate\","
		"\"actor\":\"os:alice\",\"channel\":\"cli\",\"error_code\":null,"
		"\"object_id\":\"1\",\"object_type\":\"key\","
		"\"params\":{\"name\":\"k\"},\"result\":\"success\",\"seq\":1,"
		"\"time\":\"2026-10-28T10:00:00Z\"}"));
	QCOMPARE(e.computeHash(),
		QByteArray("985ddd15737743ad6a0ffbe34e2dd264"
			   "76d683f2e1578a86c34a54fe8c51db16"));
}

void test_service_audit::chainValid()
{
	AuditVerifyResult r = AuditLog::verify();
	QVERIFY(r.ok());
	QCOMPARE(r.entries, qint64(0));

	appendSample(5);
	QList<AuditEntry> list = AuditLog::entries();
	QCOMPARE(list.size(), 5);
	QByteArray prev = AuditLog::genesisHash;
	for (int i = 0; i < list.size(); i++) {
		QCOMPARE(list[i].seq, (qint64)i + 1);
		QCOMPARE(list[i].prevHash, prev);
		QCOMPARE(list[i].hash, list[i].computeHash());
		QCOMPARE(list[i].actor, QString("os:alice"));
		QCOMPARE(list[i].channel, QString("cli"));
		prev = list[i].hash;
	}

	/* Persisted, and still intact after reopening */
	reopenDatabase();
	r = AuditLog::verify();
	QVERIFY(r.ok());
	QCOMPARE(r.entries, qint64(5));
	QCOMPARE(r.verifiedEntries, qint64(5));
	QCOMPARE(r.firstBrokenSeq, qint64(0));

	/* The local user context names the OS account */
	ServiceContext gui = ServiceContext::localUser(ServiceContext::gui);
	QCOMPARE(gui.channelName(), QString("gui"));
	QCOMPARE(gui.actor(), "os:" + ServiceContext::osUser());
	QCOMPARE(AuditLog::append(gui, "test", "none", "").seq, qint64(6));
}

void test_service_audit::tamper_data()
{
	QTest::addColumn<QStringList>("statements");
	QTest::addColumn<bool>("rehash");
	QTest::addColumn<qint64>("firstBroken");
	QTest::addColumn<QString>("reason");

	QTest::newRow("delete") << QStringList({
		"DELETE FROM audit_log WHERE seq=3" })
		<< false << (qint64)3 << "missing";
	QTest::newRow("change actor") << QStringList({
		"UPDATE audit_log SET actor='os:mallory' WHERE seq=3" })
		<< false << (qint64)3 << "hash";
	QTest::newRow("change params") << QStringList({
		"UPDATE audit_log SET params='{\"name\":\"other\"}' WHERE seq=3" })
		<< false << (qint64)3 << "hash";
	QTest::newRow("params no JSON") << QStringList({
		"UPDATE audit_log SET params='garbage' WHERE seq=3" })
		<< false << (qint64)3 << "hash";
	QTest::newRow("swap") << QStringList({
		"UPDATE audit_log SET seq=-2 WHERE seq=2",
		"UPDATE audit_log SET seq=2 WHERE seq=3",
		"UPDATE audit_log SET seq=3 WHERE seq=-2" })
		<< false << (qint64)2 << "prev_hash";
	/* The attacker also recomputes the hash of the changed entry:
	 * its successor no longer links to it */
	QTest::newRow("change and rehash") << QStringList({
		"UPDATE audit_log SET object_id='99' WHERE seq=3" })
		<< true << (qint64)4 << "prev_hash";
	QTest::newRow("delete first") << QStringList({
		"DELETE FROM audit_log WHERE seq=1" })
		<< false << (qint64)1 << "missing";
}

void test_service_audit::tamper()
{
	QFETCH(QStringList, statements);
	QFETCH(bool, rehash);
	QFETCH(qint64, firstBroken);
	QFETCH(QString, reason);

	appendSample(5);
	QVERIFY(AuditLog::verify().ok());

	for (const QString &s : statements)
		sql(s);
	if (rehash) {
		for (const AuditEntry &e : AuditLog::entries()) {
			if (e.seq == 3)
				sql(QString("UPDATE audit_log SET hash='%1' WHERE seq=3")
					.arg(QString::fromLatin1(e.computeHash())));
		}
	}

	AuditVerifyResult r = AuditLog::verify();
	QVERIFY(!r.ok());
	QVERIFY(!r.chainOk());
	QCOMPARE(r.firstBrokenSeq, firstBroken);
	QCOMPARE(r.reason, reason);
	QCOMPARE(r.verifiedEntries, firstBroken - 1);
	QVERIFY(r.toJson().contains(
		QString("\"first_broken_seq\":%1").arg(firstBroken).toUtf8()));
}

void test_service_audit::appendRejectsInvalidEntries()
{
	appendSample(1);
	QVERIFY_THROWS_EXCEPTION(errorEx,
		AuditLog::append(cliAlice, "", "key", "1"));
	QVERIFY_THROWS_EXCEPTION(errorEx,
		AuditLog::append(cliAlice, "key.generate", "key", "1",
				AuditParams(), "maybe"));
	AuditVerifyResult r = AuditLog::verify();
	QVERIFY(r.ok());
	QCOMPARE(r.entries, qint64(1));
}

void test_service_audit::noSecretsInEntryOrExport()
{
	/* A password-carrying operation: a key encrypted with the database
	 * password, exported with a transport password. The caller hands
	 * everything it has to the audit log; only the allow-list survives. */
	pki_key *key = Database.model<db_key>()->newKey(
				keyjob("EC:prime256v1"), "secret-key");
	QVERIFY(key);
	EVP_PKEY *pkey = key->decryptKey();
	QVERIFY(pkey);
	BIO *bio = BIO_new(BIO_s_mem());
	QVERIFY(PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL));
	char *data;
	long len = BIO_get_mem_data(bio, &data);
	QString pem = QString::fromLatin1(data, len);
	BIO_free(bio);
	EVP_PKEY_free(pkey);
	QStringList pemLines = pem.split('\n', Qt::SkipEmptyParts);
	QVERIFY(pemLines.size() >= 3);
	QString pemBody = pemLines[1];

	const QString transport = "transport-pw-4711";
	const QString pin = "246810";
	const QString challenge = "challenge-pw-1357";
	QVariantMap call;
	call["name"] = "secret-key";
	call["format"] = "PKCS#8";
	call["password"] = transport;
	call["export_password"] = transport;
	call["db_password"] = QString(dbPassword);
	call["pin"] = pin;
	call["private_key"] = pem;
	call["challenge_password"] = challenge;
	call["key_der"] = QByteArray("\x30\x82\x01\x00", 4);

	AuditParams params = AuditParams::fromMap(call);
	QStringList dropped = params.dropped();
	dropped.sort();
	QCOMPARE(dropped, QStringList({ "challenge_password", "db_password",
			"export_password", "key_der", "password", "pin",
			"private_key" }));
	QCOMPARE(params.getValues().keys(), QStringList({ "format", "name" }));
	params.set("password", transport).set("pin", pin);
	QCOMPARE(params.getValues().keys(), QStringList({ "format", "name" }));

	AuditLog::append(cliAlice, "key.export", "key",
			key->getSqlItemId().toString(), params);

	QString row;
	QSqlQuery q(QSqlDatabase::database());
	QVERIFY(q.exec("SELECT * FROM audit_log"));
	while (q.next())
		for (int i = 0; i < q.record().count(); i++)
			row += q.value(i).toString() + "|";
	QByteArray exported = AuditLog::exportJsonLines();
	QVERIFY(row.contains("secret-key"));
	QVERIFY(exported.contains("secret-key"));

	for (const QString &secret : { transport, pin, challenge,
				QString(dbPassword), pemBody,
				QString("PRIVATE KEY") }) {
		QVERIFY2(!row.contains(secret), CCHAR("stored: " + secret));
		QVERIFY2(!exported.contains(secret.toUtf8()),
			CCHAR("exported: " + secret));
	}
	QVERIFY(AuditLog::verify().ok());
}

void test_service_audit::allowListCarriesNoSecrets()
{
	QRegularExpression secret("pass|pin|secret|private|challenge|pwd",
			QRegularExpression::CaseInsensitiveOption);
	for (const QString &key : AuditParams::allowList())
		QVERIFY2(!secret.match(key).hasMatch(), CCHAR(key));
}

void test_service_audit::exportJsonLines()
{
	appendSample(2);
	AuditLog::append(ServiceContext(ServiceContext::rest, "apikey:k-17"),
			"cert.issue", "cert", "", AuditParams(), "failure",
			"E_POLICY");

	QByteArray out = AuditLog::exportJsonLines();
	QVERIFY(out.endsWith('\n'));
	QList<QByteArray> lines = out.split('\n');
	lines.removeLast();
	QCOMPARE(lines.size(), 3);

	const QStringList fields { "action", "actor", "channel", "error_code",
		"hash", "object_id", "object_type", "params", "prev_hash",
		"result", "seq", "time" };
	QRegularExpression rfc3339(
		"^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d{3})?Z$");
	QByteArray prev = AuditLog::genesisHash;
	for (int i = 0; i < lines.size(); i++) {
		QJsonParseError err;
		QJsonDocument doc = QJsonDocument::fromJson(lines[i], &err);
		QVERIFY2(doc.isObject(), CCHAR(err.errorString()));
		QVariantMap m = doc.toVariant().toMap();
		QCOMPARE(QStringList(m.keys()), fields);
		QCOMPARE(m["seq"].toLongLong(), (qint64)i + 1);
		QVERIFY2(rfc3339.match(m["time"].toString()).hasMatch(),
			CCHAR(m["time"].toString()));
		QVERIFY(QDateTime::fromString(m["time"].toString(),
				Qt::ISODate).isValid());

		/* Each line is canonical and verifiable on its own */
		QCOMPARE(AuditLog::canonicalJson(m), lines[i]);
		QCOMPARE(m["prev_hash"].toString().toLatin1(), prev);
		QByteArray hash = m.take("hash").toString().toLatin1();
		m.remove("prev_hash");
		QCOMPARE(AuditLog::chainHash(prev, AuditLog::canonicalJson(m)),
			hash);
		prev = hash;
	}
	QVariantMap last = QJsonDocument::fromJson(lines[2]).toVariant().toMap();
	QCOMPARE(last["actor"].toString(), QString("apikey:k-17"));
	QCOMPARE(last["channel"].toString(), QString("rest"));
	QCOMPARE(last["result"].toString(), QString("failure"));
	QCOMPARE(last["error_code"].toString(), QString("E_POLICY"));
	QVariantMap first = QJsonDocument::fromJson(lines[0]).toVariant().toMap();
	QVERIFY(first["error_code"].isNull());
	QCOMPARE(first["params"].toMap()["key_size"].toLongLong(), qint64(2048));
}

/* What BTD-33 will do on revocation, here as a minimal insert:
 * the row in XCA's format and the audit entry with its state */
void test_service_audit::insertRevocation()
{
	sql("INSERT INTO revocations (caId, serial, date, invaldate, crlNo, "
		"reasonBit) VALUES (1, '0A1B', '20261028100000Z', "
		"'20261027000000Z', NULL, 1)");
	AuditLog::append(cliAlice, AuditLog::actionRevoke, "cert", "0A1B",
		AuditParams::revocation(1, "0a1b", 1,
			utc("2026-10-28T10:00:00Z"), utc("2026-10-27T00:00:00Z")));
}

void test_service_audit::revocationCrossCheck_data()
{
	QTest::addColumn<QString>("statement");
	QTest::addColumn<QString>("field");
	QTest::addColumn<QString>("expected");
	QTest::addColumn<QString>("actual");

	QTest::newRow("date") << "UPDATE revocations SET date='20261101000000Z'"
		<< "date" << "2026-10-28T10:00:00Z" << "2026-11-01T00:00:00Z";
	QTest::newRow("invalidity date")
		<< "UPDATE revocations SET invaldate='99991231235959Z'"
		<< "invaldate" << "2026-10-27T00:00:00Z" << "";
	QTest::newRow("reason") << "UPDATE revocations SET reasonBit=4"
		<< "reasonBit" << "1" << "4";
	QTest::newRow("crl number") << "UPDATE revocations SET crlNo=9"
		<< "crlNo" << "5" << "9";
	QTest::newRow("row deleted") << "DELETE FROM revocations"
		<< "row" << "present" << "absent";
}

void test_service_audit::revocationCrossCheck()
{
	QFETCH(QString, statement);
	QFETCH(QString, field);
	QFETCH(QString, expected);
	QFETCH(QString, actual);

	insertRevocation();
	AuditVerifyResult r = AuditLog::verify();
	QVERIFY(r.ok());
	QCOMPARE(r.unauditedRevocations, qint64(0));

	/* CRL 5 picks up the pending revocation (db_crl::newCrl) */
	sql("UPDATE revocations SET crlNo=5 WHERE crlNo IS NULL AND caId=1");
	AuditLog::append(cliAlice, AuditLog::actionCrlGenerate, "crl", "",
		AuditParams::crl(1, 5));
	r = AuditLog::verify();
	QVERIFY2(r.ok(), r.toJson().constData());

	sql(statement);
	r = AuditLog::verify();
	QVERIFY(r.chainOk());
	QVERIFY(!r.ok());
	QCOMPARE(r.mismatches.size(), 1);
	const AuditStateMismatch &m = r.mismatches[0];
	QCOMPARE(m.caId, qint64(1));
	QCOMPARE(m.serial, QString("0A1B"));
	QCOMPARE(m.field, field);
	QCOMPARE(m.expected, expected);
	QCOMPARE(m.actual, actual);
	QCOMPARE(m.seq, qint64(2));
	QVERIFY(r.toJson().contains("\"state_mismatches\":[{"));
}

void test_service_audit::revocationAfterUnrevoke()
{
	insertRevocation();
	sql("DELETE FROM revocations WHERE serial='0A1B'");
	AuditLog::append(cliAlice, AuditLog::actionUnrevoke, "cert", "0A1B",
		AuditParams::unrevocation(1, "0A1B"));
	QVERIFY(AuditLog::verify().ok());

	/* Revocation put back with sqlite after the unrevoke */
	sql("INSERT INTO revocations (caId, serial, date, invaldate, crlNo, "
		"reasonBit) VALUES (1, '0A1B', '20261028100000Z', "
		"'20261027000000Z', NULL, 1)");
	AuditVerifyResult r = AuditLog::verify();
	QVERIFY(!r.ok());
	QCOMPARE(r.mismatches.size(), 1);
	QCOMPARE(r.mismatches[0].field, QString("row"));
	QCOMPARE(r.mismatches[0].expected, QString("absent"));
	QCOMPARE(r.mismatches[0].seq, qint64(2));
}

void test_service_audit::unauditedRevocationIsNoMismatch()
{
	insertRevocation();
	sql("INSERT INTO revocations (caId, serial, date, invaldate, crlNo, "
		"reasonBit) VALUES (1, '0C0D', '20261028100000Z', "
		"'99991231235959Z', NULL, 0)");
	AuditVerifyResult r = AuditLog::verify();
	QVERIFY(r.ok());
	QCOMPARE(r.unauditedRevocations, qint64(1));

	/* State after a broken link is not trusted: only entries before
	 * the break are replayed */
	sql("UPDATE audit_log SET actor='os:mallory' WHERE seq=1");
	r = AuditLog::verify();
	QVERIFY(!r.chainOk());
	QCOMPARE(r.verifiedEntries, qint64(0));
	QCOMPARE(r.unauditedRevocations, qint64(2));
}

void test_service_audit::libHasNoAuditUpdateOrDelete()
{
	/* Acceptance criterion: lib/ offers no way to change or remove an
	 * entry. Guard against a future UPDATE/DELETE on the table. */
	QRegularExpression write("\\b(UPDATE|DELETE\\s+FROM|DROP\\s+TABLE|"
		"ALTER\\s+TABLE|REPLACE\\s+INTO)\\s+audit_log\\b",
		QRegularExpression::CaseInsensitiveOption);
	int files = 0;
	QDirIterator it(XCA_LIB_DIR, { "*.cpp", "*.h" }, QDir::Files);
	while (it.hasNext()) {
		QFile f(it.next());
		QVERIFY(f.open(QIODevice::ReadOnly));
		QString src = QString::fromUtf8(f.readAll());
		QVERIFY2(!write.match(src).hasMatch(), CCHAR(f.fileName()));
		files++;
	}
	QVERIFY(files > 50);
}

XCA_SERVICE_TEST_MAIN(test_service_audit)
#include "test_service_audit.moc"
