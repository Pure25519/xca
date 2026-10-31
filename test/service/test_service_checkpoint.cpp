/* vi: set sw=4 ts=4:
 *
 * Signed audit checkpoints (BTD-37): checkpoint every N entries and on
 * export, verify() against a recomputed chain, the audit key refused for
 * certificates, requests and CRLs, the exported signatures checked with
 * the openssl program, and key rotation. Tampered checkpoint structures
 * (BTD-110): removed checkpoints and keys, a checkpoint that does not
 * sign its predecessor, changed checkpoint metadata, a missing key.
 * A failing automatic checkpoint never takes the caller's change with
 * it, and never asks for the password (BTD-111).
 */

#include <QThread>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QProcess>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlRecord>
#include <QTemporaryDir>

#include <cstring>
#include <functional>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "lib/BioByteArray.h"
#include "lib/PwDialogCore.h"
#include "lib/audit.h"
#include "lib/audit_key.h"
#include "lib/database_model.h"
#include "lib/db_crl.h"
#include "lib/db_key.h"
#include "lib/db_x509.h"
#include "lib/db_x509req.h"
#include "lib/entropy.h"
#include "lib/exception.h"
#include "lib/importexport.h"
#include "lib/issuance.h"
#include "lib/pki_crl.h"
#include "lib/pki_evp.h"
#include "lib/pki_export.h"
#include "lib/pki_x509.h"
#include "lib/pki_x509req.h"
#include "lib/request.h"
#include "lib/settings.h"

#include "ServiceTestCase.h"

class test_service_checkpoint : public ServiceTestCase
{
	Q_OBJECT

	ServiceContext ctx{ ServiceContext::cli, "os:service-test" };
	QTemporaryDir dir{};

	/* What an attacker with sqlite3 can do */
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
	void appendSample(int count);
	static QMap<QString, QStringList> tableRows();
	static QList<AuditEntry> byAction(const QString &action);
	static void recomputeFrom(qint64 seq);
	static void renumber();
	static void removeCheckpoints(bool keys);
	static void setParams(qint64 seq, const QVariantMap &params);
	static AuditEntry forgeEntry(const QString &action,
			const QString &objectId, const QVariantMap &params);
	static EVP_PKEY *auditPrivateKey();
	static QByteArray publicPem(EVP_PKEY *pkey);
	static QString signature(EVP_PKEY *pkey, const QVariantMap &params);
	static QString errorCode(std::function<void()> call);
	QString writeFile(const QString &name, const QByteArray &data);
	QString keyAtCheckpoint(int n, const QString &name);
#ifdef OPENSSL_PROGRAM
	QByteArray openssl(const QStringList &args, int *exitCode,
			const QByteArray &input = QByteArray());
	void opensslVerifiesExport(const QByteArray &jsonl, int expected);
#endif

  private slots:
	void checkpointEveryN();
	void checkpointAfterConfirmedOperation();
	void defaultInterval();
	void recomputedChain_data();
	void recomputedChain();
	void unannouncedKey();
	void tamperedStructure_data();
	void tamperedStructure();
	void unsignedTailLimit();
	void unannouncedKeyAlone();
	void forgedDeletionNotSigned();
	void intervalClamped();
	void adoptUnanchored_data();
	void adoptUnanchored();
	void baselineException_data();
	void baselineException();
	void missingCurrentKey_data();
	void missingCurrentKey();
	void auditKeyNotUsableForSigning();
	void exportSignsCheckpoint();
	void exportWithoutPassword();
	void exportWithWrongPassword();
	void noPasswordKeepsEntry();
	void checkpointFailureAfterWrite();
	void checkpointDatabaseErrorReachesCaller();
	void failureEntryKeepsErrorCode();
	void exportCheckpointWriteFails();
	void unusableKeyKeepsChange();
	void automaticCheckpointNeverAsks();
	void skippedCheckpointNotice();
	void skippedCheckpointNoticeMissingKey();
	void skippedCheckpointNoticeSigning();
	void neverSignsBrokenTail();
	void keyRotation();
	void pinRewrittenLog();
	void pinFollowsRotation();
	void pinMinCheckpoint();
	void passwordChange();
	void reservedActions();
	void opensslCli();
};

void test_service_checkpoint::appendSample(int count)
{
	for (int i = 1; i <= count; i++) {
		AuditParams p;
		p.set("name", QString("key-%1").arg(i));
		AuditLog::append(ctx, "key.generate", "key",
				QString::number(i), p);
	}
}

/* Every row of every table as text, sorted per table */
QMap<QString, QStringList> test_service_checkpoint::tableRows()
{
	QMap<QString, QStringList> rows;
	QSqlQuery q(QSqlDatabase::database());

	q.exec("SELECT name FROM sqlite_master WHERE type='table'");
	while (q.next()) {
		QSqlQuery c(QSqlDatabase::database());
		c.exec(QString("SELECT * FROM %1").arg(q.value(0).toString()));
		QStringList list;
		while (c.next()) {
			QStringList cols;
			for (int i = 0; i < c.record().count(); i++)
				cols << c.value(i).toString();
			list << cols.join("|");
		}
		list.sort();
		rows[q.value(0).toString()] = list;
	}
	return rows;
}

QList<AuditEntry> test_service_checkpoint::byAction(const QString &action)
{
	QList<AuditEntry> list;
	for (const AuditEntry &e : AuditLog::entries())
		if (e.action == action)
			list << e;
	return list;
}

/* Recomputes prev_hash and hash from entry seq on, as an attacker who
 * changed entry seq would */
void test_service_checkpoint::recomputeFrom(qint64 seq)
{
	QByteArray prev = AuditLog::genesisHash;
	for (AuditEntry e : AuditLog::entries()) {
		if (e.seq >= seq) {
			e.prevHash = prev;
			e.hash = e.computeHash();
			sql(QString("UPDATE audit_log SET prev_hash='%1', hash='%2' "
				"WHERE seq=%3").arg(QString::fromLatin1(e.prevHash))
				.arg(QString::fromLatin1(e.hash)).arg(e.seq));
		}
		prev = e.hash;
	}
}

/* Closes the gaps of deleted entries: seq 1, 2, ... in the old order */
void test_service_checkpoint::renumber()
{
	qint64 seq = 1;
	for (const AuditEntry &e : AuditLog::entries())
		sql(QString("UPDATE audit_log SET seq=%1 WHERE seq=%2")
			.arg(seq++).arg(e.seq));
}

/* The review's reproduction of BTD-110: every checkpoint and announcement
 * gone (keys: audit_keys too), the rest renumbered and rehashed */
void test_service_checkpoint::removeCheckpoints(bool keys)
{
	sql(QString("DELETE FROM audit_log WHERE action IN ('%1','%2')")
		.arg(AuditLog::actionKeyCreate).arg(AuditLog::actionCheckpoint));
	if (keys)
		sql("DELETE FROM audit_keys");
	renumber();
	recomputeFrom(1);
}

void test_service_checkpoint::setParams(qint64 seq, const QVariantMap &params)
{
	sql(QString("UPDATE audit_log SET params='%1' WHERE seq=%2")
		.arg(QString::fromUtf8(AuditLog::canonicalJson(params))).arg(seq));
}

/* Appends a chained entry with sqlite3, bypassing append() and its
 * reserved actions */
AuditEntry test_service_checkpoint::forgeEntry(const QString &action,
		const QString &objectId, const QVariantMap &params)
{
	AuditEntry last = AuditLog::entries().last();
	AuditEntry e;
	e.seq = last.seq + 1;
	e.prevHash = last.hash;
	e.time = AuditLog::rfc3339(QDateTime::currentDateTimeUtc());
	e.actor = "os:mallory";
	e.channel = "cli";
	e.action = action;
	e.objectType = "audit_key";
	e.objectId = objectId;
	e.params = params;
	e.result = "success";
	e.hash = e.computeHash();
	QSqlQuery q(QSqlDatabase::database());
	q.prepare("INSERT INTO audit_log (seq, created, actor, channel, "
		"action, object_type, object_id, params, result, prev_hash, "
		"hash) VALUES (?,?,?,?,?,?,?,?,?,?,?)");
	q.addBindValue(e.seq);
	q.addBindValue(e.time);
	q.addBindValue(e.actor);
	q.addBindValue(e.channel);
	q.addBindValue(e.action);
	q.addBindValue(e.objectType);
	q.addBindValue(e.objectId);
	q.addBindValue(QString::fromUtf8(AuditLog::canonicalJson(e.params)));
	q.addBindValue(e.result);
	q.addBindValue(QString::fromLatin1(e.prevHash));
	q.addBindValue(QString::fromLatin1(e.hash));
	if (!q.exec())
		qWarning() << "forgeEntry:" << q.lastError().text();
	return e;
}

QByteArray test_service_checkpoint::publicPem(EVP_PKEY *pkey)
{
	BioByteArray pem;
	PEM_write_bio_PUBKEY(pem, pkey);
	return pem.byteArray();
}

/* The Base64 signature of a checkpoint with params, as signHead() makes it */
QString test_service_checkpoint::signature(EVP_PKEY *pkey,
					const QVariantMap &params)
{
	QByteArray data = AuditLog::checkpointPayload(params);
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	size_t len = 0;
	QByteArray sig;
	if (EVP_DigestSignInit_ex(ctx, NULL, NULL, NULL, NULL, pkey, NULL) &&
	    EVP_DigestSign(ctx, NULL, &len,
			(const unsigned char *)data.constData(), data.size())) {
		sig.resize(len);
		EVP_DigestSign(ctx, (unsigned char *)sig.data(), &len,
			(const unsigned char *)data.constData(), data.size());
		sig.resize(len);
	}
	EVP_MD_CTX_free(ctx);
	return QString::fromLatin1(sig.toBase64());
}

/* The current audit private key, read and decrypted from a copy of
 * audit_keys: what someone with the database file and its password has */
EVP_PKEY *test_service_checkpoint::auditPrivateKey()
{
	QByteArray der = QByteArray::fromBase64(sqlValue(
		"SELECT private FROM audit_keys WHERE retired=0").toByteArray());
	X509_SIG *p8 = d2i_PKCS8_bio(BioByteArray(der).ro(), NULL);
	if (!p8)
		return nullptr;
	PKCS8_PRIV_KEY_INFO *inf = PKCS8_decrypt(p8, dbPassword,
					strlen(dbPassword));
	X509_SIG_free(p8);
	if (!inf) {
		ERR_clear_error();
		return nullptr;
	}
	EVP_PKEY *pkey = EVP_PKCS82PKEY(inf);
	PKCS8_PRIV_KEY_INFO_free(inf);
	return pkey;
}

QString test_service_checkpoint::errorCode(std::function<void()> call)
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

QString test_service_checkpoint::writeFile(const QString &name,
					const QByteArray &data)
{
	QString path = dir.filePath(name);
	QFile f(path);
	if (f.open(QIODevice::WriteOnly))
		f.write(data);
	return path;
}

/* Calls db_key::newKey() so that its audit entry is entry n of the chain
 * and triggers the automatic checkpoint (interval n) */
QString test_service_checkpoint::keyAtCheckpoint(int n, const QString &name)
{
	Settings["audit_checkpoint_interval"] = n;
	appendSample(n - 1);
	return errorCode([&]() {
		Database.model<db_key>()->newKey(ctx,
				keyjob("EC:prime256v1"), name);
	});
}

void test_service_checkpoint::checkpointFailureAfterWrite()
{
	/* Fault injection: the key announced by the first checkpoint loses
	 * its private part as soon as the announcement is written, so the
	 * signature fails after the checkpoint's first write. On dfa29716
	 * that serviceError rolled back the nested transaction, append()
	 * swallowed it and newKey() returned the key: success with neither
	 * the key nor its entry in the database (BTD-111). */
	sql(QString("CREATE TRIGGER fault AFTER INSERT ON audit_log "
		"WHEN NEW.action='%1' BEGIN UPDATE audit_keys SET private=NULL; "
		"END").arg(AuditLog::actionKeyCreate));
	QCOMPARE(keyAtCheckpoint(3, "victim"), QString());

	reopenDatabase();
	QCOMPARE(sqlValue("SELECT COUNT(*) FROM items WHERE name='victim'")
			.toInt(), 1);
	QList<AuditEntry> list = AuditLog::entries();
	QCOMPARE(list.size(), 5);
	QCOMPARE(list[2].action, QString("key.generate"));
	QCOMPARE(list[2].objectType, QString("key"));
	QCOMPARE(list[4].action, QString(AuditLog::actionCheckpoint));
	AuditVerifyResult r = AuditLog::verify();
	QVERIFY2(r.ok(), r.toJson().constData());
}

void test_service_checkpoint::checkpointDatabaseErrorReachesCaller()
{
	/* A database error while the checkpoint writes rolls back the
	 * caller's transaction with it: the caller must see the failure */
	sql("CREATE TRIGGER fault BEFORE INSERT ON audit_keys BEGIN "
		"SELECT RAISE(ABORT, 'BTD-111 checkpoint write'); END");
	QString code = keyAtCheckpoint(3, "victim");
	QVERIFY2(code.startsWith("errorEx: "), CCHAR(code));
	/* the checkpoint's error, not one of newKey() (BTD-143) */
	QVERIFY2(code.contains("BTD-111 checkpoint write"), CCHAR(code));
	/* nor in memory: on 9121ddcd the key stayed in store and view
	 * with the id of its rolled-back row (BTD-130) */
	for (pki_key *key : Store.getAll<pki_key>())
		QVERIFY(key->getIntName() != "victim");
	QCOMPARE(Database.model<db_key>()->rowCount(),
		Store.getAll<pki_key>().size());

	reopenDatabase();
	QCOMPARE(sqlValue("SELECT COUNT(*) FROM items WHERE name='victim'")
			.toInt(), 0);
	QCOMPARE(sqlValue("SELECT COUNT(*) FROM audit_keys").toInt(), 0);
	/* the failure entry that newKey() appends after the rollback */
	QList<AuditEntry> list = AuditLog::entries();
	QCOMPARE(list.size(), 3);
	QCOMPARE(list[2].result, QString("failure"));
	QVERIFY(AuditLog::verify().ok());
}

/* The failure entry of a service function is appended after the
 * rollback, outside any transaction, and its checkpoint fails while
 * writing. On 9121ddcd append() threw that error anyway, and the caller
 * got "errorEx" instead of the function's own code (BTD-143). The entry
 * is committed; the next entry tries the checkpoint again. */
void test_service_checkpoint::failureEntryKeepsErrorCode()
{
	Settings["audit_checkpoint_interval"] = 3;
	appendSample(2);
	sql("CREATE TRIGGER fault BEFORE INSERT ON audit_keys BEGIN "
		"SELECT RAISE(ABORT, 'BTD-143 checkpoint write'); END");
	QString code = errorCode([&]() {
		Database.model<db_key>()->deleteItems(ctx, {});
	});
	QCOMPARE(code, QString("nothing_to_delete"));

	QList<AuditEntry> list = AuditLog::entries();
	QCOMPARE(list.size(), 3);
	QCOMPARE(list[2].action, QString("object.delete"));
	QCOMPARE(list[2].result, QString("failure"));
	QCOMPARE(list[2].errorCode, QString("nothing_to_delete"));
	QCOMPARE(byAction(AuditLog::actionCheckpoint).size(), 0);
	QVERIFY(AuditLog::verify().ok());

	sql("DROP TRIGGER fault");
	appendSample(1);
	QCOMPARE(byAction(AuditLog::actionCheckpoint).size(), 1);
}

/* An export appends its entries inside its own transaction, before the
 * file is written (BTD-114). A checkpoint that fails while writing rolls
 * that transaction back: the export fails, the file is not written, the
 * failure entry is kept (the BTD-111 rule, unchanged by BTD-143). */
void test_service_checkpoint::exportCheckpointWriteFails()
{
	pki_key *key = Database.model<db_key>()->newKey(ctx,
				keyjob("EC:prime256v1"), "BTD-143 key");
	QVERIFY(key);
	Settings["audit_checkpoint_interval"] =
		(int)AuditLog::entries().size() + 1;
	sql("CREATE TRIGGER fault BEFORE INSERT ON audit_keys BEGIN "
		"SELECT RAISE(ABORT, 'BTD-143 checkpoint write'); END");
	ExportSpec spec;
	spec.items << key;
	spec.format = pki_export::by_id(19);
	spec.fileName = dir.filePath("btd143.pem");
	QString code = errorCode([&]() {
		Database.model<db_key>()->exportItems(ctx, spec);
	});
	QVERIFY2(code.contains("BTD-143 checkpoint write"), CCHAR(code));
	/* neither the file nor a temporary file of QSaveFile */
	QCOMPARE(QDir(dir.path()).entryList({ "btd143.pem*" },
		QDir::Files | QDir::Hidden).size(), 0);
	QCOMPARE(byAction("object.export").size(), 1);
	QCOMPARE(byAction("object.export")[0].result, QString("failure"));
	QVERIFY(AuditLog::verify().ok());
}

void test_service_checkpoint::unusableKeyKeepsChange()
{
	/* An audit key that no longer decrypts: the automatic checkpoint is
	 * skipped before it writes, the key and its entry are stored, the
	 * next append tries again. On dfa29716 the call failed. */
	Settings["audit_checkpoint_interval"] = 3;
	appendSample(3);
	QCOMPARE(byAction(AuditLog::actionCheckpoint).size(), 1);
	sql("UPDATE audit_keys SET private='AAAA'");
	QCOMPARE(keyAtCheckpoint(4, "victim"), QString());

	reopenDatabase();
	QCOMPARE(sqlValue("SELECT COUNT(*) FROM items WHERE name='victim'")
			.toInt(), 1);
	QCOMPARE(byAction(AuditLog::actionCheckpoint).size(), 1);
	QCOMPARE(AuditLog::entries().size(), 9);
	/* An explicit checkpoint reports it */
	QVERIFY(errorCode([&]() { AuditLog::checkpoint(ctx); })
			.contains("decrypt"));
}

void test_service_checkpoint::automaticCheckpointNeverAsks()
{
	/* Database open without its password, e.g. the unlock dialog
	 * cancelled: the automatic checkpoints do not ask (any prompt is a
	 * violation of the strict dialog); explicit ones still do */
	Settings["audit_checkpoint_interval"] = 2;
	pki_evp::passwd.cleanse();
	appendSample(5);
	QVERIFY(byAction(AuditLog::actionCheckpoint).isEmpty());
	QCOMPARE(AuditLog::entries().size(), 5);

	pwdialog->expect("", pw_cancel);
	QCOMPARE(errorCode([&]() { AuditLog::checkpoint(ctx); }),
		QString("audit_key_unavailable"));
	pwdialog->expect("", pw_cancel);
	qint64 unsignedEntries = -1;
	AuditLog::exportJsonLines(ctx, &unsignedEntries);
	QCOMPARE(unsignedEntries, qint64(5));

	/* Explicit with the password: 5 unsigned entries are more than
	 * interval + 1, so only the adoption signs them (BTD-110) */
	pwdialog->expect(dbPassword);
	QCOMPARE(errorCode([&]() { AuditLog::checkpoint(ctx); }),
		QString("audit_checkpoint_missing"));
	pwdialog->expect(dbPassword);
	AuditLog::adoptUnanchored(ctx);
	QCOMPARE(byAction(AuditLog::actionCheckpoint).size(), 1);
	AuditVerifyResult r = AuditLog::verify();
	QVERIFY2(r.ok(), r.toJson().constData());
	QCOMPARE(r.adoptedEntries, qint64(5));
}

void test_service_checkpoint::checkpointEveryN()
{
	Settings["audit_checkpoint_interval"] = 5;
	QCOMPARE(AuditLog::checkpointInterval(), 5);
	appendSample(4);
	QVERIFY(byAction(AuditLog::actionCheckpoint).isEmpty());
	QCOMPARE(sqlValue("SELECT COUNT(*) FROM audit_keys").toInt(), 0);

	/* The fifth entry: key created on first use, announced, and the
	 * announcement signed */
	appendSample(1);
	QList<AuditEntry> list = AuditLog::entries();
	QCOMPARE(list.size(), 7);
	QCOMPARE(list[5].action, QString(AuditLog::actionKeyCreate));
	QCOMPARE(list[6].action, QString(AuditLog::actionCheckpoint));
	QString key = AuditKey::current();
	QCOMPARE(key.size(), 64);
	QCOMPARE(list[5].objectId, key);
	/* keytype::name, as every key entry (BTD-97) */
	QCOMPARE(list[5].params.value("key_type").toString(), QString("ED25519"));
	QCOMPARE(AuditKey::keyId(list[5].params.value("public_key")
			.toString().toLatin1()), key);
	QVariantMap cp = list[6].params;
	QCOMPARE(cp.value("key_id").toString(), key);
	QCOMPARE(cp.value("checkpoint_seq").toLongLong(), qint64(6));
	QCOMPARE(cp.value("checkpoint_hash").toString().toLatin1(), list[5].hash);
	QVERIFY(!cp.contains("next_key_id"));
	QCOMPARE(QStringList(cp.keys()), QStringList({ "checkpoint_hash",
		"checkpoint_seq", "checkpoint_time", "key_id", "signature" }));
	QVERIFY(AuditKey::verify(list[5].params.value("public_key").toString()
		.toLatin1(), AuditLog::checkpointPayload(cp),
		QByteArray::fromBase64(cp.value("signature").toByteArray())));

	/* The key is not a key item: no key list or dialog offers it */
	QCOMPARE(Store.getAll<pki_key>().size(), 0);
	QCOMPARE(sqlValue("SELECT COUNT(*) FROM audit_keys").toInt(), 1);
	QVERIFY(!sqlValue("SELECT private FROM audit_keys").toString().isEmpty());

	AuditVerifyResult r = AuditLog::verify();
	QVERIFY2(r.ok(), r.toJson().constData());
	QCOMPARE(r.checkpoints, qint64(1));
	QCOMPARE(r.lastCheckpointSeq, qint64(7));
	/* The checkpoint signs entry 6; its own row is anchored by the next
	 * one (BTD-110) */
	QCOMPARE(r.unanchoredEntries, qint64(1));
	QCOMPARE(r.auditKeys, QStringList({ key }));

	/* N entries after the checkpoint entry the next one follows */
	appendSample(4);
	QCOMPARE(byAction(AuditLog::actionCheckpoint).size(), 1);
	appendSample(1);
	list = byAction(AuditLog::actionCheckpoint);
	QCOMPARE(list.size(), 2);
	QCOMPARE(list[1].seq, qint64(13));
	QCOMPARE(list[1].params.value("checkpoint_seq").toLongLong(), qint64(12));
	r = AuditLog::verify();
	QVERIFY2(r.ok(), r.toJson().constData());
	QCOMPARE(r.checkpoints, qint64(2));
	QVERIFY(r.toJson().contains("\"last_checkpoint_seq\":13,"));

	/* Survives reopening */
	reopenDatabase();
	QVERIFY(AuditLog::verify().ok());
	QCOMPARE(AuditKey::current(), key);
}

/* A checkpoint written by an operation with confirmed questions (BTD-71)
 * carries only its own params, so its signature verifies */
void test_service_checkpoint::checkpointAfterConfirmedOperation()
{
	Settings["audit_checkpoint_interval"] = 5;
	ServiceContext confirmed = ctx;
	confirmed.confirm("key.size", "--yes");
	for (int i = 1; i <= 5; i++) {
		AuditParams p;
		p.set("name", QString("key-%1").arg(i));
		AuditLog::append(confirmed, "key.generate", "key",
				QString::number(i), p);
	}
	QList<AuditEntry> list = AuditLog::entries();
	QCOMPARE(list.size(), 7);
	QCOMPARE(list[4].params.value("confirmed").toString(),
		QString("key.size:--yes"));
	QVERIFY(!list[5].params.contains("confirmed"));
	/* The same for the password check on open (BTD-78) */
	QVERIFY(list[4].params.contains("db_unlock_verified"));
	QVERIFY(!list[5].params.contains("db_unlock_verified"));
	QCOMPARE(list[6].action, QString(AuditLog::actionCheckpoint));
	QCOMPARE(QStringList(list[6].params.keys()), QStringList({
		"checkpoint_hash", "checkpoint_seq", "checkpoint_time",
		"key_id", "signature" }));
	AuditVerifyResult r = AuditLog::verify();
	QVERIFY2(r.ok(), r.toJson().constData());
	QCOMPARE(r.checkpoints, qint64(1));
}

void test_service_checkpoint::defaultInterval()
{
	QCOMPARE(AuditLog::checkpointInterval(), 100);
	Settings["audit_checkpoint_interval"] = "garbage";
	QCOMPARE(AuditLog::checkpointInterval(), 100);
	Settings["audit_checkpoint_interval"] = 0;
	QCOMPARE(AuditLog::checkpointInterval(), 100);
	Settings["audit_checkpoint_interval"] = QString();

	appendSample(99);
	QVERIFY(byAction(AuditLog::actionCheckpoint).isEmpty());
	appendSample(1);
	QList<AuditEntry> list = byAction(AuditLog::actionCheckpoint);
	QCOMPARE(list.size(), 1);
	QCOMPARE(list[0].params.value("checkpoint_seq").toLongLong(), qint64(101));
	AuditVerifyResult r = AuditLog::verify();
	QVERIFY2(r.ok(), r.toJson().constData());
	QCOMPARE(r.entries, qint64(102));
}

void test_service_checkpoint::recomputedChain_data()
{
	QTest::addColumn<QString>("forge");
	QTest::addColumn<QString>("reason");

	QTest::newRow("hashes recomputed") << "" << "checkpoint_hash";
	QTest::newRow("checkpoint_hash forged") << "hash" << "checkpoint_signature";
	QTest::newRow("signature removed") << "signature" << "checkpoint_signature";
}

void test_service_checkpoint::recomputedChain()
{
	QFETCH(QString, forge);
	QFETCH(QString, reason);

	/* 1-5 sample, 6 key, 7 checkpoint of 6, 8-12 sample, 13 checkpoint
	 * of 12, 14-15 sample */
	Settings["audit_checkpoint_interval"] = 5;
	appendSample(12);
	QCOMPARE(AuditLog::entries().size(), 15);
	QCOMPARE(byAction(AuditLog::actionCheckpoint).size(), 2);
	QVERIFY(AuditLog::verify().ok());

	/* Change entry 10 and recompute every later hash: the plain hash
	 * chain verifies again, the checkpoint of entry 12 does not */
	sql("UPDATE audit_log SET object_id='99' WHERE seq=10");
	if (forge == "hash" || forge == "signature") {
		recomputeFrom(10);
		QVariantMap p = AuditLog::entries()[12].params;
		if (forge == "hash")
			p["checkpoint_hash"] = QString::fromLatin1(
					AuditLog::entries()[11].hash);
		else
			p.remove("signature");
		sql(QString("UPDATE audit_log SET params='%1' WHERE seq=13")
			.arg(QString::fromUtf8(AuditLog::canonicalJson(p))));
	}
	recomputeFrom(10);

	AuditVerifyResult r = AuditLog::verify();
	QVERIFY(!r.ok());
	QCOMPARE(r.verifiedEntries, qint64(15));   // the hash chain holds
	QCOMPARE(r.reason, reason);
	QCOMPARE(r.lastCheckpointSeq, qint64(7));  // broken after this one
	/* entry 7 itself is not signed: anchored up to 6 */
	QCOMPARE(r.firstBrokenSeq, qint64(7));
	QCOMPARE(r.failedCheckpointSeq, qint64(13));
	QCOMPARE(r.checkpoints, qint64(1));
	QCOMPARE(r.unanchoredEntries, qint64(9));
	QVERIFY(r.toJson().contains("\"first_broken_seq\":7,"));
}

void test_service_checkpoint::unannouncedKey()
{
	/* A second key announced without a rotation checkpoint of the first
	 * one cannot sign: the entries signed by it are not trusted */
	Settings["audit_checkpoint_interval"] = 3;
	appendSample(3);
	QString first = AuditKey::current();
	EVP_PKEY *mallory = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
	QVERIFY(mallory);
	QByteArray pem = publicPem(mallory);
	QString id = AuditKey::keyId(pem);
	AuditEntry announced = forgeEntry(AuditLog::actionKeyCreate, id, {
		{ "key_id", id }, { "key_type", "ed25519" },
		{ "public_key", QString::fromLatin1(pem) } });
	QVariantMap cp {
		{ "checkpoint_seq", announced.seq },
		{ "checkpoint_hash", QString::fromLatin1(announced.hash) },
		{ "checkpoint_time", announced.time }, { "key_id", id } };
	cp["signature"] = signature(mallory, cp);
	EVP_PKEY_free(mallory);
	forgeEntry(AuditLog::actionCheckpoint, id, cp);

	AuditVerifyResult r = AuditLog::verify();
	QVERIFY(!r.ok());
	QCOMPARE(r.reason, QString("checkpoint_key"));
	QCOMPARE(r.lastCheckpointSeq, qint64(5));
	QCOMPARE(r.failedCheckpointSeq, qint64(7));
	QCOMPARE(r.auditKeys, QStringList({ first }));
}

void test_service_checkpoint::tamperedStructure_data()
{
	QTest::addColumn<QString>("forge");
	QTest::addColumn<QString>("reason");
	QTest::addColumn<qint64>("firstBroken");
	QTest::addColumn<qint64>("failedCheckpoint");
	QTest::addColumn<qint64>("lastCheckpoint");
	QTest::addColumn<qint64>("unanchored");

	/* 1-5 sample, 6 key, 7 checkpoint of 6, 8-12 sample, 13 checkpoint
	 * of 12 */
	QTest::newRow("checkpoints removed") << "remove" << "checkpoint_missing"
		<< qint64(1) << qint64(0) << qint64(0) << qint64(10);
	QTest::newRow("checkpoints and keys removed") << "remove keys"
		<< "checkpoint_missing" << qint64(1) << qint64(0) << qint64(0)
		<< qint64(10);
	QTest::newRow("checkpoint_seq not the predecessor") << "seq"
		<< "checkpoint_hash" << qint64(7) << qint64(13) << qint64(7)
		<< qint64(7);
	QTest::newRow("announced PEM is not key_id") << "pem"
		<< "checkpoint_key" << qint64(1) << qint64(6) << qint64(0)
		<< qint64(13);
	QTest::newRow("next_key_id never announced") << "next"
		<< "checkpoint_key" << qint64(7) << qint64(13) << qint64(7)
		<< qint64(7);
	QTest::newRow("metadata of a covered checkpoint") << "metadata 7"
		<< "checkpoint_hash" << qint64(7) << qint64(13) << qint64(7)
		<< qint64(7);
	/* Not signed, so not detected, but no longer counted as anchored */
	QTest::newRow("metadata of the last checkpoint") << "metadata 13"
		<< "" << qint64(0) << qint64(0) << qint64(13) << qint64(1);
}

void test_service_checkpoint::tamperedStructure()
{
	QFETCH(QString, forge);
	QFETCH(QString, reason);
	QFETCH(qint64, firstBroken);
	QFETCH(qint64, failedCheckpoint);
	QFETCH(qint64, lastCheckpoint);
	QFETCH(qint64, unanchored);

	Settings["audit_checkpoint_interval"] = 5;
	appendSample(10);
	QCOMPARE(byAction(AuditLog::actionCheckpoint).size(), 2);
	AuditVerifyResult r = AuditLog::verify();
	QVERIFY2(r.ok(), r.toJson().constData());
	QVariantMap cp = AuditLog::entries()[12].params;
	EVP_PKEY *key = auditPrivateKey();
	QVERIFY(key);

	if (forge.startsWith("remove")) {
		removeCheckpoints(forge == "remove keys");
	} else if (forge == "seq") {
		/* Signed with the audit key, but over entry 11 instead of 12 */
		cp["checkpoint_seq"] = qint64(11);
		cp["checkpoint_hash"] = QString::fromLatin1(
				AuditLog::entries()[10].hash);
		cp["signature"] = signature(key, cp);
		setParams(13, cp);
		recomputeFrom(13);
	} else if (forge == "pem") {
		EVP_PKEY *other = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
		QVariantMap p = AuditLog::entries()[5].params;
		p["public_key"] = QString::fromLatin1(publicPem(other));
		EVP_PKEY_free(other);
		setParams(6, p);
		recomputeFrom(6);
	} else if (forge == "next") {
		cp["next_key_id"] = QString(64, 'a');
		cp["signature"] = signature(key, cp);
		setParams(13, cp);
		recomputeFrom(13);
	} else if (forge.startsWith("metadata")) {
		qint64 seq = forge.mid(9).toLongLong();
		sql(QString("UPDATE audit_log SET actor='os:mallory', "
			"created='2020-01-01T00:00:00Z' WHERE seq=%1").arg(seq));
		recomputeFrom(seq);
	}
	EVP_PKEY_free(key);

	r = AuditLog::verify();
	QCOMPARE(r.chainOk(), reason.isEmpty());
	QCOMPARE(r.reason, reason);
	QCOMPARE(r.firstBrokenSeq, firstBroken);
	QCOMPARE(r.failedCheckpointSeq, failedCheckpoint);
	QCOMPARE(r.lastCheckpointSeq, lastCheckpoint);
	QCOMPARE(r.unanchoredEntries, unanchored);
	/* the hash chain itself holds in every case */
	QCOMPARE(r.verifiedEntries, r.entries);
}

void test_service_checkpoint::unsignedTailLimit()
{
	/* No password: no checkpoint, the tail grows. Up to interval + 1
	 * unsigned entries are what a working writer leaves, more means
	 * checkpoints are missing */
	Settings["audit_checkpoint_interval"] = 3;
	pki_evp::passwd.cleanse();
	appendSample(4);
	AuditVerifyResult r = AuditLog::verify();
	QVERIFY2(r.ok(), r.toJson().constData());
	QCOMPARE(r.unanchoredEntries, qint64(4));

	appendSample(1);
	r = AuditLog::verify();
	QVERIFY(!r.ok());
	QCOMPARE(r.reason, QString("checkpoint_missing"));
	QCOMPARE(r.firstBrokenSeq, qint64(1));
	QCOMPARE(r.failedCheckpointSeq, qint64(0));
	QCOMPARE(r.unanchoredEntries, qint64(5));

	/* Unlocked, the next append does not sign so long a tail on its
	 * own, the explicit adoption does (review of #27) */
	pki_evp::passwd = dbPassword;
	appendSample(1);
	QVERIFY(byAction(AuditLog::actionCheckpoint).isEmpty());
	AuditLog::adoptUnanchored(ctx);
	r = AuditLog::verify();
	QVERIFY2(r.ok(), r.toJson().constData());
	QCOMPARE(r.checkpoints, qint64(1));
	QCOMPARE(r.adoptedEntries, qint64(6));
}

void test_service_checkpoint::unannouncedKeyAlone()
{
	/* Short enough for the tail rule: only the key in audit_keys that
	 * the chain no longer announces reveals the removal */
	Settings["audit_checkpoint_interval"] = 5;
	appendSample(5);
	removeCheckpoints(false);
	QCOMPARE(AuditLog::entries().size(), 5);
	AuditVerifyResult r = AuditLog::verify();
	QVERIFY(!r.ok());
	QCOMPARE(r.reason, QString("checkpoint_missing"));
	QCOMPARE(r.firstBrokenSeq, qint64(1));
}

void test_service_checkpoint::forgedDeletionNotSigned()
{
	/* Review of #27, blocker 1: after the removal of every checkpoint,
	 * announcement and audit key, the next append with the password
	 * must not take the first-use path and sign the forged history */
	Settings["audit_checkpoint_interval"] = 5;
	appendSample(10);
	removeCheckpoints(true);
	appendSample(1);
	QVERIFY(byAction(AuditLog::actionKeyCreate).isEmpty());
	QVERIFY(byAction(AuditLog::actionCheckpoint).isEmpty());
	QCOMPARE(sqlValue("SELECT COUNT(*) FROM audit_keys").toInt(), 0);
	AuditVerifyResult r = AuditLog::verify();
	QCOMPARE(r.reason, QString("checkpoint_missing"));
	QCOMPARE(r.entries, qint64(11));

	/* Explicit checkpoints, rotation and export refuse it too */
	QCOMPARE(errorCode([&]() { AuditLog::checkpoint(ctx); }),
		QString("audit_checkpoint_missing"));
	QCOMPARE(errorCode([&]() { AuditLog::rotateKey(ctx); }),
		QString("audit_checkpoint_missing"));
	QCOMPARE(errorCode([&]() { AuditLog::exportJsonLines(ctx); }),
		QString("audit_checkpoint_missing"));
	QCOMPARE(AuditLog::entries().size(), 11);
}

void test_service_checkpoint::intervalClamped()
{
	/* Review of #27, blocker 2: the unsigned setting cannot switch the
	 * tail rule off; it is clamped to 1000 */
	Settings["audit_checkpoint_interval"] = 1000000;
	QCOMPARE(AuditLog::checkpointInterval(), 1000);
	Settings["audit_checkpoint_interval"] = QString();
	appendSample(1010);
	QVERIFY(!byAction(AuditLog::actionCheckpoint).isEmpty());
	removeCheckpoints(true);
	Settings["audit_checkpoint_interval"] = 1000000;
	AuditVerifyResult r = AuditLog::verify();
	QVERIFY(!r.ok());
	QCOMPARE(r.reason, QString("checkpoint_missing"));
	QCOMPARE(r.unanchoredEntries, qint64(1010));
}

void test_service_checkpoint::adoptUnanchored_data()
{
	QTest::addColumn<bool>("forged");

	/* Both look the same: a log without key and with a long unsigned
	 * tail. Only the operator who checked it can tell them apart. */
	QTest::newRow("written without password") << false;
	QTest::newRow("checkpoints and keys deleted") << true;
}

void test_service_checkpoint::adoptUnanchored()
{
	QFETCH(bool, forged);

	Settings["audit_checkpoint_interval"] = 5;
	if (forged) {
		appendSample(10);
		removeCheckpoints(true);
	} else {
		pki_evp::passwd.cleanse();
		PwDialogHeadless *headless = new PwDialogHeadless();
		pwdialog->delegateTo(headless);
		appendSample(10);
		pki_evp::passwd = dbPassword;
	}
	/* Unlocked: the automatic checkpoint is refused, the entry stays */
	appendSample(1);
	QCOMPARE(AuditLog::entries().size(), 11);
	QVERIFY(byAction(AuditLog::actionKeyCreate).isEmpty());
	QCOMPARE(AuditLog::verify().reason, QString("checkpoint_missing"));

	/* Adopted on request: recorded in the signed announcement */
	AuditEntry cp = AuditLog::adoptUnanchored(ctx);
	QCOMPARE(cp.seq, qint64(13));
	QList<AuditEntry> list = AuditLog::entries();
	QCOMPARE(list[11].action, QString(AuditLog::actionKeyCreate));
	QCOMPARE(list[11].params.value("adopted_entries").toLongLong(),
			qint64(11));
	AuditVerifyResult r = AuditLog::verify();
	QVERIFY2(r.ok(), r.toJson().constData());
	QCOMPARE(r.adoptedEntries, qint64(11));
	QVERIFY(r.toJson().contains("\"adopted_entries\":11,"));

	/* From now on as usual */
	appendSample(5);
	QCOMPARE(byAction(AuditLog::actionCheckpoint).size(), 2);
	QVERIFY(byAction(AuditLog::actionKeyCreate)[0].params
			.contains("adopted_entries"));
	r = AuditLog::verify();
	QVERIFY2(r.ok(), r.toJson().constData());
	QCOMPARE(r.adoptedEntries, qint64(11));

	/* The adoption is signed: removing the mark breaks the checkpoint */
	QVariantMap p = list[11].params;
	p.remove("adopted_entries");
	setParams(12, p);
	recomputeFrom(12);
	r = AuditLog::verify();
	QCOMPARE(r.reason, QString("checkpoint_hash"));
	QCOMPARE(r.failedCheckpointSeq, qint64(13));
	QCOMPARE(r.adoptedEntries, qint64(0));
}

void test_service_checkpoint::baselineException_data()
{
	QTest::addColumn<qint64>("count");
	QTest::addColumn<QString>("reason");

	QTest::newRow("baseline of an upgrade") << qint64(5) << "";
	QTest::newRow("forged baseline row") << qint64(4) << "checkpoint_missing";
}

void test_service_checkpoint::baselineException()
{
	/* An upgraded database: one revocation.baseline per revocation row,
	 * then audit.init with their count, written before any checkpoint
	 * could be. They do not count against the unsigned tail, but only
	 * when audit.init counts exactly the baseline rows */
	QFETCH(qint64, count);
	QFETCH(QString, reason);

	Settings["audit_checkpoint_interval"] = 2;
	for (int i = 1; i <= 5; i++)
		sql(QString("INSERT INTO revocations (caId, serial, date, "
			"invaldate, crlNo, reasonBit) VALUES (1, '0%1', "
			"'20260101000000Z', '20260101000000Z', NULL, 0)").arg(i));
	AuditLog::writeBaseline();
	pki_evp::passwd.cleanse();
	PwDialogHeadless *headless = new PwDialogHeadless();
	pwdialog->delegateTo(headless);
	appendSample(3);
	QList<AuditEntry> list = AuditLog::entries();
	QCOMPARE(list.size(), 9);
	QCOMPARE(list[5].action, QString(AuditLog::actionInit));
	if (count != 5) {
		QVariantMap p = list[5].params;
		p["count"] = count;
		setParams(6, p);
		recomputeFrom(6);
	}

	AuditVerifyResult r = AuditLog::verify();
	QCOMPARE(r.reason, reason);
	QCOMPARE(r.unanchoredEntries, qint64(9));
	QVERIFY(r.mismatches.isEmpty());
}

/* BTD-148: a skipped automatic checkpoint reaches the user, once per
 * error code and open database, with the code and the next step; the
 * entries stay. On 6b1110da only a qWarning said so. */
void test_service_checkpoint::skippedCheckpointNotice()
{
	Settings["audit_checkpoint_interval"] = 2;
	Passwd pass = pki_evp::passwd;
	pki_evp::passwd.cleanse();
	appendSample(5);
	QStringList n = warning->takeNotices();
	QCOMPARE(n.size(), 1);
	QVERIFY2(n[0].contains("audit_key_unavailable"), CCHAR(n[0]));

	/* With the password the unsigned tail is too long: a new code */
	pki_evp::passwd = pass;
	appendSample(3);
	n = warning->takeNotices();
	QCOMPARE(n.size(), 1);
	QVERIFY2(n[0].contains("audit_checkpoint_missing") &&
		n[0].contains("--audit-adopt"), CCHAR(n[0]));
	QCOMPARE(AuditLog::entries().size(), 8);

	/* Once per open database: the next open reports it again */
	reopenDatabase();
	appendSample(1);
	n = warning->takeNotices();
	QCOMPARE(n.size(), 1);
	QVERIFY2(n[0].contains("audit_checkpoint_missing"), CCHAR(n[0]));
}

void test_service_checkpoint::skippedCheckpointNoticeMissingKey()
{
	Settings["audit_checkpoint_interval"] = 5;
	appendSample(5);
	QVERIFY(warning->takeNotices().isEmpty());
	sql("DELETE FROM audit_keys");
	appendSample(10);
	QStringList n = warning->takeNotices();
	QCOMPARE(n.size(), 1);
	QVERIFY2(n[0].contains("audit_key_missing") &&
		n[0].contains("--audit-verify"), CCHAR(n[0]));
}

void test_service_checkpoint::skippedCheckpointNoticeSigning()
{
	/* An audit key that decrypts but cannot sign (X25519): reported
	 * with its code and the OpenSSL reason before verify() would
	 * report checkpoint_missing (review of xca#59, MINOR 9) */
	Settings["audit_checkpoint_interval"] = 3;
	appendSample(3);
	QCOMPARE(byAction(AuditLog::actionCheckpoint).size(), 1);
	EVP_PKEY *x25519 = EVP_PKEY_Q_keygen(nullptr, nullptr, "X25519");
	QVERIFY(x25519);
	BioByteArray der;
	QVERIFY(i2d_PKCS8PrivateKey_bio(der, x25519, EVP_aes_256_cbc(),
		(char *)pki_evp::passwd.constData(), pki_evp::passwd.size(),
		nullptr, nullptr) > 0);
	EVP_PKEY_free(x25519);
	sql(QString("UPDATE audit_keys SET private='%1'")
		.arg(QString::fromLatin1(der.byteArray().toBase64())));

	appendSample(3);
	QStringList n = warning->takeNotices();
	QCOMPARE(n.size(), 1);
	QVERIFY2(n[0].contains("audit_signing_failed") &&
		n[0].contains("Failed to sign the audit checkpoint"),
		CCHAR(n[0]));
	QCOMPARE(byAction(AuditLog::actionCheckpoint).size(), 1);
	AuditVerifyResult r = AuditLog::verify();
	QVERIFY2(r.ok(), r.toJson().constData());
}

void test_service_checkpoint::missingCurrentKey_data()
{
	QTest::addColumn<QString>("statement");

	QTest::newRow("retired") << "UPDATE audit_keys SET retired=1";
	QTest::newRow("private part dropped") << "UPDATE audit_keys SET private=NULL";
	QTest::newRow("deleted") << "DELETE FROM audit_keys";
}

void test_service_checkpoint::missingCurrentKey()
{
	QFETCH(QString, statement);

	/* The chain announced a key: a missing current key fails closed
	 * instead of announcing a new one */
	Settings["audit_checkpoint_interval"] = 5;
	appendSample(5);
	QCOMPARE(byAction(AuditLog::actionKeyCreate).size(), 1);
	sql(statement);
	int keys = sqlValue("SELECT COUNT(*) FROM audit_keys").toInt();

	QCOMPARE(errorCode([&]() { AuditLog::checkpoint(ctx); }),
		QString("audit_key_missing"));
	QCOMPARE(errorCode([&]() { AuditLog::rotateKey(ctx); }),
		QString("audit_key_missing"));
	/* The automatic checkpoint fails the same way; the entries stay */
	appendSample(5);
	QCOMPARE(AuditLog::entries().size(), 12);
	QCOMPARE(byAction(AuditLog::actionKeyCreate).size(), 1);
	QCOMPARE(byAction(AuditLog::actionCheckpoint).size(), 1);
	QCOMPARE(sqlValue("SELECT COUNT(*) FROM audit_keys").toInt(), keys);
	AuditVerifyResult r = AuditLog::verify();
	QVERIFY2(r.ok(), r.toJson().constData());
	QCOMPARE(r.unanchoredEntries, qint64(6));
}

void test_service_checkpoint::auditKeyNotUsableForSigning()
{
	AuditLog::append(ctx, "test", "none", "");
	AuditLog::checkpoint(ctx);
	QString key = AuditKey::current();

	/* Somebody copies the audit key out of the database and imports it
	 * as a key: every signing service refuses it */
	EVP_PKEY *pkey = auditPrivateKey();
	QVERIFY(pkey);
	pki_evp *evp = new pki_evp(pkey);
	evp->setIntName("copied audit key");
	pki_key *imported = dynamic_cast<pki_key *>(
			Database.model<db_key>()->insert(evp));
	QVERIFY(imported);
	QVERIFY(imported->isPrivKey());

	RequestSpec req;
	req.name = "audit csr";
	req.subject.addEntryByNid(NID_commonName, "audit csr");
	req.key = imported;
	QCOMPARE(errorCode([&]() {
		Database.model<db_x509req>()->newRequest(ctx, req);
	}), QString("audit_key"));

	QDateTime now = QDateTime::currentDateTimeUtc();
	IssuanceSpec cert;
	cert.name = "audit cert";
	cert.subject.addEntryByNid(NID_commonName, "audit cert");
	cert.key = imported;
	cert.notBefore = a1time(now);
	cert.notAfter = a1time(now.addDays(30));
	cert.hashAlgo = digest(NID_undef);
	cert.extensions.basicCA = ExtensionSpec::bc_ca;
	QCOMPARE(errorCode([&]() {
		Database.model<db_x509>()->newCert(ctx, cert);
	}), QString("audit_key"));

	/* BTD-230: BTD230_DELAY_MS widens the gap between now and the CA
	 * below, as a slow ASan run does, to show the race on demand */
	int delay = qEnvironmentVariableIntValue("BTD230_DELAY_MS");
	if (delay > 0)
		QThread::msleep(delay);

	/* A CA certificate made outside the service layer with that key,
	 * then imported: neither issuance nor a CRL is signed with it */
	EVP_PKEY *caKey = auditPrivateKey();
	QVERIFY(caKey);
	X509 *x = X509_new();
	X509_NAME *name = X509_NAME_new();
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
		(const unsigned char *)"audit ca", -1, -1, 0);
	X509_set_version(x, X509_VERSION_3);
	ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
	X509_set_subject_name(x, name);
	X509_set_issuer_name(x, name);
	X509_NAME_free(name);
	/* from the same now as the end entity below, a minute earlier: the
	 * wall clock here could be a second later than its notBefore under a
	 * slow run, and issuer_not_yet_valid came before audit_key (BTD-230) */
	ASN1_TIME_set(X509_getm_notBefore(x), now.toSecsSinceEpoch() - 60);
	X509_gmtime_adj(X509_getm_notAfter(x), 30 * 86400L);
	X509_set_pubkey(x, caKey);
	X509V3_CTX ext{};
	X509V3_set_ctx_nodb(&ext);
	X509V3_set_ctx(&ext, x, x, NULL, NULL, 0);
	X509_EXTENSION *bc = X509V3_EXT_conf_nid(NULL, &ext,
				NID_basic_constraints, "critical,CA:TRUE");
	X509_add_ext(x, bc, -1);
	X509_EXTENSION_free(bc);
	QVERIFY(X509_sign(x, caKey, NULL) > 0);
	EVP_PKEY_free(caKey);
	pki_x509 *ca = new pki_x509(x);
	ca->setIntName("audit ca");
	ca = dynamic_cast<pki_x509 *>(Database.model<db_x509>()->insert(ca));
	QVERIFY(ca);
	QVERIFY(ca->isCA());
	QCOMPARE(ca->getRefKey(), imported);

	pki_key *eeKey = Database.model<db_key>()->newKey(
				keyjob("EC:prime256v1"), "ee key");
	IssuanceSpec ee = cert;
	ee.name = "ee";
	ee.key = eeKey;
	ee.signer = ca;
	ee.hashAlgo = digest(NID_sha256);
	ee.extensions.basicCA = ExtensionSpec::bc_not_ca;
	QCOMPARE(errorCode([&]() {
		Database.model<db_x509>()->newCert(ctx, ee);
	}), QString("audit_key"));

	crljob job(ca);
	job.hashAlgo = digest(NID_undef);
	QCOMPARE(errorCode([&]() {
		Database.model<db_crl>()->newCrl(ctx, job);
	}), QString("audit_key"));

	/* The signing primitives refuse it too, whoever calls them: renewal
	 * (db_x509::certRenewal) signs a copy of the certificate with the
	 * issuer's key outside of the services */
	pki_x509 renewed(ca);
	renewed.setNotAfter(a1time(now.addDays(60)));
	pki_crl rawCrl;
	rawCrl.createCrl("raw crl", ca);
	pki_x509req rawReq;
	QStringList primitives;
	primitives << errorCode([&]() {
		renewed.sign(ca->getRefKey(), ca->getDigest());
	}) << errorCode([&]() {
		rawCrl.sign(imported, digest(NID_undef));
	}) << errorCode([&]() {
		rawReq.createReq(imported, req.subject, digest(NID_undef),
				extList());
	});
	QCOMPARE(primitives, QStringList({ "audit_key", "audit_key",
		"audit_key" }));

	/* Each rejection is audited; the chain and its checkpoint hold */
	QStringList codes;
	for (const AuditEntry &e : AuditLog::entries())
		if (e.result == "failure")
			codes << e.action + ":" + e.errorCode;
	QCOMPARE(codes, QStringList({ "request.create:audit_key",
		"certificate.issue:audit_key", "certificate.issue:audit_key",
		"crl.generate:audit_key" }));
	QCOMPARE(Database.model<db_x509>()->getAllIssuers().size(), 1);
	QCOMPARE(AuditKey::current(), key);
	QVERIFY(AuditLog::verify().ok());
}

void test_service_checkpoint::exportSignsCheckpoint()
{
	/* An empty log exports nothing and signs nothing */
	QCOMPARE(AuditLog::exportJsonLines(ctx), QByteArray());
	QCOMPARE(sqlValue("SELECT COUNT(*) FROM audit_keys").toInt(), 0);

	appendSample(2);
	QByteArray out = AuditLog::exportJsonLines(ctx);
	QCOMPARE(out.count('\n'), 4);
	QList<AuditEntry> list = AuditLog::entries();
	QCOMPARE(list.last().action, QString(AuditLog::actionCheckpoint));
	QCOMPARE(list.last().actor, QString("os:service-test"));
	QCOMPARE(list.last().params.value("checkpoint_seq").toLongLong(),
			qint64(3));

	/* The newest entry is a checkpoint already: nothing new to sign */
	QCOMPARE(AuditLog::exportJsonLines(ctx), out);
	appendSample(1);
	QCOMPARE(AuditLog::exportJsonLines(ctx).count('\n'), 6);
	QCOMPARE(byAction(AuditLog::actionCheckpoint).size(), 2);
	QCOMPARE(byAction(AuditLog::actionKeyCreate).size(), 1);
	QVERIFY(AuditLog::verify().ok());
}

void test_service_checkpoint::exportWithoutPassword()
{
	/* As xca --no-gui without --password: the database is open, not
	 * unlocked, and the password request has no source */
	appendSample(2);
	pki_evp::passwd.cleanse();
	PwDialogHeadless *headless = new PwDialogHeadless();
	pwdialog->delegateTo(headless);
	QMap<QString, QStringList> before = tableRows();

	/* Read only (BTD-70): no checkpoint, no key, no row changed */
	qint64 unsignedEntries = -1;
	QByteArray out = AuditLog::exportJsonLines(ctx, &unsignedEntries);
	QCOMPARE(out.count('\n'), 2);
	QCOMPARE(unsignedEntries, qint64(2));
	QCOMPARE(tableRows(), before);
	AuditVerifyResult r = AuditLog::verify();
	QVERIFY2(r.ok(), r.toJson().constData());
	QCOMPARE(r.unanchoredEntries, qint64(2));

	/* With the password from the source it is signed */
	headless->setSource(pass_info::DatabasePassword,
				QString("pass:") + dbPassword);
	out = AuditLog::exportJsonLines(ctx, &unsignedEntries);
	QCOMPARE(out.count('\n'), 4);
	QCOMPARE(unsignedEntries, qint64(0));
	QVERIFY(QByteArray(out.split('\n')[3]).contains(
			"\"action\":\"audit.checkpoint\""));
	/* verify counts the checkpoint row itself (BTD-110) */
	QCOMPARE(AuditLog::verify().unanchoredEntries, qint64(1));

	/* Covered already: nothing to sign */
	QCOMPARE(AuditLog::exportJsonLines(ctx, &unsignedEntries), out);
	QCOMPARE(unsignedEntries, qint64(0));
}

void test_service_checkpoint::exportWithWrongPassword()
{
	/* A wrong source is an error, not a read-only export */
	appendSample(1);
	pki_evp::passwd.cleanse();
	PwDialogHeadless *headless = new PwDialogHeadless();
	headless->setSource(pass_info::DatabasePassword, "pass:wrong");
	pwdialog->delegateTo(headless);
	QCOMPARE(errorCode([&]() { AuditLog::exportJsonLines(ctx); }),
		QString("audit_password_rejected"));
	QCOMPARE(AuditLog::entries().size(), 1);
	QCOMPARE(sqlValue("SELECT COUNT(*) FROM audit_keys").toInt(), 0);
}

void test_service_checkpoint::noPasswordKeepsEntry()
{
	Settings["audit_checkpoint_interval"] = 2;
	appendSample(1);
	pki_evp::passwd.cleanse();

	/* The checkpoint is due but cannot be signed: the entry and the
	 * caller's transaction stay. No password prompt (BTD-111) */
	{
		Transaction;
		QVERIFY(TransBegin());
		AuditLog::append(ctx, "key.generate", "key", "2");
		QVERIFY(TransCommit());
	}
	reopenDatabase();
	QCOMPARE(AuditLog::entries().size(), 2);
	AuditVerifyResult r = AuditLog::verify();
	QVERIFY2(r.ok(), r.toJson().constData());
	QCOMPARE(r.unanchoredEntries, qint64(2));
	QCOMPARE(r.checkpoints, qint64(0));

	/* Unlocked again, the next append signs */
	appendSample(1);
	QCOMPARE(byAction(AuditLog::actionCheckpoint).size(), 1);
	r = AuditLog::verify();
	QVERIFY2(r.ok(), r.toJson().constData());
	QCOMPARE(r.unanchoredEntries, qint64(1));   // the checkpoint row
}

void test_service_checkpoint::neverSignsBrokenTail()
{
	appendSample(3);
	AuditLog::checkpoint(ctx);
	appendSample(2);

	/* An entry after the checkpoint changed without recomputing: no
	 * checkpoint anchors it, the export fails, append() goes on */
	sql("UPDATE audit_log SET actor='os:mallory' WHERE seq=7");
	QCOMPARE(errorCode([&]() { AuditLog::checkpoint(ctx); }),
		QString("audit_chain_broken"));
	QCOMPARE(errorCode([&]() { AuditLog::exportJsonLines(ctx); }),
		QString("audit_chain_broken"));
	Settings["audit_checkpoint_interval"] = 1;
	appendSample(1);
	QCOMPARE(byAction(AuditLog::actionCheckpoint).size(), 1);
	AuditVerifyResult r = AuditLog::verify();
	QVERIFY(!r.ok());
	QCOMPARE(r.firstBrokenSeq, qint64(7));
	QCOMPARE(r.reason, QString("hash"));
	QCOMPARE(r.lastCheckpointSeq, qint64(5));
}

/* BTD-101: a log rewritten from scratch with a new audit key passes
 * verify on its own (trust on first use); the key id pinned from an
 * earlier export reveals it */
void test_service_checkpoint::pinRewrittenLog()
{
	Settings["audit_checkpoint_interval"] = 3;
	appendSample(3);
	QString oldKey = AuditKey::current();
	QVERIFY(!oldKey.isEmpty());

	/* the attacker deletes log and keys and writes a new history */
	sql("DELETE FROM audit_log");
	sql("DELETE FROM audit_keys");
	appendSample(3);
	QString newKey = AuditKey::current();
	QVERIFY(!newKey.isEmpty() && newKey != oldKey);

	AuditVerifyResult r = AuditLog::verify();
	QVERIFY2(r.ok(), r.toJson().constData());

	AuditVerifyPins pins;
	pins.keys << oldKey;
	r = AuditLog::verify(pins);
	QVERIFY(!r.ok());
	QCOMPARE(r.reason, QString("untrusted_key"));
	QCOMPARE(r.toMap().value("pinned_keys").toStringList(),
		QStringList() << oldKey);
	QCOMPARE(r.toMap().value("audit_keys").toStringList(),
		QStringList() << newKey);

	/* the right pin passes */
	pins.keys = QStringList() << newKey;
	r = AuditLog::verify(pins);
	QVERIFY2(r.ok(), r.toJson().constData());
}

void test_service_checkpoint::pinFollowsRotation()
{
	/* the first key pinned: every rotation leads from it */
	Settings["audit_checkpoint_interval"] = 5;
	appendSample(5);
	QString firstKey = AuditKey::current();
	AuditLog::rotateKey(ctx);
	QString secondKey = AuditKey::current();
	appendSample(5);

	AuditVerifyPins pins;
	pins.keys << firstKey;
	AuditVerifyResult r = AuditLog::verify(pins);
	QVERIFY2(r.ok(), r.toJson().constData());
	QCOMPARE(r.auditKeys, QStringList() << firstKey << secondKey);

	/* only the second key pinned: the log does not start with it */
	pins.keys = QStringList() << secondKey;
	r = AuditLog::verify(pins);
	QCOMPARE(r.reason, QString("untrusted_key"));
}

void test_service_checkpoint::pinMinCheckpoint()
{
	/* the newest entries cut off together with their checkpoints pass
	 * verify on their own; the checkpoint seq of an earlier export
	 * reveals it */
	Settings["audit_checkpoint_interval"] = 3;
	appendSample(9);
	AuditVerifyResult full = AuditLog::verify();
	QVERIFY2(full.ok(), full.toJson().constData());
	qint64 newest = full.lastCheckpointSeq;
	QVERIFY(newest > 0);
	QList<AuditEntry> cps = byAction(AuditLog::actionCheckpoint);
	QVERIFY(cps.size() >= 2);
	qint64 cut = cps[cps.size() - 2].seq;
	sql(QString("DELETE FROM audit_log WHERE seq > %1").arg(cut));

	AuditVerifyResult r = AuditLog::verify();
	QVERIFY2(r.ok(), r.toJson().constData());
	AuditVerifyPins pins;
	pins.minCheckpoint = newest;
	r = AuditLog::verify(pins);
	QVERIFY(!r.ok());
	QCOMPARE(r.reason, QString("checkpoint_truncated"));

	pins.minCheckpoint = cut;
	r = AuditLog::verify(pins);
	QVERIFY2(r.ok(), r.toJson().constData());
}

void test_service_checkpoint::keyRotation()
{
	Settings["audit_checkpoint_interval"] = 5;
	appendSample(5);
	QString oldKey = AuditKey::current();
	QVERIFY(!oldKey.isEmpty());

	AuditEntry rot = AuditLog::rotateKey(ctx);
	QString newKey = AuditKey::current();
	QVERIFY(!newKey.isEmpty());
	QVERIFY(newKey != oldKey);

	/* The new key is announced, then a checkpoint of the old key over
	 * the announcement names it */
	QList<AuditEntry> list = AuditLog::entries();
	QCOMPARE(list.size(), 9);
	QCOMPARE(list[7].action, QString(AuditLog::actionKeyCreate));
	QCOMPARE(list[7].objectId, newKey);
	QCOMPARE(rot.seq, qint64(9));
	QCOMPARE(rot.params.value("key_id").toString(), oldKey);
	QCOMPARE(rot.params.value("next_key_id").toString(), newKey);
	QCOMPARE(rot.params.value("checkpoint_seq").toLongLong(), qint64(8));

	/* The old key is retired: public part kept, private part gone */
	QCOMPARE(sqlValue(QString("SELECT retired FROM audit_keys WHERE "
		"key_id='%1'").arg(oldKey)).toInt(), 1);
	QVERIFY(sqlValue(QString("SELECT private FROM audit_keys WHERE "
		"key_id='%1'").arg(oldKey)).isNull());
	QVERIFY(!sqlValue(QString("SELECT public_key FROM audit_keys WHERE "
		"key_id='%1'").arg(oldKey)).toString().isEmpty());

	appendSample(5);
	list = byAction(AuditLog::actionCheckpoint);
	QCOMPARE(list.size(), 3);
	QCOMPARE(list[2].params.value("key_id").toString(), newKey);

	AuditVerifyResult r = AuditLog::verify();
	QVERIFY2(r.ok(), r.toJson().constData());
	QCOMPARE(r.checkpoints, qint64(3));
	QCOMPARE(r.auditKeys, QStringList({ oldKey, newKey }));

	/* A checkpoint of the old key after the rotation is not trusted */
	QVariantMap forged = list[2].params;
	forged["key_id"] = oldKey;
	sql(QString("UPDATE audit_log SET params='%1' WHERE seq=%2")
		.arg(QString::fromUtf8(AuditLog::canonicalJson(forged)))
		.arg(list[2].seq));
	recomputeFrom(list[2].seq);
	r = AuditLog::verify();
	QCOMPARE(r.reason, QString("checkpoint_key"));
	QCOMPARE(r.lastCheckpointSeq, qint64(9));
}

void test_service_checkpoint::passwordChange()
{
	appendSample(1);
	AuditLog::checkpoint(ctx);

	/* What MainWindow::changeDbPass() does, without the dialogs */
	Passwd newPass;
	newPass = "a new database password";
	{
		Transaction;
		QVERIFY(TransBegin());
		AuditKey::reencrypt(newPass);
		QString hash = pki_evp::sha512passwT(newPass,
					Entropy::makeSalt());
		Settings["pwhash"] = hash;
		QVERIFY(TransCommit());
		pki_evp::passHash = hash;
		pki_evp::passwd = newPass;
	}
	appendSample(1);
	AuditLog::checkpoint(ctx);
	AuditVerifyResult r = AuditLog::verify();
	QVERIFY2(r.ok(), r.toJson().constData());
	QCOMPARE(r.checkpoints, qint64(2));

	/* The old password no longer opens the audit key */
	QVERIFY(!auditPrivateKey());
	pki_evp::passwd = dbPassword;
	pki_evp::passHash = pki_evp::sha512passwT(pki_evp::passwd,
					Entropy::makeSalt());
}

void test_service_checkpoint::reservedActions()
{
	for (const char *action : { AuditLog::actionCheckpoint,
				AuditLog::actionKeyCreate }) {
		QVERIFY_THROWS_EXCEPTION(errorEx,
			AuditLog::append(ctx, action, "audit_key", ""));
	}
	QCOMPARE(errorCode([&]() { AuditLog::checkpoint(ctx); }),
		QString("empty_audit_log"));
	QCOMPARE(AuditLog::entries().size(), 0);
}

#ifdef OPENSSL_PROGRAM
QByteArray test_service_checkpoint::openssl(const QStringList &args,
				int *exitCode, const QByteArray &input)
{
	QProcess p;
	p.setProcessChannelMode(QProcess::MergedChannels);
	p.start(OPENSSL_PROGRAM, args);
	p.write(input);
	p.closeWriteChannel();
	if (!p.waitForFinished(30000))
		*exitCode = -1;
	else
		*exitCode = p.exitCode();
	return p.readAll();
}

/* The commands of doc/audit-checkpoints.md, with the payload extraction
 * done here instead of jq: each checkpoint line of the export verifies
 * with the public key of its key_id, and that key id is the SHA-256 of
 * the DER public key */
void test_service_checkpoint::opensslVerifiesExport(const QByteArray &jsonl,
						int expected)
{
	QMap<QString, QString> pemFile;
	int verified = 0, rc;

	for (const QByteArray &line : jsonl.split('\n')) {
		if (line.isEmpty())
			continue;
		QVariantMap e = QJsonDocument::fromJson(line).toVariant().toMap();
		QVariantMap p = e["params"].toMap();
		QString seq = e["seq"].toString();

		if (e["action"].toString() == AuditLog::actionKeyCreate) {
			QString id = p["key_id"].toString();
			pemFile[id] = writeFile("key-" + id + ".pem",
					p["public_key"].toString().toLatin1());
			QByteArray der = openssl({ "pkey", "-pubin", "-in",
				pemFile[id], "-outform", "DER" }, &rc);
			QCOMPARE(rc, 0);
			QByteArray dgst = openssl({ "dgst", "-sha256", "-r" },
						&rc, der);
			QCOMPARE(rc, 0);
			QCOMPARE(QString::fromLatin1(dgst.left(64)), id);
		}
		if (e["action"].toString() != AuditLog::actionCheckpoint)
			continue;
		QString key = p["key_id"].toString();
		QVERIFY2(pemFile.contains(key), CCHAR(key));
		QString payload = writeFile("payload-" + seq + ".json",
				AuditLog::checkpointPayload(p));
		QString sig = writeFile("sig-" + seq + ".bin",
			QByteArray::fromBase64(p["signature"].toByteArray()));
		QByteArray out = openssl({ "pkeyutl", "-verify", "-pubin",
			"-inkey", pemFile[key], "-rawin", "-in", payload,
			"-sigfile", sig }, &rc);
		QVERIFY2(rc == 0, out.constData());
		QVERIFY2(out.contains("Signature Verified Successfully"),
			out.constData());

		/* A changed payload does not verify */
		QString bad = writeFile("bad-" + seq + ".json",
			AuditLog::checkpointPayload(p).replace("\"checkpoint_seq\":",
						"\"checkpoint_seq\":1"));
		openssl({ "pkeyutl", "-verify", "-pubin", "-inkey", pemFile[key],
			"-rawin", "-in", bad, "-sigfile", sig }, &rc);
		QCOMPARE(rc, 1);
		verified++;
	}
	QCOMPARE(verified, expected);
}
#endif

void test_service_checkpoint::opensslCli()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	/* Checkpoints of the old key, the rotation, the new key and the
	 * export; the file as xca --audit-export writes it */
	Settings["audit_checkpoint_interval"] = 4;
	appendSample(4);
	AuditLog::rotateKey(ctx);
	appendSample(5);
	QString path = dir.filePath("audit.jsonl");
	QFile f(path);
	QVERIFY(f.open(QIODevice::WriteOnly));
	f.write(AuditLog::exportJsonLines(ctx));
	f.close();
	QVERIFY(f.open(QIODevice::ReadOnly));
	QByteArray jsonl = f.readAll();
	QCOMPARE(byAction(AuditLog::actionCheckpoint).size(), 4);
	QCOMPARE(byAction(AuditLog::actionKeyCreate).size(), 2);
	opensslVerifiesExport(jsonl, 4);
	QVERIFY(AuditLog::verify().ok());
#endif
}

XCA_SERVICE_TEST_MAIN(test_service_checkpoint)
#include "test_service_checkpoint.moc"
