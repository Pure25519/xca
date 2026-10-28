/* vi: set sw=4 ts=4:
 *
 * Signed audit checkpoints (BTD-37): checkpoint every N entries and on
 * export, verify() against a recomputed chain, the audit key refused for
 * certificates, requests and CRLs, the exported signatures checked with
 * the openssl program, and key rotation.
 */

#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QProcess>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QTemporaryDir>

#include <cstring>
#include <functional>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "lib/BioByteArray.h"
#include "lib/audit.h"
#include "lib/audit_key.h"
#include "lib/database_model.h"
#include "lib/db_crl.h"
#include "lib/db_key.h"
#include "lib/db_x509.h"
#include "lib/db_x509req.h"
#include "lib/entropy.h"
#include "lib/exception.h"
#include "lib/issuance.h"
#include "lib/pki_crl.h"
#include "lib/pki_evp.h"
#include "lib/pki_x509.h"
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
	static QList<AuditEntry> byAction(const QString &action);
	static void recomputeFrom(qint64 seq);
	static EVP_PKEY *auditPrivateKey();
	static QString errorCode(std::function<void()> call);
	QString writeFile(const QString &name, const QByteArray &data);
#ifdef OPENSSL_PROGRAM
	QByteArray openssl(const QStringList &args, int *exitCode,
			const QByteArray &input = QByteArray());
	void opensslVerifiesExport(const QByteArray &jsonl, int expected);
#endif

  private slots:
	void checkpointEveryN();
	void defaultInterval();
	void recomputedChain_data();
	void recomputedChain();
	void unannouncedKey();
	void auditKeyNotUsableForSigning();
	void exportSignsCheckpoint();
	void exportWithoutPasswordFails();
	void noPasswordKeepsEntry();
	void neverSignsBrokenTail();
	void keyRotation();
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
	QByteArray prev;
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
	QCOMPARE(list[5].params.value("key_type").toString(), QString("ed25519"));
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
	QCOMPARE(r.unanchoredEntries, qint64(0));
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
	QCOMPARE(r.firstBrokenSeq, qint64(8));
	QCOMPARE(r.failedCheckpointSeq, qint64(13));
	QCOMPARE(r.checkpoints, qint64(1));
	QCOMPARE(r.unanchoredEntries, qint64(8));
	QVERIFY(r.toJson().contains("\"first_broken_seq\":8,"));
}

void test_service_checkpoint::unannouncedKey()
{
	/* A second key announced without a rotation checkpoint of the first
	 * one cannot sign: the entries signed by it are not trusted */
	Settings["audit_checkpoint_interval"] = 3;
	appendSample(3);
	QString first = AuditKey::current();
	sql(QString("UPDATE audit_keys SET retired=1 WHERE key_id='%1'")
			.arg(first));
	appendSample(3);
	AuditVerifyResult r = AuditLog::verify();
	QVERIFY(!r.ok());
	QCOMPARE(r.reason, QString("checkpoint_key"));
	QCOMPARE(r.lastCheckpointSeq, qint64(5));
	QCOMPARE(r.failedCheckpointSeq, qint64(10));
	QCOMPARE(r.auditKeys, QStringList({ first }));
	QVERIFY(AuditKey::current() != first);
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
	X509_gmtime_adj(X509_getm_notBefore(x), 0);
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

void test_service_checkpoint::exportWithoutPasswordFails()
{
	appendSample(2);
	/* As xca --no-gui without --password: the database is open, but
	 * not unlocked */
	pki_evp::passwd.cleanse();
	pwdialog->expect("", pw_cancel);
	QCOMPARE(errorCode([&]() { AuditLog::exportJsonLines(ctx); }),
		QString("audit_key_unavailable"));
	QCOMPARE(AuditLog::entries().size(), 2);
	QCOMPARE(sqlValue("SELECT COUNT(*) FROM audit_keys").toInt(), 0);

	/* With the password from the source it is signed */
	pwdialog->expect(dbPassword);
	QCOMPARE(AuditLog::exportJsonLines(ctx).count('\n'), 4);
}

void test_service_checkpoint::noPasswordKeepsEntry()
{
	Settings["audit_checkpoint_interval"] = 2;
	appendSample(1);
	pki_evp::passwd.cleanse();

	/* The checkpoint is due but cannot be signed: the entry and the
	 * caller's transaction stay */
	pwdialog->expect("", pw_cancel);
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
	QCOMPARE(r.unanchoredEntries, qint64(0));
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
