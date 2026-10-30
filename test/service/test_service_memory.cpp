/* vi: set sw=4 ts=4:
 *
 * Memory follows the database (BTD-130): after a transaction that rolled
 * back, the in-memory store and the views show what the database holds.
 * Before, a failed multi-delete freed the objects deleted before the
 * failure, and a failed create, issue, CRL, request, template or import
 * left the new object in store and view with the id of its rolled-back
 * row, usable for signing. A completed public key, the revocations of an
 * imported CRL and keys re-encrypted for a new database password stayed
 * changed as well, and taking a certificate out of the view after the
 * rollback wrote to the database. The failures are injected with a
 * trigger or with DbTransaction::injectNestedRollback() (BTD-142).
 */

#include <functional>

#include <QFile>
#include <QSqlError>
#include <QSqlQuery>
#include <QTemporaryDir>

#include <openssl/asn1.h>
#include <openssl/x509.h>

#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/db_crl.h"
#include "lib/db_key.h"
#include "lib/db_temp.h"
#include "lib/db_x509.h"
#include "lib/db_x509req.h"
#include "lib/exception.h"
#include "lib/importexport.h"
#include "lib/issuance.h"
#include "lib/pki_crl.h"
#include "lib/pki_evp.h"
#include "lib/pki_export.h"
#include "lib/pki_temp.h"
#include "lib/settings.h"
#include "lib/digest.h"
#include "lib/pki_pkcs12.h"
#include "lib/pki_x509.h"
#include "lib/pki_x509req.h"
#include "lib/request.h"
#include "lib/sql.h"
#include "lib/template.h"

#include "ServiceTestCase.h"

class test_service_memory : public ServiceTestCase
{
	Q_OBJECT

	ServiceContext ctx{ ServiceContext::cli, "os:service-test" };
	QTemporaryDir dir{};

	static void sql(const QString &statement)
	{
		QSqlQuery q(QSqlDatabase::database());
		QVERIFY2(q.exec(statement), CCHAR(q.lastError().text()));
	}
	static int count(const QString &statement)
	{
		QSqlQuery q(QSqlDatabase::database());
		q.exec(statement);
		return q.next() ? q.value(0).toInt() : -1;
	}
	/* "" on success, else the serviceError code or "errorEx" */
	static QString errorCode(std::function<void()> call);
	/* How often an object of that name is in the store */
	static int inStore(const QString &name);
	/* Whether the model shows an object of that name */
	static bool inModel(const db_base *db, const QString &name,
			const QModelIndex &parent = QModelIndex());
	static pki_key *newKey(const QString &name)
	{
		return Database.model<db_key>()->newKey(
				keyjob("EC:prime256v1"), name);
	}
	IssuanceSpec caSpec(const QString &cn, pki_key *key, int years);
	pki_x509 *issue(const QString &cn, pki_x509 *signer);
	QString exportFile(pki_base *pki, int format, const QString &name);
	static int entries(const QString &action, const QString &result);

  private slots:
	void cleanup();
	void deleteSecondFailsKeepsAll();
	void deleteCommitFailsKeepsAll();
	void newTemplateRollback();
	void newKeyRollback();
	void newCertRollback();
	void newRequestRollback();
	void newCrlRollback();
	void importCompletedKeyAndCrlRollback();
	void importRollbackWritesNoSql();
	void settingWithoutStoredValueRollback();
	void pkcs12MigrationCommitFails();
};

QString test_service_memory::errorCode(std::function<void()> call)
{
	try {
		call();
	} catch (serviceError &err) {
		return err.code;
	} catch (errorEx &err) {
		return "errorEx";
	}
	return QString();
}

int test_service_memory::inStore(const QString &name)
{
	int n = 0;
	for (pki_base *pki : Store.getAll<pki_base>())
		if (pki->getIntName() == name)
			n++;
	return n;
}

bool test_service_memory::inModel(const db_base *db, const QString &name,
			const QModelIndex &parent)
{
	for (int row = 0; row < db->rowCount(parent); row++) {
		QModelIndex idx = db->index(row, 0, parent);
		pki_base *pki = db_base::fromIndex(idx);
		if (pki && pki->getIntName() == name)
			return true;
		if (inModel(db, name, idx))
			return true;
	}
	return false;
}

IssuanceSpec test_service_memory::caSpec(const QString &cn, pki_key *key,
			int years)
{
	QDateTime now = QDateTime::currentDateTimeUtc();
	IssuanceSpec spec;
	spec.name = cn;
	spec.subject.addEntryByNid(NID_commonName, cn);
	spec.key = key;
	spec.notBefore = a1time(now.addDays(-1));
	spec.notAfter = a1time(now.addYears(years));
	spec.hashAlgo = digest(NID_sha256);
	spec.extensions.subjectKeyId = true;
	spec.extensions.authorityKeyId = true;
	spec.extensions.basicCA = ExtensionSpec::bc_ca;
	spec.extensions.basicCritical = true;
	spec.extensions.keyUsage << "keyCertSign" << "cRLSign";
	return spec;
}

pki_x509 *test_service_memory::issue(const QString &cn, pki_x509 *signer)
{
	if (!signer)
		return Database.model<db_x509>()->newCert(ctx,
				caSpec(cn, newKey(cn + " key"), 1));
	QDateTime now = QDateTime::currentDateTimeUtc();
	IssuanceSpec spec;
	spec.name = cn;
	spec.subject.addEntryByNid(NID_commonName, cn);
	spec.key = newKey(cn + " key");
	spec.signer = signer;
	spec.notBefore = a1time(now.addDays(-1));
	spec.notAfter = a1time(now.addMonths(6));
	spec.hashAlgo = digest(NID_sha256);
	spec.extensions.basicCA = ExtensionSpec::bc_not_ca;
	spec.extensions.keyUsage << "digitalSignature";
	return Database.model<db_x509>()->newCert(ctx, spec);
}

/* Writes pki in the export format with that id, unencrypted */
QString test_service_memory::exportFile(pki_base *pki, int format,
			const QString &name)
{
	ExportSpec spec;
	spec.items << pki;
	spec.format = pki_export::by_id(format);
	spec.fileName = dir.filePath(name);
	Database.modelForPki(pki)->exportItems(ctx, spec);
	return spec.fileName;
}

int test_service_memory::entries(const QString &action,
			const QString &result)
{
	int n = 0;
	for (const AuditEntry &e : AuditLog::entries())
		if (e.action == action && e.result == result)
			n++;
	return n;
}

void test_service_memory::cleanup()
{
	bool pending = DbTransaction::injectionPending();
	DbTransaction::injectNestedRollback(-1);
	ServiceTestCase::cleanup();
	QVERIFY(!pending);
}

/* Three keys, the second one cannot be deleted: the first was gone from
 * store and view (and freed) although the database kept all three */
void test_service_memory::deleteSecondFailsKeepsAll()
{
	QList<pki_base *> keys;
	for (const char *name : { "BTD-130 a", "BTD-130 b", "BTD-130 c" })
		keys << newKey(name);
	QVERIFY(!keys.contains(nullptr));
	const db_key *db = Database.model<db_key>();

	sql("CREATE TEMP TRIGGER btd130_delete BEFORE UPDATE ON items "
		"WHEN NEW.del=1 AND OLD.name='BTD-130 b' BEGIN SELECT "
		"RAISE(ABORT, 'BTD-130 test: delete refused'); END");
	QCOMPARE(errorCode([&]() {
		Database.model<db_key>()->deleteItems(ctx, keys); }),
		QString("database_error"));
	sql("DROP TRIGGER temp.btd130_delete");

	for (const char *name : { "BTD-130 a", "BTD-130 b", "BTD-130 c" }) {
		QVERIFY2(inStore(name) == 1, name);
		QVERIFY2(inModel(db, name), name);
	}
	for (pki_base *key : keys)
		QVERIFY(db->isStored(key));
	QCOMPARE(count("SELECT COUNT(*) FROM items "
		"WHERE name LIKE 'BTD-130 _' AND del=0"), 3);
	QCOMPARE(entries("object.delete", "success"), 0);
	QCOMPARE(entries("object.delete", "failure"), 1);
}

/* All three deleted, the commit fails: all three stay */
void test_service_memory::deleteCommitFailsKeepsAll()
{
	QList<pki_base *> keys;
	for (const char *name : { "BTD-130 a", "BTD-130 b", "BTD-130 c" })
		keys << newKey(name);
	QVERIFY(!keys.contains(nullptr));
	const db_key *db = Database.model<db_key>();

	DbTransaction::injectNestedRollback();
	QCOMPARE(errorCode([&]() {
		Database.model<db_key>()->deleteItems(ctx, keys); }),
		QString("database_error"));

	for (const char *name : { "BTD-130 a", "BTD-130 b", "BTD-130 c" }) {
		QVERIFY2(inStore(name) == 1, name);
		QVERIFY2(inModel(db, name), name);
	}
	QCOMPARE(count("SELECT COUNT(*) FROM items "
		"WHERE name LIKE 'BTD-130 _' AND del=0"), 3);

	/* and a later delete of the same objects succeeds */
	Database.model<db_key>()->deleteItems(ctx, keys);
	QCOMPARE(inStore("BTD-130 a"), 0);
	QVERIFY(!inModel(db, "BTD-130 c"));
	QCOMPARE(count("SELECT COUNT(*) FROM items "
		"WHERE name LIKE 'BTD-130 _' AND del=0"), 0);
}

void test_service_memory::newTemplateRollback()
{
	TemplateSpec spec;
	spec.name = "BTD-130 template";

	DbTransaction::injectNestedRollback();
	QCOMPARE(errorCode([&]() {
		Database.model<db_temp>()->newTemplate(ctx, spec); }),
		QString("database_error"));

	QCOMPARE(inStore("BTD-130 template"), 0);
	QVERIFY(!inModel(Database.model<db_temp>(), "BTD-130 template"));
	QCOMPARE(count("SELECT COUNT(*) FROM templates"), 0);
}

void test_service_memory::newKeyRollback()
{
	DbTransaction::injectNestedRollback();
	QCOMPARE(errorCode([&]() {
		Database.model<db_key>()->newKey(ctx,
			keyjob("EC:prime256v1"), "BTD-130 key"); }),
		QString("database_error"));

	QCOMPARE(inStore("BTD-130 key"), 0);
	QVERIFY(!inModel(Database.model<db_key>(), "BTD-130 key"));
	QCOMPARE(count("SELECT COUNT(*) FROM items "
		"WHERE name='BTD-130 key'"), 0);
}

/* A rolled-back CA certificate must not stay selectable as a signer */
void test_service_memory::newCertRollback()
{
	pki_key *key = newKey("BTD-130 CA key");
	QVERIFY(key);
	IssuanceSpec spec = caSpec("BTD-130 CA", key, 1);

	DbTransaction::injectNestedRollback();
	QCOMPARE(errorCode([&]() {
		Database.model<db_x509>()->newCert(ctx, spec); }),
		QString("database_error"));

	QCOMPARE(inStore("BTD-130 CA"), 0);
	QVERIFY(!inModel(Database.model<db_x509>(), "BTD-130 CA"));
	QCOMPARE(Database.model<db_x509>()->getAllIssuers().size(), 0);
	QCOMPARE(count("SELECT COUNT(*) FROM certs"), 0);
	/* the key is untouched and still usable */
	QCOMPARE(inStore("BTD-130 CA key"), 1);
	QVERIFY(Database.model<db_x509>()->newCert(ctx, spec));
}

void test_service_memory::newRequestRollback()
{
	pki_key *key = newKey("BTD-130 request key");
	QVERIFY(key);
	RequestSpec spec;
	spec.name = "BTD-130 request";
	spec.subject.addEntryByNid(NID_commonName, "BTD-130 request");
	spec.key = key;
	spec.hashAlgo = digest(NID_sha256);

	DbTransaction::injectNestedRollback();
	QCOMPARE(errorCode([&]() {
		Database.model<db_x509req>()->newRequest(ctx, spec); }),
		QString("database_error"));

	QCOMPARE(inStore("BTD-130 request"), 0);
	QVERIFY(!inModel(Database.model<db_x509req>(), "BTD-130 request"));
	QCOMPARE(count("SELECT COUNT(*) FROM requests"), 0);
}

void test_service_memory::newCrlRollback()
{
	pki_x509 *ca = issue("BTD-130 CA", nullptr);
	QVERIFY(ca);
	pki_x509 *ee = issue("BTD-130 device", ca);
	QVERIFY(ee);
	x509rev rev;
	rev.setReason("Key Compromise");
	Database.model<db_x509>()->revoke(ctx, ee, rev);

	DbTransaction::injectNestedRollback();
	QCOMPARE(errorCode([&]() {
		Database.model<db_crl>()->newCrl(ctx, crljob(ca)); }),
		QString("database_error"));

	QCOMPARE(Store.getAll<pki_crl>().size(), 0);
	QCOMPARE(Database.model<db_crl>()->rowCount(), 0);
	QCOMPARE(count("SELECT COUNT(*) FROM crls"), 0);
	/* a new CRL of the CA works */
	QVERIFY(Database.model<db_crl>()->newCrl(ctx, crljob(ca)));
}

/* A batch import: a private key that completes a public key of the
 * database, then a CRL of a CA of the database that revokes one of its
 * certificates; the CRL's audit entry fails. The public key was freed,
 * the CA kept the CRL's revocations and the certificate was flagged
 * revoked, although the database rolled all of it back. */
void test_service_memory::importCompletedKeyAndCrlRollback()
{
	pki_x509 *ca = issue("BTD-130 CA", nullptr);
	QVERIFY(ca);
	pki_x509 *ee = issue("BTD-130 device", ca);
	QVERIFY(ee);
	x509rev rev;
	rev.setReason("Key Compromise");
	Database.model<db_x509>()->revoke(ctx, ee, rev);
	pki_crl *crl = Database.model<db_crl>()->newCrl(ctx, crljob(ca));
	QVERIFY(crl);
	QByteArray crlDer = crl->i2d();
	Database.model<db_crl>()->deleteItems(ctx, { crl });
	Database.model<db_x509>()->unrevoke(ctx, ee);
	QCOMPARE(ca->getRevList().size(), 0);
	QVERIFY(!ee->isRevoked());

	pki_key *key = newKey("BTD-130 completed");
	QVERIFY(key);
	QString pub = exportFile(key, 19, "public.pem");
	QString priv = exportFile(key, 20, "private.pem");
	Database.model<db_key>()->deleteItems(ctx, { key });
	ImportSpec pubSpec;
	pubSpec.files << pub;
	ImportResult pubResult = Database.importItems(ctx, pubSpec);
	QCOMPARE(pubResult.created.size(), 1);
	Database.model<db_key>()->rename(ctx, pubResult.created[0],
					"BTD-130 completed");
	QCOMPARE(inStore("BTD-130 completed"), 1);

	sql("CREATE TEMP TRIGGER btd130_import BEFORE INSERT ON audit_log "
		"WHEN NEW.action='object.import' AND NEW.result='success' "
		"AND NEW.object_type='crl' BEGIN SELECT RAISE(ABORT, "
		"'BTD-130 test: audit refused'); END");
	ImportSpec spec;
	spec.files << priv;
	spec.data = crlDer;
	spec.dataName = "btd130.crl";
	QVERIFY(!errorCode([&]() { Database.importItems(ctx, spec); })
		.isEmpty());
	sql("DROP TRIGGER temp.btd130_import");

	/* the public key is back, still public */
	QCOMPARE(inStore("BTD-130 completed"), 1);
	QVERIFY(inModel(Database.model<db_key>(), "BTD-130 completed"));
	for (pki_key *k : Store.getAll<pki_key>())
		if (k->getIntName() == "BTD-130 completed")
			QVERIFY(k->isPubKey());
	QCOMPARE(count("SELECT COUNT(*) FROM private_keys p JOIN items i "
		"ON p.item=i.id WHERE i.name='BTD-130 completed'"), 0);
	/* the CA and the certificate as before the import */
	QCOMPARE(ca->getRevList().size(), 0);
	QVERIFY(!ee->isRevoked());
	QCOMPARE(Store.getAll<pki_crl>().size(), 0);
	QCOMPARE(count("SELECT COUNT(*) FROM crls"), 0);
	QCOMPARE(count("SELECT COUNT(*) FROM revocations"), 0);
}

/* A newer CA certificate with the subject and key of a CA of the
 * database takes over its children when it is stored. Its import fails:
 * the children go back to the old CA, and taking the new certificate out
 * of the view writes nothing to the database (it wrote
 * "UPDATE certs SET issuer" in a transaction of its own). */
void test_service_memory::importRollbackWritesNoSql()
{
	pki_key *key = newKey("BTD-130 CA key");
	QVERIFY(key);
	pki_x509 *ca = Database.model<db_x509>()->newCert(ctx,
				caSpec("BTD-130 CA", key, 1));
	QVERIFY(ca);
	pki_x509 *ee = issue("BTD-130 device", ca);
	QVERIFY(ee);
	pki_x509 *renewed = Database.model<db_x509>()->newCert(ctx,
				caSpec("BTD-130 CA", key, 2));
	QVERIFY(renewed);
	QCOMPARE(ee->getSigner(), renewed);
	QString pem = exportFile(renewed, 1, "renewed.pem");
	Database.model<db_x509>()->deleteItems(ctx, { renewed });
	QCOMPARE(ee->getSigner(), ca);

	sql("CREATE TEMP TABLE btd130_writes (n INTEGER)");
	sql("CREATE TEMP TRIGGER btd130_count AFTER UPDATE ON certs "
		"BEGIN INSERT INTO btd130_writes VALUES (1); END");
	sql("CREATE TEMP TRIGGER btd130_import BEFORE INSERT ON audit_log "
		"WHEN NEW.action='object.import' AND NEW.result='success' "
		"BEGIN SELECT RAISE(ABORT, 'BTD-130 test: audit refused'); END");
	ImportSpec spec;
	spec.files << pem;
	QVERIFY(!errorCode([&]() { Database.importItems(ctx, spec); })
		.isEmpty());
	sql("DROP TRIGGER temp.btd130_import");
	sql("DROP TRIGGER temp.btd130_count");

	QCOMPARE(count("SELECT COUNT(*) FROM btd130_writes"), 0);
	QCOMPARE(ee->getSigner(), ca);
	QCOMPARE(ee->getParent(), (pki_base *)ca);
	QCOMPARE(Store.getAll<pki_x509>().size(), 2);
	QCOMPARE(count("SELECT COUNT(*) FROM certs"), 2);
}

/* A setting the database did not hold before, written in a transaction
 * that rolls back: memory goes back to the default, including what
 * setAction() set outside the settings map (BTD-186). The undo removed
 * the value and left the OpenSSL string mask of string_opt in place. */
void test_service_memory::settingWithoutStoredValueRollback()
{
	QSqlQuery q;
	QVERIFY(q.exec("DELETE FROM settings WHERE key_ IN "
		"('default_hash', 'string_opt')"));
	q.finish();
	Settings.clear();
	QString builtin = digest::getBuiltinDefault().name();
	QCOMPARE(digest::getDefault().name(), builtin);
	QString other = builtin == "SHA512" ? "SHA384" : "SHA512";
	unsigned long mask = ASN1_STRING_get_default_mask();
	{
		Transaction;
		QVERIFY(TransBegin());
		Settings["default_hash"] = other;
		Settings["string_opt"] = QString("utf8only");
		QCOMPARE(digest::getDefault().name(), other);
		QVERIFY(ASN1_STRING_get_default_mask() != mask);
		TransRollback();
	}
	QCOMPARE(digest::getDefault().name(), builtin);
	QCOMPARE(QString(Settings["default_hash"]), builtin);
	QCOMPARE(QString(Settings["string_opt"]), QString("MASK:0x2002"));
	QCOMPARE(ASN1_STRING_get_default_mask(), mask);
}

/* The PKCS#12 default migration of BTD-52 when its outer COMMIT fails
 * (a nested commit rolled back, review of xca#48 re-review MINOR 1):
 * database and memory keep the old algorithm, no marker, no entry */
void test_service_memory::pkcs12MigrationCommitFails()
{
	QSqlQuery q;
	QVERIFY(q.exec("DELETE FROM settings WHERE key_ IN ('pkcs12_migrated', "
		"'pkcs12_enc_algo', 'pkcs12_keep_legacy')"));
	QVERIFY(q.exec("INSERT INTO settings (key_, value) VALUES "
		"('pkcs12_enc_algo', 'PBE-SHA1-3DES')"));
	q.finish();
	int entries = AuditLog::entries().size();

	Database.close();
	/* the first nested commit of the open is the algorithm of the
	 * migration: it rolls back, the outer commit fails */
	DbTransaction::injectNestedRollback();
	openDatabase();
	QVERIFY(!DbTransaction::injectionPending());

	/* a query of the new connection */
	q = QSqlQuery();
	QVERIFY(q.exec("SELECT value FROM settings WHERE key_='pkcs12_enc_algo'")
		&& q.next());
	QCOMPARE(q.value(0).toString(), QString("PBE-SHA1-3DES"));
	q.finish();
	QVERIFY(q.exec("SELECT COUNT(*) FROM settings "
		"WHERE key_='pkcs12_migrated'") && q.next());
	QCOMPARE(q.value(0).toInt(), 0);
	q.finish();
	QVERIFY(encAlgo::getDefault().legacy());
	QCOMPARE(QString(Settings["pkcs12_enc_algo"]),
		QString("PBE-SHA1-3DES"));
	QVERIFY(!Settings["pkcs12_migrated"]);
	QCOMPARE(AuditLog::entries().size(), entries);
}

XCA_SERVICE_TEST_MAIN(test_service_memory)
#include "test_service_memory.moc"
