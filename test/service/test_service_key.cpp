/* vi: set sw=4 ts=4:
 *
 * Sample service test: key generation through db_key::newKey(keyjob, name),
 * the GUI-free path behind "New key".
 */

#include <QFile>
#include <QProcess>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QTemporaryDir>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/db_key.h"
#include "lib/exception.h"
#include "lib/json_report.h"
#include "lib/pki_evp.h"
#include "lib/pki_export.h"

#include "ServiceTestCase.h"

/* The key types without size or curve (BTD-16) and the size of their
 * raw public key in bytes, which KeyDetail shows */
static const QList<QPair<QString, int>> fixedTypes {
	{ "ED25519", 32 }, { "ED448", 57 },
	{ "ML-DSA-44", 1312 }, { "ML-DSA-65", 1952 }, { "ML-DSA-87", 2592 },
	{ "SLH-DSA-SHA2-128s", 32 }, { "SLH-DSA-SHA2-128f", 32 },
	{ "SLH-DSA-SHA2-192s", 48 }, { "SLH-DSA-SHA2-192f", 48 },
	{ "SLH-DSA-SHA2-256s", 64 }, { "SLH-DSA-SHA2-256f", 64 },
	{ "SLH-DSA-SHAKE-128s", 32 }, { "SLH-DSA-SHAKE-128f", 32 },
	{ "SLH-DSA-SHAKE-192s", 48 }, { "SLH-DSA-SHAKE-192f", 48 },
	{ "SLH-DSA-SHAKE-256s", 64 }, { "SLH-DSA-SHAKE-256f", 64 },
};

class test_service_key : public ServiceTestCase
{
	Q_OBJECT

	ServiceContext ctx{ ServiceContext::cli, "os:service-test" };

	static pki_key *onlyKey()
	{
		QList<pki_key*> keys = Store.getAll<pki_key>();
		return keys.size() == 1 ? keys[0] : nullptr;
	}
	static AuditEntry lastEntry()
	{
		QList<AuditEntry> list = AuditLog::entries();
		return list.isEmpty() ? AuditEntry() : list.last();
	}
	static QString pkeyText(EVP_PKEY *pkey, int *exitCode);
	static QVariant sqlValue(const QString &statement)
	{
		QSqlQuery q(QSqlDatabase::database());
		if (!q.exec(statement) || !q.next())
			return QVariant();
		return q.value(0);
	}
	static void fixedTypeRows();

  private slots:
	void newKey_data();
	void newKey();
	void newKeySize_data();
	void newKeySize();
	void newKeyRejectedSize_data();
	void newKeyRejectedSize();
	void newKeySmallRsaConfirmed();
	void newKeySmallRsaDeclined();
	void newKeySmallRsaHeadless_data();
	void newKeySmallRsaHeadless();
	void newKeySmallRsaHeadlessUnconfirmed_data();
	void newKeySmallRsaHeadlessUnconfirmed();
	void newKeyTooSmall();
	void keyjobParse_data();
	void keyjobParse();
	void keytypeList();
	void newKeyFixed_data();
	void newKeyFixed();
	void newKeyFixedWithSize_data();
	void newKeyFixedWithSize();
	void newKeyUnknownType_data();
	void newKeyUnknownType();
	void compareFixed();
	void exportFlagsFixed_data();
	void exportFlagsFixed();
	void nidOfGeneratedKey_data();
	void nidOfGeneratedKey();
};

void test_service_key::fixedTypeRows()
{
	QTest::addColumn<QString>("name");
	QTest::addColumn<int>("pubLen");

	for (const auto &t : fixedTypes)
		QTest::newRow(CCHAR(t.first)) << t.first << t.second;
}

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
	QCOMPARE(keytype::nid(pkey), keytype::byName(type).type);
	EVP_PKEY_free(pkey);
}

/* openssl pkey -text of the public key */
QString test_service_key::pkeyText(EVP_PKEY *pkey, int *exitCode)
{
	*exitCode = -1;
#ifdef OPENSSL_PROGRAM
	QTemporaryDir dir;
	if (!dir.isValid())
		return QString();
	QString file = dir.filePath("key.pub.pem");
	BIO *b = BIO_new_file(QFile::encodeName(file).constData(), "w");
	if (!b)
		return QString();
	int ok = PEM_write_bio_PUBKEY(b, pkey);
	BIO_free(b);
	if (!ok)
		return QString();

	QProcess p;
	p.setProcessChannelMode(QProcess::MergedChannels);
	p.start(OPENSSL_PROGRAM, { "pkey", "-pubin", "-in", file,
				"-noout", "-text" });
	if (p.waitForFinished(30000))
		*exitCode = p.exitCode();
	return QString::fromUtf8(p.readAll());
#else
	(void)pkey;
	return QString();
#endif
}

void test_service_key::newKeySize_data()
{
	QTest::addColumn<QString>("job");
	QTest::addColumn<int>("bits");
	QTest::addColumn<QString>("text");

	/* RSA 2048 is OpenSSL's default size: alone it proves nothing */
	QTest::newRow("RSA 2048") << "RSA:2048" << 2048
			<< "Public-Key: (2048 bit)";
	QTest::newRow("RSA 3072") << "RSA:3072" << 3072
			<< "Public-Key: (3072 bit)";
	QTest::newRow("RSA 4096") << "RSA:4096" << 4096
			<< "Public-Key: (4096 bit)";
	QTest::newRow("DSA 2048") << "DSA:2048" << 2048
			<< "Public-Key: (2048 bit)";
#ifndef OPENSSL_NO_EC
	QTest::newRow("EC prime256v1") << "EC:prime256v1" << 256
			<< "ASN1 OID: prime256v1";
	QTest::newRow("EC secp384r1") << "EC:secp384r1" << 384
			<< "ASN1 OID: secp384r1";
#ifdef EVP_PKEY_ED25519
	QTest::newRow("ED25519") << "ED25519" << 256
			<< "ED25519 Public-Key:";
#endif
#endif
}

/* The key has the requested size, in the key, in the audit entry and
 * as the openssl program reads it (BTD-94) */
void test_service_key::newKeySize()
{
	QFETCH(QString, job);
	QFETCH(int, bits);
	QFETCH(QString, text);

	pki_key *key = Database.model<db_key>()->newKey(ctx, keyjob(job),
							"sized-key");
	QVERIFY(key);
	QCOMPARE(EVP_PKEY_get_bits(key->getPubKey()), bits);

	AuditEntry e = lastEntry();
	QCOMPARE(e.action, QString("key.generate"));
	QCOMPARE(e.result, QString("success"));
	QCOMPARE(e.params["key_size"].toInt(), bits);

#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#endif
	int rc;
	QString out = pkeyText(key->getPubKey(), &rc);
	QCOMPARE(rc, 0);
	QVERIFY2(out.contains(text), CCHAR(out));
}

void test_service_key::newKeyRejectedSize_data()
{
	QTest::addColumn<QString>("job");
	QTest::addColumn<int>("bits");

	/* above the service's lower bound (32), below OpenSSL's */
	QTest::newRow("RSA 100") << "RSA:100" << 100;
	QTest::newRow("DSA 100") << "DSA:100" << 100;
}

/* A size OpenSSL rejects fails, it does not become OpenSSL's default */
void test_service_key::newKeyRejectedSize()
{
	QFETCH(QString, job);
	QFETCH(int, bits);
	int before = AuditLog::entries().size();

	try {
		Database.model<db_key>()->newKey(ctx, keyjob(job), "bad-size");
		QFAIL("newKey accepted the size");
	} catch (serviceError &err) {
		QCOMPARE(err.code, QString("invalid_key_size"));
	}
	QCOMPARE(Store.getAll<pki_key>().size(), 0);
	QCOMPARE(AuditLog::entries().size(), before + 1);
	AuditEntry e = lastEntry();
	QCOMPARE(e.action, QString("key.generate"));
	QCOMPARE(e.result, QString("failure"));
	QCOMPARE(e.errorCode, QString("invalid_key_size"));
	QVERIFY(e.objectId.isEmpty());
	QCOMPARE(e.params["key_size"].toInt(), bits);
	QVERIFY(AuditLog::verify().ok());
}

void test_service_key::newKeySmallRsaConfirmed()
{
	/* Below 1024 bit, newKey() asks before generating */
	warning->expectQuestion(true);
	pki_key *key = Database.model<db_key>()->newKey(
				keyjob("RSA:768"), "small-key");
	QVERIFY(key);
	QCOMPARE(key->getIntName(), QString("small-key"));
	QCOMPARE(EVP_PKEY_get_bits(key->getPubKey()), 768);
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

void test_service_key::keyjobParse_data()
{
	QTest::addColumn<QString>("desc");
	QTest::addColumn<bool>("valid");
	QTest::addColumn<QString>("canonical");

	QTest::newRow("lower case") << "ml-dsa-65" << true << "ML-DSA-65";
	QTest::newRow("ED448") << "ED448" << true << "ED448";
	QTest::newRow("SLH-DSA mixed case") << "slh-dsa-shake-256F" << true
			<< "SLH-DSA-SHAKE-256f";
	QTest::newRow("ed25519") << "ed25519" << true << "ED25519";
	QTest::newRow("RSA") << "RSA:3072" << true << "RSA:3072";
#ifndef OPENSSL_NO_EC
	QTest::newRow("EC") << "ec:prime256v1" << true << "EC:prime256v1";
#endif
	/* Rejected, never silently dropped (PLAN.md 8.4) */
	QTest::newRow("ML-DSA with size") << "ML-DSA-65:2048" << false << "";
	QTest::newRow("Ed25519 with size") << "ED25519:256" << false << "";
	QTest::newRow("unknown ML-DSA") << "ML-DSA-99" << false << "";
	QTest::newRow("unknown Edwards") << "ED449" << false << "";
}

/* --keygen and the remembered default key take the OpenSSL name in any
 * case; the job prints it in the canonical spelling */
void test_service_key::keyjobParse()
{
	QFETCH(QString, desc);
	QFETCH(bool, valid);
	QFETCH(QString, canonical);

	keyjob job(desc);
	QCOMPARE(job.isValid(), valid);
	if (valid)
		QCOMPARE(job.toString(), canonical);
}

/* Every fixed type is offered, once, under the name OpenSSL uses */
void test_service_key::keytypeList()
{
	QStringList names;
	for (const keytype &t : keytype::types())
		names << t.name;
	for (const auto &t : fixedTypes) {
		QCOMPARE(names.count(t.first), 1);
		keytype k = keytype::byName(t.first);
		QVERIFY(k.fixed());
		QCOMPARE(k.traditionalPemName(), QString("PRIVATE KEY"));
		if (t.first.startsWith("ED"))
			QCOMPARE(k.type, OBJ_sn2nid(CCHAR(t.first)));
		else
			QCOMPARE(k.type, OBJ_ln2nid(CCHAR(t.first)));
	}
	for (const char *n : { "RSA", "DSA", "EC" }) {
		QVERIFY(!keytype::byName(n).fixed());
		QCOMPARE(keytype::byName(n).traditionalPemName(),
			QString("%1 PRIVATE KEY").arg(n));
	}
}

void test_service_key::newKeyFixed_data()
{
	fixedTypeRows();
}

/* Generated through the service, stored with its full type name, read
 * back after reopening: the key type resolves for keys that OpenSSL
 * knows only by name (EVP_PKEY_get_id() -1, BTD-16) */
void test_service_key::newKeyFixed()
{
	QFETCH(QString, name);
	QFETCH(int, pubLen);

	keytype t = keytype::byName(name);
	QVERIFY2(t.isValid(), CCHAR(name));

	pki_key *key = Database.model<db_key>()->newKey(ctx, keyjob(name),
							"fixed-key");
	QVERIFY(key);
	QCOMPARE(key->getKeyType(), t.type);
	QCOMPARE(key->getKeyTypeString(), name);
	QCOMPARE(QString(EVP_PKEY_get0_type_name(key->getPubKey())).toUpper(),
			name.toUpper());
	/* KeyDetail shows the raw public key, the key list its bits */
	QCOMPARE(key->QByteArrayParam(OSSL_PKEY_PARAM_PUB_KEY).size(), pubLen);
	QCOMPARE(key->length(), QString("%1 bit").arg(pubLen * 8));

	AuditEntry e = lastEntry();
	QCOMPARE(e.action, QString("key.generate"));
	QCOMPARE(e.result, QString("success"));
	QCOMPARE(e.params["key_type"].toString(), name);
	QCOMPARE(e.params["key_size"].toInt(), pubLen * 8);
	QVERIFY(!e.params.contains("curve"));

	/* --print --json names the type like the GUI (BTD-39) */
	QJsonObject pub = JsonReport::key(key)["public_key"].toObject();
	QCOMPARE(pub["type"].toString(), name);
	QCOMPARE(pub["size"].toInt(), pubLen * 8);
	QVERIFY(pub["curve"].isNull());

	/* The full name in the database, not the first four characters */
	QCOMPARE(sqlValue("SELECT type FROM public_keys").toString(), name);
	QCOMPARE(sqlValue("SELECT key_type FROM view_public_keys").toString(),
			name);

	reopenDatabase();
	key = onlyKey();
	QVERIFY(key);
	QCOMPARE(key->getKeyType(), t.type);
	QCOMPARE(key->getKeyTypeString(), name);
	QVERIFY(key->isPrivKey());
	EVP_PKEY *pkey = key->decryptKey();
	QVERIFY(pkey);
	QCOMPARE(keytype::nid(pkey), t.type);
	QCOMPARE(EVP_PKEY_eq(pkey, key->getPubKey()), 1);
	/* ML-DSA keeps its seed in the database (RFC 9881 export, BTD-16) */
	if (name.startsWith("ML-DSA")) {
		size_t len = 0;
		QVERIFY(EVP_PKEY_get_octet_string_param(pkey,
			OSSL_PKEY_PARAM_ML_DSA_SEED, nullptr, 0, &len));
		QCOMPARE(len, size_t(32));
	}
	EVP_PKEY_free(pkey);

#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#endif
	int rc;
	QString out = pkeyText(key->getPubKey(), &rc);
	QCOMPARE(rc, 0);
	QVERIFY2(out.startsWith(name + " Public-Key:"), CCHAR(out));
}

void test_service_key::newKeyFixedWithSize_data()
{
	QTest::addColumn<QString>("job");
	QTest::addColumn<QString>("type");

	QTest::newRow("ML-DSA") << "ML-DSA-65:2048" << "ML-DSA-65";
	QTest::newRow("SLH-DSA") << "SLH-DSA-SHA2-128s:128"
			<< "SLH-DSA-SHA2-128s";
	QTest::newRow("Ed25519") << "ED25519:256" << "ED25519";
}

/* A size for a type without size fails instead of being dropped */
void test_service_key::newKeyFixedWithSize()
{
	QFETCH(QString, job);
	QFETCH(QString, type);
	int before = AuditLog::entries().size();

	try {
		Database.model<db_key>()->newKey(ctx, keyjob(job), "sized");
		QFAIL("newKey accepted a size for a fixed key type");
	} catch (serviceError &err) {
		QCOMPARE(err.code, QString("invalid_key_size"));
	}
	QCOMPARE(Store.getAll<pki_key>().size(), 0);
	QCOMPARE(AuditLog::entries().size(), before + 1);
	AuditEntry e = lastEntry();
	QCOMPARE(e.action, QString("key.generate"));
	QCOMPARE(e.result, QString("failure"));
	QCOMPARE(e.errorCode, QString("invalid_key_size"));
	QCOMPARE(e.params["key_type"].toString(), type);
	QVERIFY(!e.params.contains("key_size"));
	QVERIFY(AuditLog::verify().ok());
}

void test_service_key::newKeyUnknownType_data()
{
	QTest::addColumn<QString>("job");

	QTest::newRow("ML-DSA-99") << "ML-DSA-99";
	QTest::newRow("ED449") << "ED449";
}

void test_service_key::newKeyUnknownType()
{
	QFETCH(QString, job);

	try {
		Database.model<db_key>()->newKey(ctx, keyjob(job), "unknown");
		QFAIL("newKey accepted an unknown key type");
	} catch (serviceError &err) {
		QCOMPARE(err.code, QString("invalid_key_type"));
	}
	QCOMPARE(Store.getAll<pki_key>().size(), 0);
	AuditEntry e = lastEntry();
	QCOMPARE(e.result, QString("failure"));
	QCOMPARE(e.errorCode, QString("invalid_key_type"));
	QCOMPARE(e.params["name"].toString(), QString("unknown"));
	QVERIFY(AuditLog::verify().ok());
}

/* pki_key::compare() checks the type first: keys that OpenSSL knows
 * only by name must not all look alike (type -1) */
void test_service_key::compareFixed()
{
	db_key *keys = Database.model<db_key>();
	pki_key *a = keys->newKey(ctx, keyjob("ML-DSA-65"), "a");
	pki_key *b = keys->newKey(ctx, keyjob("ML-DSA-65"), "b");
	pki_key *c = keys->newKey(ctx, keyjob("SLH-DSA-SHA2-128f"), "c");
	QVERIFY(a && b && c);

	EVP_PKEY *dup = EVP_PKEY_dup(a->getPubKey());
	QVERIFY(dup);
	pki_evp copy(dup);
	QCOMPARE(copy.getKeyType(), a->getKeyType());
	QVERIFY(a->compare(&copy));
	QVERIFY(!a->compare(b));
	QVERIFY(!a->compare(c));
	/* the database finds the stored key for the same public key */
	QCOMPARE(keys->getByReference(&copy), static_cast<pki_base*>(a));
}

void test_service_key::exportFlagsFixed_data()
{
	fixedTypeRows();
}

/* Export formats the type does not have are not offered: no PVK, no
 * traditional PEM, no JWK; SSH only for Ed25519 */
void test_service_key::exportFlagsFixed()
{
	QFETCH(QString, name);

	db_key *keys = Database.model<db_key>();
	pki_key *key = keys->newKey(ctx, keyjob(name), "flags");
	QVERIFY(key);
	int disabled = keys->exportFlags(key);
	QVERIFY(disabled & F_PVK);
	QVERIFY(disabled & F_TRADITION);
	QVERIFY(disabled & F_JWK);
	QCOMPARE(bool(disabled & F_SSH2), name != "ED25519");
	QCOMPARE(key->SSH2_compatible(), name == "ED25519");
}

void test_service_key::nidOfGeneratedKey_data()
{
	fixedTypeRows();
}

/* A key generated from its NID (pki_evp::generate) carries the NID,
 * which EVP_PKEY_type() does not know; a decoded one has none (-1) and
 * resolves by name. The stored public key is a decoded one and hid
 * this; the private key in encryptKey() is the generated one */
void test_service_key::nidOfGeneratedKey()
{
	QFETCH(QString, name);
	keytype t = keytype::byName(name);
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(t.type, nullptr);
	EVP_PKEY *pkey = nullptr;
	QVERIFY(ctx && EVP_PKEY_keygen_init(ctx) > 0 &&
		EVP_PKEY_keygen(ctx, &pkey) > 0);
	EVP_PKEY_CTX_free(ctx);
	QCOMPARE(keytype::nid(pkey), t.type);
	EVP_PKEY_free(pkey);
	pkey = EVP_PKEY_Q_keygen(nullptr, nullptr, CCHAR(name));
	QVERIFY(pkey);
	QCOMPARE(keytype::nid(pkey), t.type);
	EVP_PKEY_free(pkey);
}

XCA_SERVICE_TEST_MAIN(test_service_key)
#include "test_service_key.moc"
