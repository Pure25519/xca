/* vi: set sw=4 ts=4:
 *
 * Replacing a software key by its copy on a token (BTD-217): the GUI
 * action "Store on Security token" writes the key to the token and then
 * calls db_key::replaceWithToken(). That is all or nothing: on a failed
 * store of the token key the software key, its comment and the links of
 * its certificate and request stay as they were, in the database and in
 * memory; on success the token key has the links and the software key is
 * gone, in one commit.
 *
 * No token is needed (BTD-126 is open): the token key is a pki_scard with
 * the public key of the software key, as store_token() leaves it.
 */

#include <QSqlError>
#include <QSqlQuery>

#include <openssl/evp.h>
#include <openssl/x509.h>

#include "lib/audit.h"
#include "lib/db_key.h"
#include "lib/db_x509.h"
#include "lib/db_x509req.h"
#include "lib/digest.h"
#include "lib/exception.h"
#include "lib/issuance.h"
#include "lib/pki_scard.h"
#include "lib/pki_x509.h"
#include "lib/pki_x509req.h"
#include "lib/request.h"

#include "ServiceTestCase.h"

/* The token key without a token: the public key, a card label */
class tokenCopy : public pki_scard
{
  public:
	tokenCopy(const QString &name, pki_key *software) : pki_scard(name)
	{
		unsigned char *der = nullptr;
		int len = i2d_PUBKEY(software->getPubKey(), &der);
		const unsigned char *p = der;
		/* pki_key() starts with an empty EVP_PKEY */
		EVP_PKEY_free(key);
		key = d2i_PUBKEY(nullptr, &p, len);
		OPENSSL_free(der);
		card_label = "BTD-217 card";
		card_serial = "217";
		card_manufacturer = "BTD-217";
		card_model = "test";
		slot_label = "BTD-217 slot";
	}
};

class test_service_token_replace : public ServiceTestCase
{
	Q_OBJECT

	ServiceContext ctx{ ServiceContext::gui, "os:service-test" };
	pki_key *key{};
	pki_x509 *cert{};
	pki_x509req *req{};

	static void sql(const QString &statement)
	{
		QSqlQuery q;
		if (!q.exec(statement))
			qFatal("%s: %s", qPrintable(statement),
				qPrintable(q.lastError().text()));
	}
	static QVariant value(const QString &statement)
	{
		QSqlQuery q;
		return q.exec(statement) && q.next() ? q.value(0) : QVariant();
	}
	/* a key with a self-signed certificate and a request of its own */
	void keyWithLinks()
	{
		key = Database.model<db_key>()->newKey(ctx,
				keyjob("EC:prime256v1"), "BTD-217 key");
		QVERIFY(key);
		Database.model<db_key>()->updateProperties(ctx, key,
				"BTD-217 key", "software key comment");
		IssuanceSpec spec;
		spec.name = "BTD-217 cert";
		spec.subject.addEntryByNid(NID_commonName, "BTD-217 cert");
		spec.key = key;
		spec.notBefore = a1time(QDateTime::currentDateTimeUtc()
					.addDays(-1));
		spec.notAfter = a1time(QDateTime::currentDateTimeUtc()
					.addDays(30));
		spec.hashAlgo = digest(NID_sha256);
		spec.extensions.basicCA = ExtensionSpec::bc_ca;
		spec.extensions.keyUsage << "keyCertSign";
		cert = Database.model<db_x509>()->newCert(ctx, spec);
		QVERIFY(cert);
		RequestSpec rs;
		rs.name = "BTD-217 request";
		rs.subject.addEntryByNid(NID_commonName, "BTD-217 request");
		rs.key = key;
		rs.hashAlgo = digest(NID_sha256);
		rs.extensions.basicCA = ExtensionSpec::bc_not_ca;
		req = Database.model<db_x509req>()->newRequest(ctx, rs);
		QVERIFY(req);
	}
	/* the item id the pkey column of the certificate and the request
	 * point to */
	static QString links(pki_base *cert, pki_base *req)
	{
		return value(QString("SELECT pkey FROM x509super WHERE item=%1")
			.arg(cert->getSqlItemId().toString())).toString() + "," +
			value(QString("SELECT pkey FROM x509super WHERE item=%1")
			.arg(req->getSqlItemId().toString())).toString();
	}

  private slots:
	void cleanup();
	void failedStoreKeepsSoftwareKey();
	void replacementMovesLinks();
};

void test_service_token_replace::cleanup()
{
	QSqlQuery("DROP TRIGGER IF EXISTS temp.btd217_refuse");
	ServiceTestCase::cleanup();
}

void test_service_token_replace::failedStoreKeepsSoftwareKey()
{
	keyWithLinks();
	QString id = key->getSqlItemId().toString();
	QString before = links(cert, req);
	QCOMPARE(before, id + "," + id);
	int entries = AuditLog::entries().size();

	tokenCopy *card = new tokenCopy("BTD-217 key", key);
	sql("CREATE TEMP TRIGGER btd217_refuse BEFORE INSERT ON tokens "
		"BEGIN SELECT RAISE(ABORT, 'BTD-217 test: token key refused'); END");
	QString code;
	try {
		Database.model<db_key>()->replaceWithToken(ctx, key, card);
	} catch (serviceError &err) {
		code = err.code;
	}
	sql("DROP TRIGGER temp.btd217_refuse");
	QCOMPARE(code, QString("database_error"));
	/* the card is the caller's again */
	QVERIFY(!card->getSqlItemId().isValid());
	delete card;

	/* the software key, its comment and its links, in the database */
	QCOMPARE(value(QString("SELECT del FROM items WHERE id=%1").arg(id))
			.toInt(), 0);
	QCOMPARE(value(QString("SELECT comment FROM items WHERE id=%1")
			.arg(id)).toString(), QString("software key comment"));
	QCOMPARE(links(cert, req), before);
	QCOMPARE(value("SELECT COUNT(*) FROM tokens").toInt(), 0);
	/* and in memory */
	QCOMPARE(Store.lookupPki<pki_key>(key->getSqlItemId()), key);
	QVERIFY(cert->getRefKey() == key);
	QVERIFY(req->getRefKey() == key);
	/* no audit entry claims the delete */
	for (const AuditEntry &e : AuditLog::entries().mid(entries))
		QVERIFY2(e.result != "success", CCHAR(e.action));
}

void test_service_token_replace::replacementMovesLinks()
{
	keyWithLinks();
	QString id = key->getSqlItemId().toString();
	int entries = AuditLog::entries().size();

	tokenCopy *card = new tokenCopy("BTD-217 key", key);
	pki_key *stored = Database.model<db_key>()->replaceWithToken(ctx,
							key, card);
	QVERIFY(stored == card);
	QString cardId = card->getSqlItemId().toString();
	QVERIFY(!cardId.isEmpty());
	QCOMPARE(links(cert, req), cardId + "," + cardId);
	QCOMPARE(value(QString("SELECT del FROM items WHERE id=%1").arg(id))
			.toInt(), 1);
	QCOMPARE(value("SELECT COUNT(*) FROM tokens").toInt(), 1);
	QVERIFY(cert->getRefKey() == card);
	QVERIFY(req->getRefKey() == card);
	QStringList actions;
	for (const AuditEntry &e : AuditLog::entries().mid(entries))
		if (e.action != AuditLog::actionCheckpoint &&
		    e.action != AuditLog::actionKeyCreate)
			actions << e.action + ":" + e.result;
	QVERIFY2(actions.contains("object.delete:success"),
		CCHAR(actions.join(" ")));
}

XCA_SERVICE_TEST_MAIN(test_service_token_replace)
#include "test_service_token_replace.moc"
