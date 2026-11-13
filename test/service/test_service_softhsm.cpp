/* vi: set sw=4 ts=4:
 *
 * The token paths of BTD-35 with a real token (BTD-126): a SoftHSM v2
 * token per run (test/SoftHsmToken.h), keys generated on it, a
 * certificate stored on it, renamed and deleted on the token, and the
 * failure of a wrong PIN. The result is read back from the token, the
 * database and the audit log. Without SOFTHSM2_MODULE every test skips
 * with the reason.
 *
 * The process maps exactly one libcrypto, libcrypto.so.4, also with the
 * module loaded (one-libcrypto, BTD-251), and no PIN shows in a message
 * or in the audit log.
 */

#include <QSqlQuery>

#include <openssl/evp.h>

#include "lib/audit.h"
#include "lib/db_key.h"
#include "lib/db_token.h"
#include "lib/db_x509.h"
#include "lib/digest.h"
#include "lib/exception.h"
#include "lib/issuance.h"
#include "lib/pkcs11.h"
#include "lib/pk11_attribute.h"
#include "lib/pki_scard.h"
#include "lib/pki_x509.h"

#include "test/SoftHsmToken.h"
#include "ServiceTestCase.h"

/* The token list of the Manage Tokens dialog, filled from the token */
class TokenObjects : public db_token
{
  public:
	void add(pki_base *pki)
	{
		rootItem->insert(pki);
	}
	~TokenObjects()
	{
		for (pki_base *pki : rootItem->getChildItems()) {
			rootItem->takeChild(pki);
			delete pki;
		}
	}
};

/* A token call that must succeed: its error is the test failure */
#define TRY(...) do { \
	try { __VA_ARGS__; } catch (errorEx &err) { \
		QFAIL(CCHAR("unexpected error: " + err.getString())); \
	} } while (0)

class test_service_softhsm : public ServiceTestCase
{
	Q_OBJECT

	ServiceContext ctx{ ServiceContext::cli, "os:service-test" };
	SoftHsmToken token{};
	QString skip{};

	static db_key *keys()
	{
		return Database.model<db_key>();
	}
	static AuditEntry last()
	{
		return AuditLog::entries().last();
	}
	/* a key generated on the token */
	pki_key *tokenKey(const QString &name)
	{
		keyjob job("EC:prime256v1");
		job.slot = token.slot();
		TokenPinScope pin;
		try {
			return keys()->newKey(ctx, job, name);
		} catch (errorEx &err) {
			qWarning() << "key generation on the token failed:"
				<< err.getString();
			return nullptr;
		}
	}
	/* a self-signed certificate of key */
	static pki_x509 *selfSigned(const ServiceContext &ctx, pki_key *key,
				    const QString &name)
	{
		IssuanceSpec spec;
		spec.name = name;
		spec.subject.addEntryByNid(NID_commonName, name);
		spec.key = key;
		spec.notBefore = a1time(QDateTime::currentDateTimeUtc()
					.addDays(-1));
		spec.notAfter = a1time(QDateTime::currentDateTimeUtc()
					.addDays(30));
		spec.hashAlgo = digest(NID_sha256);
		spec.extensions.basicCA = ExtensionSpec::bc_not_ca;
		TokenPinScope pin;
		try {
			return Database.model<db_x509>()->newCert(ctx, spec);
		} catch (errorEx &err) {
			qWarning() << "issuing" << name << "with the token key:"
				<< err.getString();
			return nullptr;
		}
	}
	/* the object of class cls with label name, as the token list of the
	 * Manage Tokens dialog reads it */
	pki_base *fromToken(TokenObjects &list, unsigned long cls,
			    const QString &name)
	{
		try {
			return readFromToken(list, cls, name);
		} catch (errorEx &err) {
			qWarning() << "reading" << name << "from the token:"
				<< err.getString();
			return nullptr;
		}
	}
	pki_base *readFromToken(TokenObjects &list, unsigned long cls,
			    const QString &name)
	{
		TokenPinScope pin;
		pkcs11 p11;
		p11.startSession(token.slot());
		p11.tokenLogin(SoftHsmToken::label, false);
		pk11_attlist atts(pk11_attr_ulong(CKA_CLASS, cls));
		atts << pk11_attr_data(CKA_LABEL, name.toUtf8());
		QList<CK_OBJECT_HANDLE> found = p11.objectList(atts);
		if (found.size() != 1)
			return nullptr;
		pki_base *pki;
		if (cls == CKO_CERTIFICATE) {
			pki_x509 *c = new pki_x509(name);
			c->load_token(p11, found[0]);
			pki = c;
		} else {
			pki_scard *k = new pki_scard(name);
			k->load_token(p11, found[0]);
			pki = k;
		}
		p11.logout();
		list.setSlot(token.slot());
		list.add(pki);
		return pki;
	}

  private slots:
	void initTestCase();
	void init();
	void cleanup();
	void cleanupTestCase();

	void oneLibcryptoWithModule();
	void storeRsaKeyOnToken();
	void storeEcKeyOnToken();
	void generateOnToken();
	void renameKeyOnToken();
	void renameCertificateOnToken();
	void deleteKeyOnToken();
	void deleteCertificateOnToken();
	void wrongPinIsTokenError();
};

void test_service_softhsm::initTestCase()
{
	ServiceTestCase::initTestCase();
	SoftHsmToken::watchMessages();
	skip = token.setUp();
	if (!skip.isEmpty())
		QSKIP(CCHAR(skip));
}

void test_service_softhsm::init()
{
	ServiceTestCase::init();
	QVERIFY(token.load());
}

/* No PIN in the audit log of this test */
void test_service_softhsm::cleanup()
{
	QSqlQuery q("SELECT params FROM audit_log");
	while (q.next()) {
		QString params = q.value(0).toString();
		QVERIFY2(!params.contains(QString::fromLatin1(token.pinValue())) &&
			 !params.contains(QString::fromLatin1(
				token.soPinValue())), "a PIN in the audit log");
	}
	ServiceTestCase::cleanup();
}

/* No PIN in any message of the run */
void test_service_softhsm::cleanupTestCase()
{
	QStringList leaks = token.messagesWithPin();
	ServiceTestCase::cleanupTestCase();
	QVERIFY2(leaks.isEmpty(), CCHAR(leaks.join("; ")));
}

/* The module is built against the OpenSSL 4 of XCA: still exactly one
 * libcrypto in the process (BTD-251) */
void test_service_softhsm::oneLibcryptoWithModule()
{
	QVERIFY(pkcs11::libraries.loaded());
	QString more = SoftHsmToken::oneLibcrypto();
	QVERIFY2(more.isEmpty(), CCHAR(more));
}

/* A software key stored on the token and read back as the token key
 * (pki_scard::store_token(), load_token(); the action Store on Security
 * token): the public key read from the token is the software key's.
 * Found with the SoftHSM token (BTD-126), all from upstream be0d7e3a:
 * 1. load_pubkey() built RSA, DSA and EC keys only when it already had
 *    one, so the token key was empty (encoding_failed);
 * 2. it passed the PKCS#11 key type where an EVP_PKEY type belongs
 *    (EVP_PKEY_CTX_new_id() NULL, std::bad_alloc);
 * 3. it took the DER OCTET STRING of CKA_EC_POINT as the point;
 * 4. store_token() read the parameters of the empty key of the new
 *    pki_scard instead of the key to store;
 * 5. it stored the curve's generator as the EC public point.
 * storeRsaKeyOnToken fails through 1, 2 and 4, storeEcKeyOnToken through
 * 1, 3, 4 and 5. */
void test_service_softhsm::storeRsaKeyOnToken()
{
	pki_key *soft = keys()->newKey(ctx, keyjob("RSA:2048"), "BTD-126 rsa");
	QVERIFY(soft);
	pki_scard card("BTD-126 rsa");
	{
		TokenPinScope pin;
		EVP_PKEY *priv = soft->decryptKey();
		TRY(card.store_token(token.slot(), priv));
		EVP_PKEY_free(priv);
	}
	QVERIFY(token.labels(CKO_PUBLIC_KEY).contains("BTD-126 rsa"));
	QCOMPARE(EVP_PKEY_get_id(card.getPubKey()), EVP_PKEY_RSA);
	QCOMPARE(EVP_PKEY_eq(card.getPubKey(), soft->getPubKey()), 1);
}

void test_service_softhsm::storeEcKeyOnToken()
{
	pki_key *soft = keys()->newKey(ctx, keyjob("EC:prime256v1"),
				       "BTD-126 ec");
	QVERIFY(soft);
	pki_scard card("BTD-126 ec");
	{
		TokenPinScope pin;
		EVP_PKEY *priv = soft->decryptKey();
		TRY(card.store_token(token.slot(), priv));
		EVP_PKEY_free(priv);
	}
	QVERIFY(token.labels(CKO_PUBLIC_KEY).contains("BTD-126 ec"));
	QCOMPARE(EVP_PKEY_get_id(card.getPubKey()), EVP_PKEY_EC);
	QCOMPARE(EVP_PKEY_eq(card.getPubKey(), soft->getPubKey()), 1);
}

/* A key generated on the token: on the token, in the database as a
 * token key, audited */
void test_service_softhsm::generateOnToken()
{
	pki_key *key = tokenKey("BTD-126 generated");
	QVERIFY(key);
	QVERIFY(key->isToken());
	QVERIFY(token.labels(CKO_PRIVATE_KEY).contains("BTD-126 generated"));
	AuditEntry e = last();
	QCOMPARE(e.action, QString("key.generate"));
	QCOMPARE(e.result, QString("success"));
}

/* object.rename with on_token: the label on the token and the name in
 * the database */
void test_service_softhsm::renameKeyOnToken()
{
	pki_key *key = tokenKey("BTD-126 key");
	QVERIFY(key);
	TokenObjects list;
	pki_base *card = fromToken(list, CKO_PUBLIC_KEY, "BTD-126 key");
	QVERIFY(card);
	{
		TokenPinScope pin;
		TRY(list.rename(ctx, card, "BTD-126 renamed"));
	}
	QVERIFY(token.labels(CKO_PRIVATE_KEY).contains("BTD-126 renamed"));
	QVERIFY(token.labels(CKO_PUBLIC_KEY).contains("BTD-126 renamed"));
	QVERIFY(!token.labels(CKO_PRIVATE_KEY).contains("BTD-126 key"));
	/* the database keeps the item name and stores the label of the
	 * token object (tokens.slot_label) */
	pki_scard *dbKey = dynamic_cast<pki_scard *>(key);
	QVERIFY(dbKey);
	QCOMPARE(dbKey->getLabel(), QString("BTD-126 renamed"));
	QCOMPARE(QSqlQuery(QString("SELECT slot_label FROM tokens WHERE item=%1")
		.arg(key->getSqlItemId().toString())).next(), true);
	AuditEntry e = last();
	QCOMPARE(e.action, QString("object.rename"));
	QCOMPARE(e.result, QString("success"));
	QCOMPARE(e.params.value("on_token").toBool(), true);
	QCOMPARE(e.params.value("name").toString(), QString("BTD-126 renamed"));
	QCOMPARE(e.params.value("old_name").toString(), QString("BTD-126 key"));
}

void test_service_softhsm::renameCertificateOnToken()
{
	/* signed by a software key: signing with a token key is the work of
	 * the PKCS#11 provider (BTD-17) */
	pki_key *key = keys()->newKey(ctx, keyjob("EC:prime256v1"), "BTD-126 cert key");
	QVERIFY(key);
	pki_x509 *cert = selfSigned(ctx, key, "BTD-126 cert");
	QVERIFY(cert);
	pwdialog->delegateTo(new TokenChooser());
	{
		TokenPinScope pin;
		TRY(cert->store_token(true));
	}
	QVERIFY(token.labels(CKO_CERTIFICATE).contains("BTD-126 cert"));
	TokenObjects list;
	pki_base *onToken = fromToken(list, CKO_CERTIFICATE, "BTD-126 cert");
	QVERIFY(onToken);
	{
		TokenPinScope pin;
		TRY(list.rename(ctx, onToken, "BTD-126 cert renamed"));
	}
	QVERIFY(token.labels(CKO_CERTIFICATE).contains("BTD-126 cert renamed"));
	AuditEntry e = last();
	QCOMPARE(e.action, QString("object.rename"));
	QCOMPARE(e.result, QString("success"));
	QCOMPARE(e.params.value("on_token").toBool(), true);
}

/* Delete from token (the import dialog): the object is gone from the
 * token, the database keeps its key, one object.delete with on_token */
void test_service_softhsm::deleteKeyOnToken()
{
	pki_key *key = tokenKey("BTD-126 doomed");
	QVERIFY(key);
	TokenObjects list;
	pki_base *card = fromToken(list, CKO_PUBLIC_KEY, "BTD-126 doomed");
	QVERIFY(card);
	warning->expectQuestion(true);
	{
		TokenPinScope pin;
		slotid slot = token.slot();
		TRY(db_token::deleteOnToken(ctx, card, &slot));
	}
	QVERIFY(!token.labels(CKO_PRIVATE_KEY).contains("BTD-126 doomed"));
	QVERIFY(!token.labels(CKO_PUBLIC_KEY).contains("BTD-126 doomed"));
	QVERIFY(keys()->isStored(key));
	AuditEntry e = last();
	QCOMPARE(e.action, QString("object.delete"));
	QCOMPARE(e.result, QString("success"));
	QCOMPARE(e.params.value("on_token").toBool(), true);
}

void test_service_softhsm::deleteCertificateOnToken()
{
	/* signed by a software key: signing with a token key is the work of
	 * the PKCS#11 provider (BTD-17) */
	pki_key *key = keys()->newKey(ctx, keyjob("EC:prime256v1"), "BTD-126 cert key 2");
	QVERIFY(key);
	pki_x509 *cert = selfSigned(ctx, key, "BTD-126 cert 2");
	QVERIFY(cert);
	pwdialog->delegateTo(new TokenChooser());
	{
		TokenPinScope pin;
		TRY(cert->store_token(true));
	}
	TokenObjects list;
	pki_base *onToken = fromToken(list, CKO_CERTIFICATE, "BTD-126 cert 2");
	QVERIFY(onToken);
	warning->expectQuestion(true);
	{
		TokenPinScope pin;
		slotid slot = token.slot();
		TRY(db_token::deleteOnToken(ctx, onToken, &slot));
	}
	QVERIFY(!token.labels(CKO_CERTIFICATE).contains("BTD-126 cert 2"));
	AuditEntry e = last();
	QCOMPARE(e.action, QString("object.delete"));
	QCOMPARE(e.params.value("on_token").toBool(), true);
}

/* A wrong PIN: token_error, the label and the name stay, and the
 * failure is audited */
void test_service_softhsm::wrongPinIsTokenError()
{
	pki_key *key = tokenKey("BTD-126 kept");
	QVERIFY(key);
	TokenObjects list;
	pki_base *card = fromToken(list, CKO_PUBLIC_KEY, "BTD-126 kept");
	QVERIFY(card);
	QString code;
	try {
		TokenPinScope pin(SoftHsmToken::wrongPinSource);
		list.rename(ctx, card, "BTD-126 never");
	} catch (serviceError &err) {
		code = err.code;
	} catch (errorEx &err) {
		code = "untyped: " + err.getString();
	}
	QCOMPARE(code, QString("token_error"));
	QVERIFY(token.labels(CKO_PRIVATE_KEY).contains("BTD-126 kept"));
	QCOMPARE(dynamic_cast<pki_scard *>(key)->getLabel(),
		 QString("BTD-126 kept"));
	AuditEntry e = last();
	QCOMPARE(e.action, QString("object.rename"));
	QCOMPARE(e.result, QString("failure"));
	QCOMPARE(e.errorCode, QString("token_error"));
	QCOMPARE(e.params.value("on_token").toBool(), true);
}

XCA_SERVICE_TEST_MAIN(test_service_softhsm)
#include "test_service_softhsm.moc"
