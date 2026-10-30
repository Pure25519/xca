/* vi: set sw=4 ts=4:
 *
 * OpenSSL results that a service path checks itself (BTD-95, groups G2,
 * G3 and G8 of the review list): _openssl_error() only prints, so before
 * these checks
 * - a private key that did not encrypt was replaced by its public key and
 *   newKey() reported success (G2),
 * - an audit checkpoint was signed with an empty signature and committed
 *   (G3),
 * - a subject entry or request attribute with a character the attribute's
 *   string types cannot hold ("@" in a country) crashed (G8):
 *   QStringToAsn1() returned NULL and its callers passed it on to
 *   ASN1_STRING_type() (SIGSEGV).
 * Each failure is injected with input OpenSSL refuses.
 */

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include "lib/audit_key.h"
#include "lib/BioByteArray.h"
#include "lib/exception.h"
#include "lib/pki_evp.h"
#include "lib/pki_x509req.h"
#include "lib/x509name.h"

#include "ServiceTestCase.h"

/* The key holds a private part (an EC key: the scalar) */
static bool hasPrivate(EVP_PKEY *key)
{
	BIGNUM *d = nullptr;
	bool ok = EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_PRIV_KEY, &d);
	BN_free(d);
	return ok;
}

class test_service_openssl_checks : public ServiceTestCase
{
	Q_OBJECT

	static QString errorCode(std::function<void()> call)
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

  private slots:
	void keyEncryptionFailureKeepsKey();
	void keyEncryptionFailureDropsPlaintext();
	void auditSigningFailureThrows();
	void refusedSubjectEntry();
	void refusedRequestAttribute();
};

/* A key without private part cannot be written as encrypted PKCS#8:
 * encryptKey() throws (G2) */
void test_service_openssl_checks::keyEncryptionFailureKeepsKey()
{
	EVP_PKEY *full = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256");
	QVERIFY(full);
	unsigned char *der = nullptr;
	int len = i2d_PUBKEY(full, &der);
	const unsigned char *p = der;
	EVP_PKEY *pub = d2i_PUBKEY(nullptr, &p, len);
	OPENSSL_free(der);
	EVP_PKEY_free(full);
	QVERIFY(pub);

	pki_evp key(pub);
	QCOMPARE(errorCode([&]() { key.encryptKey("btd95"); }),
		QString("key_encryption_failed"));
	QVERIFY(!hasPrivate(key.getPubKey()));
}

/* A private key that does not encrypt (no cipher can be fetched under
 * "fips=yes" without a FIPS provider) is not kept as plain text in the
 * key object: before, a failed password change left it there (review
 * of xca#59, MINOR 8) */
void test_service_openssl_checks::keyEncryptionFailureDropsPlaintext()
{
	EVP_PKEY *full = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256");
	QVERIFY(full);
	/* as changeDatabasePassword() does it: the decrypted key set,
	 * then encrypted again */
	pki_evp key(full);
	key.set_evp_key(key.decryptKey());
	QVERIFY(hasPrivate(key.getPubKey()));
	QVERIFY(EVP_set_default_properties(nullptr, "fips=yes"));
	QString code = errorCode([&]() { key.encryptKey("btd95"); });
	EVP_set_default_properties(nullptr, "");
	QCOMPARE(code, QString("key_encryption_failed"));
	QVERIFY(!hasPrivate(key.getPubKey()));
}

/* An X25519 key cannot sign: the checkpoint signature fails, and
 * AuditKey::sign() throws instead of returning an empty signature (G3) */
void test_service_openssl_checks::auditSigningFailureThrows()
{
	Passwd pass;
	pass = "btd95-audit";
	EVP_PKEY *x25519 = EVP_PKEY_Q_keygen(nullptr, nullptr, "X25519");
	QVERIFY(x25519);
	BioByteArray der;
	QVERIFY(i2d_PKCS8PrivateKey_bio(der, x25519, EVP_aes_256_cbc(),
		(char *)pass.constData(), pass.size(), nullptr, nullptr) > 0);
	EVP_PKEY_free(x25519);

	AuditKey::Generated key;
	key.id = "btd95";
	key.encryptedPrivate = der.byteArray();
	QByteArray sig;
	QCOMPARE(errorCode([&]() {
		sig = AuditKey::sign(key, "checkpoint", pass); }),
		QString("audit_signing_failed"));
	QVERIFY(sig.isEmpty());
}

/* A subject entry OpenSSL refuses is an error, not a crash (G8) */
void test_service_openssl_checks::refusedSubjectEntry()
{
	x509name name;
	/* no PrintableString */
	QCOMPARE(errorCode([&]() {
		name.addEntryByNid(NID_countryName, "D@"); }),
		QString("invalid_string"));
	QCOMPARE(name.entryCount(), 0);
	name.addEntryByNid(NID_countryName, "DE");
	QCOMPARE(name.entryCount(), 1);
}

/* The same for an attribute of a request */
void test_service_openssl_checks::refusedRequestAttribute()
{
	pki_x509req req;
	QCOMPARE(errorCode([&]() {
		req.addAttribute(NID_countryName, "D@"); }),
		QString("invalid_string"));
}

XCA_SERVICE_TEST_MAIN(test_service_openssl_checks)
#include "test_service_openssl_checks.moc"
