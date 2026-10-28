/* vi: set sw=4 ts=4:
 *
 * Signing key of the audit checkpoints (BTD-37).
 */

#include "audit_key.h"
#include "audit.h"
#include "base.h"
#include "BioByteArray.h"
#include "exception.h"
#include "func_base.h"
#include "pass_info.h"
#include "pki_evp.h"
#include "PwDialogCore.h"
#include "sql.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QDebug>
#include <QList>
#include <QObject>
#include <QPair>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>

const char AuditKey::typeEd25519[] = "ed25519";

static void throwOnError(XSqlQuery &q)
{
	QSqlError e = q.lastError();
	if (e.isValid())
		throw errorEx(QObject::tr("Database error: %1").arg(e.text()));
}

Passwd AuditKey::password()
{
	Passwd pass = pki_evp::passwd;
	pass_info p(XCA_TITLE, QObject::tr("Please enter the database password "
			"to sign the audit checkpoint"));
	p.setPurpose(pass_info::DatabasePassword);

	try {
		while (!pki_evp::validateDatabasePassword(pass)) {
			if (PwDialogCore::execute(&p, &pass,
					pki_evp::passHash.isEmpty()) != pw_ok)
				break;
		}
	} catch (secretError &err) {
		/* no source on the command line, or a wrong one */
		qDebug() << err.getString();
	}
	if (!pki_evp::validateDatabasePassword(pass))
		throw serviceError("audit_key_unavailable", QObject::tr(
			"The audit checkpoint needs the database password"));
	return pass;
}

static QByteArray encryptPrivate(EVP_PKEY *pkey, const Passwd &pass)
{
	BioByteArray der;
	if (!i2d_PKCS8PrivateKey_bio(der, pkey, EVP_aes_256_cbc(),
			(char *)pass.constData(), pass.size(), NULL, NULL))
		openssl_error_msg(QObject::tr("Failed to encrypt the audit key"));
	return der.byteArray();
}

static EVP_PKEY *decryptPrivate(const QByteArray &der, const Passwd &pass)
{
	EVP_PKEY *pkey = nullptr;
	X509_SIG *p8 = d2i_PKCS8_bio(BioByteArray(der).ro(), NULL);
	if (p8) {
		PKCS8_PRIV_KEY_INFO *p8inf = PKCS8_decrypt(p8,
				pass.constData(), pass.size());
		if (p8inf) {
			pkey = EVP_PKCS82PKEY(p8inf);
			PKCS8_PRIV_KEY_INFO_free(p8inf);
		}
		X509_SIG_free(p8);
	}
	if (!pkey) {
		ign_openssl_error();
		throw errorEx(QObject::tr("Failed to decrypt the audit key"));
	}
	return pkey;
}

static QString spkiId(const QByteArray &der)
{
	return QString::fromLatin1(QCryptographicHash::hash(der,
				QCryptographicHash::Sha256).toHex());
}

static QByteArray spkiDer(EVP_PKEY *pkey)
{
	unsigned char *der = nullptr;
	int len = i2d_PUBKEY(pkey, &der);
	if (len <= 0)
		openssl_error_msg(QObject::tr("Invalid audit key"));
	QByteArray ba((const char *)der, len);
	OPENSSL_free(der);
	return ba;
}

static EVP_PKEY *readPublic(const QByteArray &pem)
{
	EVP_PKEY *pkey = PEM_read_bio_PUBKEY(BioByteArray(pem).ro(),
						NULL, NULL, NULL);
	if (!pkey)
		ign_openssl_error();
	return pkey;
}

QString AuditKey::create(const Passwd &pass, QByteArray *publicPem)
{
	EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
	if (!pkey)
		openssl_error_msg(QObject::tr("Failed to generate the audit key"));

	QString id;
	try {
		BioByteArray pem;
		if (!PEM_write_bio_PUBKEY(pem, pkey))
			openssl_error_msg(QObject::tr("Invalid audit key"));
		*publicPem = pem.byteArray();
		id = spkiId(spkiDer(pkey));

		XSqlQuery q;
		SQL_PREPARE(q, "INSERT INTO audit_keys (key_id, created, "
			"key_type, public_key, private, retired) "
			"VALUES (?,?,?,?,?,0)");
		q.bindValue(0, id);
		q.bindValue(1, AuditLog::rfc3339(QDateTime::currentDateTimeUtc()));
		q.bindValue(2, QString(typeEd25519));
		q.bindValue(3, QString::fromLatin1(*publicPem));
		q.bindValue(4, QString::fromLatin1(
				encryptPrivate(pkey, pass).toBase64()));
		q.exec();
		throwOnError(q);
	} catch (...) {
		EVP_PKEY_free(pkey);
		throw;
	}
	EVP_PKEY_free(pkey);
	return id;
}

QString AuditKey::current()
{
	XSqlQuery q;
	SQL_PREPARE(q, "SELECT key_id FROM audit_keys WHERE retired=0 "
			"AND private IS NOT NULL");
	q.exec();
	throwOnError(q);
	return q.next() ? q.value(0).toString() : QString();
}

QByteArray AuditKey::sign(const QString &id, const QByteArray &data,
		const Passwd &pass)
{
	XSqlQuery q;
	SQL_PREPARE(q, "SELECT private FROM audit_keys WHERE key_id=? "
			"AND retired=0");
	q.bindValue(0, id);
	q.exec();
	throwOnError(q);
	if (!q.next() || q.value(0).isNull())
		throw serviceError("audit_key_unavailable",
			QObject::tr("The audit key %1 cannot sign").arg(id));

	EVP_PKEY *pkey = decryptPrivate(QByteArray::fromBase64(
			q.value(0).toByteArray()), pass);
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	size_t len = 0;
	QByteArray sig;
	bool ok = ctx &&
		EVP_DigestSignInit_ex(ctx, NULL, NULL, NULL, NULL, pkey, NULL) &&
		EVP_DigestSign(ctx, NULL, &len,
			(const unsigned char *)data.constData(), data.size());
	if (ok) {
		sig.resize(len);
		ok = EVP_DigestSign(ctx, (unsigned char *)sig.data(), &len,
			(const unsigned char *)data.constData(), data.size());
		sig.resize(len);
	}
	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	if (!ok)
		openssl_error_msg(QObject::tr("Failed to sign the audit checkpoint"));
	return sig;
}

void AuditKey::retire(const QString &id)
{
	XSqlQuery q;
	SQL_PREPARE(q, "UPDATE audit_keys SET retired=1, private=NULL "
			"WHERE key_id=?");
	q.bindValue(0, id);
	q.exec();
	throwOnError(q);
}

void AuditKey::reencrypt(const Passwd &newPass)
{
	XSqlQuery q;
	QList<QPair<QString, QByteArray> > keys;

	SQL_PREPARE(q, "SELECT key_id, private FROM audit_keys "
			"WHERE private IS NOT NULL");
	q.exec();
	throwOnError(q);
	while (q.next())
		keys << qMakePair(q.value(0).toString(),
			QByteArray::fromBase64(q.value(1).toByteArray()));
	if (keys.isEmpty())
		return;

	Passwd oldPass = password();
	for (const auto &k : keys) {
		EVP_PKEY *pkey = decryptPrivate(k.second, oldPass);
		QByteArray enc;
		try {
			enc = encryptPrivate(pkey, newPass);
		} catch (...) {
			EVP_PKEY_free(pkey);
			throw;
		}
		EVP_PKEY_free(pkey);
		SQL_PREPARE(q, "UPDATE audit_keys SET private=? WHERE key_id=?");
		q.bindValue(0, QString::fromLatin1(enc.toBase64()));
		q.bindValue(1, k.first);
		q.exec();
		throwOnError(q);
	}
}

QString AuditKey::keyId(const QByteArray &publicPem)
{
	EVP_PKEY *pkey = readPublic(publicPem);
	if (!pkey)
		return QString();
	QString id = spkiId(spkiDer(pkey));
	EVP_PKEY_free(pkey);
	return id;
}

bool AuditKey::verify(const QByteArray &publicPem, const QByteArray &data,
		const QByteArray &signature)
{
	EVP_PKEY *pkey = readPublic(publicPem);
	if (!pkey)
		return false;
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	bool ok = ctx &&
		EVP_DigestVerifyInit_ex(ctx, NULL, NULL, NULL, NULL, pkey, NULL) &&
		EVP_DigestVerify(ctx,
			(const unsigned char *)signature.constData(),
			signature.size(),
			(const unsigned char *)data.constData(), data.size()) == 1;
	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	ign_openssl_error();
	return ok;
}

void AuditKey::refuseSigning(pki_key *key)
{
	XSqlQuery q;

	if (!key || !key->getPubKey())
		return;
	SQL_PREPARE(q, "SELECT 1 FROM audit_keys WHERE key_id=?");
	q.bindValue(0, spkiId(key->i2d()));
	q.exec();
	throwOnError(q);
	if (q.next())
		throw serviceError("audit_key", QObject::tr(
			"The audit key '%1' only signs audit checkpoints")
				.arg(key->getIntName()));
}
