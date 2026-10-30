/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __PKI_EVP_H
#define __PKI_EVP_H

#include <QString>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include "pki_key.h"
#include "Passwd.h"

#define VIEW_private_ownpass 9

class pass_info;

class pki_evp: public pki_key
{
		Q_OBJECT
		QByteArray encKey;
		void init();
		QByteArray getEncKey() const;
		QString encKey_b64()
		{
			return QString::fromLatin1(encKey.toBase64());
		}
		static QString _sha512passwd(QByteArray pass, QString salt,
						int size, int repeat);
		/* input and pass: the bytes the key was read from and the
		 * password used, for the seed check of ML-DSA (BTD-204) */
		void set_EVP_PKEY(EVP_PKEY *pkey, QString name = QString(),
				const QByteArray *input = nullptr,
				const Passwd *pass = nullptr);

	protected:
		bool openssl_pw_error() const;

	public:
		static QString passHash;
		static Passwd passwd;
		static QString md5passwd(QByteArray pass);
		static QString sha512passwd(QByteArray pass, QString salt);
		static QString sha512passwT(QByteArray pass, QString salt);
		static bool validateDatabasePassword(const Passwd &passwd);

		pki_evp(const QString &n = QString(), int type = EVP_PKEY_RSA);
		pki_evp(const pki_evp *pkey);
		pki_evp(EVP_PKEY *pkey);
		virtual ~pki_evp();

		void generate(const keyjob &task);
		void setOwnPass(enum passType);
		void set_evp_key(EVP_PKEY *pkey);
		void encryptKey(const char *password = NULL);
		void bogusEncryptKey();
		bool updateLegacyEncryption();
		EVP_PKEY *decryptKey() const;
		/* decryptKey() in the ML-DSA private key encoding of the
		 * export that runs (MlDsaFormatScope); other keys as they are */
		EVP_PKEY *decryptKeyForExport() const;
		EVP_PKEY *tryDecryptKey() const;
		EVP_PKEY *legacyDecryptKey(QByteArray &myencKey,
					Passwd &ownPassBuf) const;
		EVP_PKEY *priv2pub(EVP_PKEY* key);
		static QString removeTypeFromIntName(QString n);

		/* ML-DSA private key encodings of RFC 9881 (BTD-16): "both"
		 * (seed and expanded key), "seed", "expanded" */
		static const QStringList mlDsaFormats;
		/* The encoding of the export that runs; empty: OpenSSL's
		 * default (both, or expanded for a key without seed) */
		class MlDsaFormatScope
		{
			QString saved{};
		  public:
			MlDsaFormatScope(const QString &format);
			~MlDsaFormatScope();
			/* The encoding the export wrote for the key; empty
			 * for other keys */
			static QString written(const pki_key *key);
		};
		static bool isMlDsa(int keytype);
		void fromPEMbyteArray(const QByteArray &ba, const QString &name);
		void fromBytes(const QByteArray &ba, const QString &fname);
		virtual bool pem(BioByteArray &b, const pki_export *xport);
		EVP_PKEY *load_ssh_ed25519_privatekey(const QByteArray &ba,
						const pass_info &p);
		void writeDefault(const QString &dirname) const;
		/* enc NULL: unencrypted, pass is ignored. No prompt: the
		 * caller provides the password (BTD-34) */
		void writeKey(QIODevice &file, const EVP_CIPHER *enc,
				const Passwd &pass, bool pem) const;
		void writePKCS8(QIODevice &file, const EVP_CIPHER *enc,
				const Passwd &pass, bool pem) const;
		void writePVKprivate(QIODevice &file) const;
		void writeSSH2private(QIODevice &file) const;
		void write_SSH2_ed25519_private(BIO *b, const EVP_PKEY *pkey) const;
		void fillJWK(QJsonObject &json, const pki_export *xport) const;
		bool verify(EVP_PKEY *pkey) const;
		QVariant getIcon(const dbheader *hd) const;
		bool sqlUpdatePrivateKey();
		QSqlError insertSqlData();
		QSqlError deleteSqlData();
		void restoreSql(const QSqlRecord &rec);
};

#endif
