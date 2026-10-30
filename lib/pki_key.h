/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __PKI_KEY_H
#define __PKI_KEY_H

#include <QString>
#include <QJsonObject>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include "pki_base.h"
#include "builtin_curves.h"

#define PEM_STRING_OPENSSH_KEY "OPENSSH PRIVATE KEY"
#define DEFAULT_KEY_LENGTH 2048
#define ED25519_KEYLEN 32

#define VIEW_public_keys_type 6
#define VIEW_public_keys_len 7
#define VIEW_public_keys_public 8

extern builtin_curves builtinCurves;

class keytype
{
  public:
	static QList<keytype> types()
	{
		return QList<keytype> {
			keytype(EVP_PKEY_RSA, "RSA", CKM_RSA_PKCS_KEY_PAIR_GEN,
				false, true),
			keytype(EVP_PKEY_DSA, "DSA", CKM_DSA_KEY_PAIR_GEN,
				false, true),
#ifndef OPENSSL_NO_EC
			keytype(EVP_PKEY_EC, "EC", CKM_EC_KEY_PAIR_GEN,
				true, false),
#ifdef EVP_PKEY_ED25519
			keytype(EVP_PKEY_ED25519, "ED25519", CKM_VENDOR_DEFINED, false, false),
#endif
#ifdef EVP_PKEY_ED448
			keytype(EVP_PKEY_ED448, "ED448", CKM_VENDOR_DEFINED, false, false),
#endif
#endif
			/* Post-quantum signature keys (BTD-16). The names are the
			 * ones of OpenSSL, which knows these keys only through its
			 * provider (see nid()) */
#ifdef EVP_PKEY_ML_DSA_44
			keytype(EVP_PKEY_ML_DSA_44, "ML-DSA-44", CKM_VENDOR_DEFINED, false, false),
			keytype(EVP_PKEY_ML_DSA_65, "ML-DSA-65", CKM_VENDOR_DEFINED, false, false),
			keytype(EVP_PKEY_ML_DSA_87, "ML-DSA-87", CKM_VENDOR_DEFINED, false, false),
#endif
#ifdef EVP_PKEY_SLH_DSA_SHA2_128S
			keytype(EVP_PKEY_SLH_DSA_SHA2_128S, "SLH-DSA-SHA2-128s", CKM_VENDOR_DEFINED, false, false),
			keytype(EVP_PKEY_SLH_DSA_SHA2_128F, "SLH-DSA-SHA2-128f", CKM_VENDOR_DEFINED, false, false),
			keytype(EVP_PKEY_SLH_DSA_SHA2_192S, "SLH-DSA-SHA2-192s", CKM_VENDOR_DEFINED, false, false),
			keytype(EVP_PKEY_SLH_DSA_SHA2_192F, "SLH-DSA-SHA2-192f", CKM_VENDOR_DEFINED, false, false),
			keytype(EVP_PKEY_SLH_DSA_SHA2_256S, "SLH-DSA-SHA2-256s", CKM_VENDOR_DEFINED, false, false),
			keytype(EVP_PKEY_SLH_DSA_SHA2_256F, "SLH-DSA-SHA2-256f", CKM_VENDOR_DEFINED, false, false),
			keytype(EVP_PKEY_SLH_DSA_SHAKE_128S, "SLH-DSA-SHAKE-128s", CKM_VENDOR_DEFINED, false, false),
			keytype(EVP_PKEY_SLH_DSA_SHAKE_128F, "SLH-DSA-SHAKE-128f", CKM_VENDOR_DEFINED, false, false),
			keytype(EVP_PKEY_SLH_DSA_SHAKE_192S, "SLH-DSA-SHAKE-192s", CKM_VENDOR_DEFINED, false, false),
			keytype(EVP_PKEY_SLH_DSA_SHAKE_192F, "SLH-DSA-SHAKE-192f", CKM_VENDOR_DEFINED, false, false),
			keytype(EVP_PKEY_SLH_DSA_SHAKE_256S, "SLH-DSA-SHAKE-256s", CKM_VENDOR_DEFINED, false, false),
			keytype(EVP_PKEY_SLH_DSA_SHAKE_256F, "SLH-DSA-SHAKE-256f", CKM_VENDOR_DEFINED, false, false),
#endif
		};
	}
	int type{};
	QString name{};
	CK_MECHANISM_TYPE mech{};
	bool curve{}, length{};

	keytype(int t, const QString &n, CK_MECHANISM_TYPE m, bool c, bool l)
			: type(t), name(n), mech(m), curve(c), length(l) { }
	keytype() : type(-1), name(QString()), mech(0),
			curve(false), length(true) { }
	bool isValid() const
	{
		return type != -1;
	}
	/* Neither size nor curve: the type itself names the parameters
	 * (Ed25519, Ed448, ML-DSA, SLH-DSA) */
	bool fixed() const
	{
		return isValid() && !curve && !length;
	}
	/* Only RSA, DSA and EC have a traditional private key format; the
	 * others are written as PKCS#8 */
	QString traditionalPemName() const
	{
		return fixed() ? QString("PRIVATE KEY") :
				QString("%1 PRIVATE KEY").arg(name);
	}
	/* The NID of the key type. EVP_PKEY_get_id() is -1 for keys that
	 * OpenSSL knows only through a provider (ML-DSA, SLH-DSA); they are
	 * found by their algorithm name (BTD-16). A key generated from its
	 * NID carries the NID, but EVP_PKEY_type() knows only the legacy
	 * types and gives NID_undef for it */
	static int nid(const EVP_PKEY *pkey)
	{
		if (!pkey)
			return NID_undef;
		int id = EVP_PKEY_get_id(pkey);
		if (id > 0) {
			int legacy = EVP_PKEY_type(id);
			return legacy != NID_undef ? legacy : id;
		}
		const char *name = EVP_PKEY_get0_type_name(pkey);
		return name ? OBJ_ln2nid(name) : NID_undef;
	}
	static const keytype byType(int type)
	{
		foreach(const keytype t, types()) {
			if (t.type == type)
				return t;
		}
		return keytype();
	}
	static const keytype byMech(CK_MECHANISM_TYPE mech)
	{
		foreach(const keytype t, types()) {
			if (t.mech == mech)
				return t;
		}
		return keytype();
	}
	static const keytype byName(const QString &name)
	{
		foreach(const keytype t, types()) {
			if (t.name.compare(name, Qt::CaseInsensitive) == 0)
				return t;
		}
		return keytype();
	}
	static const keytype byPKEY(const EVP_PKEY *pkey)
	{
		return byType(nid(pkey));
	}
};

class keyjob
{
  public:
	static keyjob defaultjob;
	keytype ktype;
	int size;
	int ec_nid;
	slotid slot;
	keyjob() {
		size = DEFAULT_KEY_LENGTH;
		ktype = keytype::byName("RSA");
		ec_nid = NID_undef;
		slot = slotid();
	}
	keyjob(const QString &desc)
	{
		QStringList sl = desc.split(':');
		if (sl.size() == 1)
			sl += "";
		if (sl.size() != 2)
			return;
		ktype = keytype::byName(sl[0]);
		size = DEFAULT_KEY_LENGTH;
		ec_nid = NID_undef;
		if (isEC())
			ec_nid = OBJ_txt2nid(sl[1].toLatin1());
		else if (!isFixed())
			size = sl[1].toInt();
		else if (!sl[1].isEmpty())
			size = 0;  /* "ED448:456": the type takes no size */
		slot = slotid();
		ign_openssl_error();
	}
	QString toString()
	{
		if (isFixed())
			return ktype.name;
		return QString("%1:%2").arg(ktype.name) .arg(isEC() ?
					OBJ_obj2QString(OBJ_nid2obj(ec_nid)) :
					QString::number(size));
	}
	bool isToken() const
	{
		return slot.lib != NULL;
	}
	bool isEC() const
	{
		return ktype.type == EVP_PKEY_EC;
	}
	bool isFixed() const
	{
		return ktype.fixed();
	}
	bool isValid()
	{
		if (!ktype.isValid())
			return false;
		if (isFixed())
			return size > 0;
		if (isEC() && builtinCurves.containNid(ec_nid))
			return true;
		if (!isEC() && size > 0)
			return true;
		return false;
	}
};

class pki_key: public pki_base
{

		Q_OBJECT
	friend class pki_x509super;

	public:
		enum passType { ptCommon, ptPrivate, ptBogus, ptPin };

	protected:
		enum passType ownPass;
		int key_size;
		bool isPub;
		EVP_PKEY *key;
		QByteArray SSH2publicQByteArray(bool raw=false) const;
		QByteArray X509_PUBKEY_public_key() const;
		QByteArray PEM_comment() const;
		void collect_properties(QMap<QString, QString> &prp) const;

		BIGNUM *ssh_key_data2bn(QByteArray *ba) const;
		void ssh_key_check_chunk(QByteArray *ba, const char *expect) const;
		QByteArray ssh_key_next_chunk(QByteArray *ba) const;
		void ssh_key_QBA2data(const QByteArray &ba,
					QByteArray *data) const;
		void ssh_key_bn2data(const BIGNUM *bn, QByteArray *data) const;
		EVP_PKEY *fromParamData(QSharedPointer<OSSL_PARAM_BLD> bld,
			const QMap<const char *, BIGNUM*> &params, int keytype) const;

		/* Read from a file that needed a password to decrypt
		 * (BTD-41, JsonReport::key() of an unstored key) */
		bool encryptedFile{};

	private:
		mutable int useCount; // usage counter

	public:

		pki_key(const QString &name = QString());
		pki_key(const pki_key *pk);
		virtual ~pki_key();

		void autoIntName(const QString &file);
		QString length() const;
		QString comboText() const;
		QString getKeyTypeString(void) const;
		virtual EVP_PKEY *decryptKey() const = 0;
		virtual bool isToken();
		virtual QString getTypeString(void) const;
		virtual QList<int> possibleHashNids();
		QString getMsg(msg_type msg, int n = 1) const;

		void writePublic(QIODevice &file, bool pem) const;
		QString getJWKcrv() const;
		void fillJWK(QJsonObject &json, const pki_export *xport) const;
		bool compare(const pki_base *ref) const;
		int getKeyType() const;
		bool isPrivKey() const;
		virtual bool verify(EVP_PKEY *pkey) const;
		int getUcount() const;
		void setUcount(int c)
		{
			useCount = c;
		}
		enum passType getOwnPass(void) const
		{
			return ownPass;
		}
		bool fileEncrypted() const
		{
			return encryptedFile;
		}
		/* For a container that decrypted the key, e.g. PKCS#12 */
		void setFileEncrypted(bool e)
		{
			encryptedFile = e;
		}
		EVP_PKEY *getPubKey()
		{
			return key;
		}
		/* For public operations only (PEM_write_bio_PUBKEY, i2d_PUBKEY,
		 * EVP_PKEY_get_bits): a key read from a file holds its private
		 * part here until it is stored encrypted (pki_evp) */
		const EVP_PKEY *getEvpKey() const
		{
			return key;
		}
		bool isPubKey() const
		{
			return isPub;
		}
		virtual void generate(const keyjob &)
		{
			qFatal("generate in pki_key");
		}
		bool pem(BioByteArray &);
		virtual bool pem(BioByteArray &b, const pki_export *xport);
		QVariant column_data(const dbheader *hd) const;
		QString base64UrlEncodeParam(const EVP_PKEY *pkey,
						const char *param, int bits = 0) const;
		void ssh_key_bn2dataParam(const EVP_PKEY *pkey, const char *param,
						QByteArray *data) const;
		QString BignumParamQString(const char *param_name) const;
		BIGNUM *BignumParam(const char *param_name) const;
		QByteArray QByteArrayParam(const char *param) const;

#ifndef OPENSSL_NO_EC
		int ecParamNid() const;
		QByteArray ed25519PubKey() const;
		QByteArray ed25519PrivKey(const EVP_PKEY *pkey) const;
#endif
		void d2i(QByteArray &ba);
		void d2i_old(QByteArray &ba, int type);
		QByteArray i2d() const;
		EVP_PKEY *load_ssh2_key(const QByteArray &ba);
		void writeSSH2public(QIODevice &file) const;
		QString fingerprint(const QString &format) const;
		bool SSH2_compatible() const;
		void print(BioByteArray &b, enum print_opt opt) const;
		void resetUcount()
		{
			useCount = -1;
		}
		QSqlError insertSqlData();
		QSqlError deleteSqlData();
		void restoreSql(const QSqlRecord &rec);
};

Q_DECLARE_METATYPE(pki_key *);
#endif
