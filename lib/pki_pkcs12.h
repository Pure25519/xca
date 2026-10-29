/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __PKI_PKCS12_H
#define __PKI_PKCS12_H

#include "pki_multi.h"

class Passwd;

class pki_key;
class pki_x509;

class encAlgo
{
  private:
	static const int builtin_encAlgo;
	static int default_encAlgo;
	int encAlgo_nid { NID_undef };

  public:
	static const QList<int> all_encAlgos;

	encAlgo(int nid);
	encAlgo(const QString &name);
	encAlgo(const encAlgo &d) = default;
	encAlgo& operator=(const encAlgo &d) = default;

	QString name() const;
	QString displayName() const;
	/* Encryption and MAC of a PKCS#12 file written with it, for the
	 * export dialog; a legacy algorithm is marked insecure */
	QString description() const;
	int getEncAlgoNid() const;
	bool legacy() const
	{
		return encAlgo_nid == NID_pbe_WithSHA1And3_Key_TripleDES_CBC ||
			   encAlgo_nid == NID_pbe_WithSHA1And40BitRC2_CBC;
	}
	static void setDefault(const QString &def);
	static const encAlgo getDefault();
	/* The compiled-in default, whatever a database set (BTD-174) */
	static const encAlgo getBuiltinDefault()
	{
		return encAlgo(builtin_encAlgo);
	}
	/* The algorithm of a PKCS#12 export: the one an ExportSpec names
	 * while its export runs, else the setting pkcs12_enc_algo (BTD-52) */
	static const encAlgo forExport();
	class ExportScope
	{
		QString saved{};
	  public:
		ExportScope(const QString &name);
		~ExportScope();
	};

  private:
	static QString exportName;
};

class pki_pkcs12: public pki_multi
{
	Q_OBJECT
	friend class pki_x509;
	friend class pki_evp;

	protected:
		QString alias{}, algorithm{};
		pki_x509 *cert{};
		pki_key *key{};
		void parse(const QByteArray &ba, const QString &fname);

	public:
		pki_pkcs12(const QString &d, pki_x509 *acert, pki_key *akey);
		pki_pkcs12(const QString &fname);
		/* The content of a PKCS#12 file (BTD-34) */
		pki_pkcs12(const QByteArray &ba, const QString &name);

		pki_key *getKey() const
		{
			return key;
		}
		pki_x509 *getCert() const
		{
			return cert;
		}
		/* No prompt: the caller provides the password (BTD-34) */
		void writePKCS12(QIODevice &file, encAlgo &encAlgo,
				const Passwd &pass) const;
		void collect_properties(QMap<QString, QString> &prp) const;
};
#endif
