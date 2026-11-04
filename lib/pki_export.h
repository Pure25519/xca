/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2021 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __PKI_EXPORT_H
#define __PKI_EXPORT_H

#include <QObject>
#include <QMetaType>
#include <QString>
#include <QList>
#include <QMap>

#define BIT(n) (1<<n)
#define DEFAULT_KEY_CLIPBOARD_TYPE 19
#define DEFAULT_CERT_CLIPBOARD_TYPE 1

enum pki_type {
	none,
	asym_key,
	x509_req,
	x509,
	revocation,
	tmpl,
	setting,
	smartCard,
};

enum {
	F_PEM       = BIT(0), /* File is PEM encoded */
	F_CRYPT     = BIT(1), /* Key will be encrypted */
	F_PRIVATE   = BIT(2), /* File contains Private Key */
	F_USUAL     = BIT(3), /* Usual format */
	F_SSH2      = BIT(4), /* Key is SSH2 compatible */
	F_MULTI     = BIT(5), /* Hide if only element is selected */
	F_SINGLE    = BIT(6), /* Single element not suitable for selections */
	F_ALL       = BIT(7), /* All elements */
	F_UNREVOKED = BIT(8), /* All unrevoked certificates */
	F_CA        = BIT(10),/* Export types for CAs */
	F_CHAIN     = BIT(11),/* Certificate chain */
	F_PKCS7     = BIT(12),
	F_PKCS8     = BIT(13),
	F_PKCS12    = BIT(14),
	F_CLIPBOARD = BIT(15),/* Suitable key format for the clipboard */
	F_PVK       = BIT(16),
	F_INDEX     = BIT(17),
	F_CAL       = BIT(18),/* Calendar entry */
	F_DER       = BIT(19),/* DER format */
	F_OVPN      = BIT(20),/* OpenVPN format */
	F_CONFIG    = BIT(21),/* OpenSSL config format */
	F_TAKEY     = BIT(22),/* OpenVPN TLS-Auth key */
	F_TRADITION = BIT(23),/* Traditional OpenSSL encrypted PEM */
	F_UNUSABLE  = BIT(24),/* Unusable certificates */
	F_JWK       = BIT(25),/* JSON Web Key (JWK) RFC-7517 */
	F_JWK_X5C   = BIT(26),/* JSON Web Key (JWK) RFC-7517 X.509 Certificate Chain */
};

class pki_export : public QObject {

	Q_OBJECT

  public:

	int id;
	enum pki_type pki_type;
	QString extension;
	int flags;
	QString desc;
	QString help;

	pki_export(int i, enum pki_type p, const QString &e,
		   const QString &d, int f, const QString &h);
	static QList<const pki_export*> select(enum pki_type, int);
	static const pki_export *by_id(int id);
	static void free_elements();
	static void init_elements();
	bool match_all(int match_flags) const;

  private:
	static QList<pki_export*> elements;
};

class pki_base;

/* The options of one export, passed from exportItems() down to the
 * writers instead of static state, so writers that run at the same time
 * do not take each other's options (BTD-183) */
class ExportOptions
{
  public:
	/* NID of the PKCS#12 encryption (encAlgo); 0: the setting
	 * pkcs12_enc_algo */
	int pkcs12Algorithm{};
	/* PKCS#12 MAC, one of pki_pkcs12::macs; empty: hmac-sha256 */
	QString pkcs12Mac{};
	/* PKCS#12 iterations; 0: the setting pkcs12_iterations */
	int pkcs12Iterations{};
	/* ML-DSA private key encoding, one of pki_evp::mlDsaFormats;
	 * empty: both, or the expanded key of a key without seed */
	QString mlDsaFormat{};
	/* Out: the ML-DSA encoding written per key, for the audit */
	mutable QMap<const pki_base *, QString> mlDsaWritten{};
};

#endif
