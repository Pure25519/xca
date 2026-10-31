/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#ifndef __DB_X509_H
#define __DB_X509_H

#include "pki_export.h"
#include "db_x509super.h"
#include "asn1int.h"
#include "x509rev.h"

#include <functional>

class pki_x509req;
class pki_x509;
class pki_temp;
class pki_crl;
class AuditParams;
class IssuanceSpec;
class RenewalSpec;
class ServiceContext;

class db_x509: public db_x509super
{
	Q_OBJECT

		static void writeTaggedPEM(const BioByteArray &b,
						const QString &tag, QIODevice &file);
		pki_x509 *issue(const IssuanceSpec &spec, AuditParams &params,
				const ServiceContext &ctx, const QString &action);
		pki_x509 *issueAudited(const ServiceContext &ctx,
				const IssuanceSpec &spec, const QString &action);
	protected:
		dbheaderList getHeaders();
		void dereferenceIssuer();

	public:
		db_x509();
		pki_base *newPKI(enum pki_type type = none);
		pki_x509 *findIssuer(pki_x509 *client);
		virtual void loadContainer();

		bool updateView();
		void updateViewAll();
		void updateViewPKI(pki_base *pki);
		void remFromCont(pki_base *pki);
		QList<pki_x509*> getAllIssuers();
		QList<pki_x509*> getCerts(bool unrevoked);
		void writeIndex(const QString &fname, bool hierarchy) const;
		void writeIndex(QIODevice &file, QList<pki_x509*> items) const;
		pki_base *insert(pki_base *item);
		void markRequestSigned(pki_x509req *req, pki_x509 *cert);
		/* Issues one certificate (BTD-31). Throws serviceError for a
		 * rejected spec and errorEx for anything else; writes exactly
		 * one audit entry certificate.issue either way (error code
		 * internal_error for anything but a serviceError). Call it
		 * outside a transaction: a failure entry appended inside the
		 * caller's transaction would be rolled back with it. */
		pki_x509 *newCert(const ServiceContext &ctx,
				const IssuanceSpec &spec);
		/* Renews or re-keys certificates (BTD-56), all in one
		 * transaction: one entry certificate.renew per certificate
		 * (the parameters of certificate.issue plus the predecessor),
		 * or nothing stored and one failure entry for the refused
		 * one. The predecessors stay as they are; revoking or
		 * deleting them is the caller's next step, after this
		 * returned. Throws like newCert(), plus the errors of
		 * RenewalSpec::issuanceSpec(). */
		QList<pki_x509 *> renew(const ServiceContext &ctx,
				const QList<RenewalSpec> &specs);
		/* The PKCS#12 algorithm and ML-DSA encoding of the
		 * options; by default the setting pkcs12_enc_algo and
		 * OpenSSL's encoding */
		void writePKCS12(pki_x509 *cert, QIODevice &file, bool chain,
				const Passwd &pass,
				const ExportOptions &opts = ExportOptions()) const;
		void writePKCS7(const QList<pki_base *> &certs,
				QIODevice &file) const;
		void inToCont(pki_base *pki);
		/* Serial number rule of BTD-31, see randomSerial() */
		static a1int randomSerial();
		bool serialInUse(pki_x509 *signer, const a1int &serial);
		a1int getUniqueSerial(pki_x509 *signer,
			const std::function<a1int()> &draw = randomSerial);
		void toToken(QModelIndex idx, bool alwaysSelect);
		void toRequest(QModelIndex idx);
		void updateCaProperties(pki_x509 *cert);

		/* Revocation (BTD-33). Each call writes exactly one audit
		 * entry certificate.revoke / certificate.unrevoke and throws
		 * serviceError for a rejected request (missing_certificate,
		 * unknown_issuer, self_signed, invalid_reason,
		 * already_revoked, not_revoked, database_error), errorEx for
		 * anything else (audited as internal_error). The reason is
		 * the one of rev; rev's serial is replaced by the
		 * certificate's, an undefined date by now. Call them outside
		 * a transaction (see newCert()). */
		void revoke(const ServiceContext &ctx, pki_x509 *cert,
				const x509rev &rev);
		void unrevoke(const ServiceContext &ctx, pki_x509 *cert);
		/* Replaces the revocation list of a CA (Manage revocations
		 * dialog): serials without a certificate in the database are
		 * allowed here. One entry certificate.revoke per added or
		 * changed and certificate.unrevoke per removed serial, all in
		 * one transaction; on a rejection or error nothing changes
		 * and one entry ca.set_revocations with the error code is
		 * written (invalid_serial, invalid_reason, duplicate_serial,
		 * issuer_not_ca, database_error, internal_error). An entry already
		 * in a CRL keeps its revocation date and CRL number. */
		void setRevocations(const ServiceContext &ctx, pki_x509 *ca,
				const x509revList &list);
		/* The certificate of issuer with this serial (certstrap rule
		 * 8): hex as XCA shows it, with or without "0x" and colons
		 * (digits only too), or decimal with the prefix "dec:".
		 * Throws serviceError invalid_serial, unknown_serial. */
		pki_x509 *certBySerial(pki_x509 *issuer,
				const QString &serial) const;
		int exportFlags(pki_base *pki) const;
		void writeItems(const QList<pki_base *> &items,
				const pki_export *xport, QIODevice &file,
				const Passwd &pass, const ExportOptions &opts) const;
		void writeItem(pki_base *pki, const pki_export *xport,
				QIODevice &file, const Passwd &pass,
				const ExportOptions &opts) const;
		QList<pki_base *> exportedObjects(
				const QList<pki_base *> &items,
				const pki_export *xport) const;
		QList<pki_key *> exportedPrivateKeys(
				const QList<pki_base *> &items,
				const pki_export *xport) const;
		QList<pki_base *> exportedSecrets(
				const QList<pki_base *> &items,
				const pki_export *xport) const;
		const pki_export *clipboardFormat() const;
};

#endif
