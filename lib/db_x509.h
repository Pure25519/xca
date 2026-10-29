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
class ServiceContext;

class db_x509: public db_x509super
{
	Q_OBJECT

		static void writeTaggedPEM(const BioByteArray &b,
						const QString &tag, QIODevice &file);
		pki_x509 *issue(const IssuanceSpec &spec, AuditParams &params,
				const ServiceContext &ctx);
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
		/* GUI: New Certificate dialog preset from a certificate,
		 * also newItem() and the newCert() slots below: defined in
		 * widgets/NewX509_issue.cpp, they fill an IssuanceSpec */
		void newCert(pki_x509 *cert);
		void writePKCS12(pki_x509 *cert, QIODevice &file, bool chain,
				const Passwd &pass) const;
		void writePKCS7(const QList<pki_base *> &certs,
				QIODevice &file) const;
		void fillContextMenu(QMenu *menu, const QModelIndex &index);
		void inToCont(pki_base *pki);
		/* Serial number rule of BTD-31, see randomSerial() */
		static a1int randomSerial();
		bool serialInUse(pki_x509 *signer, const a1int &serial);
		a1int getUniqueSerial(pki_x509 *signer,
			const std::function<a1int()> &draw = randomSerial);
		void toToken(QModelIndex idx, bool alwaysSelect);
		void toRequest(QModelIndex idx);
		void updateCaProperties(pki_x509 *cert);
		void toCertificate(QModelIndex index);
		/* GUI: Renewal dialog, defined in widgets/CertExtend.cpp */
		void certRenewal(QModelIndexList indexes);

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
		 * not_a_ca, database_error, internal_error). An entry already
		 * in a CRL keeps its revocation date and CRL number. */
		void setRevocations(const ServiceContext &ctx, pki_x509 *ca,
				const x509revList &list);
		/* The certificate of issuer with this serial (certstrap rule
		 * 8): hex as XCA shows it, with or without "0x" and colons,
		 * or decimal. Digits only fit both readings; the one that
		 * names a certificate of issuer wins, both: ambiguous_serial.
		 * Throws serviceError invalid_serial, unknown_serial,
		 * ambiguous_serial. */
		pki_x509 *certBySerial(pki_x509 *issuer,
				const QString &serial) const;
		int exportFlags(pki_base *pki) const;
		void writeItems(const QList<pki_base *> &items,
				const pki_export *xport, QIODevice &file,
				const Passwd &pass) const;
		void writeItem(pki_base *pki, const pki_export *xport,
				QIODevice &file, const Passwd &pass) const;
		QList<pki_base *> exportedObjects(
				const QList<pki_base *> &items,
				const pki_export *xport) const;
		QList<pki_key *> exportedPrivateKeys(
				const QList<pki_base *> &items,
				const pki_export *xport) const;
		const pki_export *clipboardFormat() const;

	public slots:
		void newItem();

		void newCert(pki_temp *);
		void newCert(pki_x509req *);
};

#endif
