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
						const QString &tag, XFile &file);
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
		void remFromCont(const QModelIndex &idx);
		QList<pki_x509*> getAllIssuers();
		QList<pki_x509*> getCerts(bool unrevoked);
		void writeIndex(const QString &fname, bool hierarchy) const;
		void writeIndex(XFile &file, QList<pki_x509*> items) const;
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
		void writePKCS12(pki_x509 *cert, XFile &file, bool chain) const;
		void writePKCS7(pki_x509 *cert, XFile &file, int flags,
				const QModelIndexList &list) const;
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
		void certRenewal(QModelIndexList indexes);
		void revoke(QModelIndexList indexes);
		void do_revoke(QModelIndexList indexes, const x509rev &r);
		void unRevoke(QModelIndexList indexes);
		int exportFlags(const QModelIndex &idx) const;
		void exportItems(const QModelIndexList &indexes,
				const pki_export *xport, XFile &file) const;
		void exportItem(const QModelIndex &, const pki_export *, XFile &) const;

	public slots:
		void newItem();

		void newCert(pki_temp *);
		void newCert(pki_x509req *);
};

#endif
