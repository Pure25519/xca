/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __CERTTREEVIEW_H
#define __CERTTREEVIEW_H

#include "X509SuperTreeView.h"
#include "lib/db_x509.h"

class CertTreeView: public X509SuperTreeView
{
	Q_OBJECT

	db_x509 *certs() const
	{
		return dynamic_cast<db_x509*>(basemodel);
	}

    public:
	CertTreeView(QWidget *parent) : X509SuperTreeView(parent)
	{
		ClipboardSettings = "CertFormat";
		ClipboardPki_type = x509;
	}
	void fillContextMenu(QMenu *menu, QMenu *subExport,
			const QModelIndex &index, QModelIndexList indexes);
	ExportDialog *exportDialog(const QModelIndexList &index);

	/* New Certificate dialog preset from a certificate */
	void newCert(pki_x509 *cert);
	/* Renewal dialog for the certificates of the source model
	 * indexes (CertExtend.cpp) */
	void renewal(QModelIndexList indexes);

    public slots:
	/* The New Certificate dialog (NewX509_issue.cpp, BTD-36) */
	void newItem();
	void newCert(pki_temp *temp);
	void newCert(pki_x509req *req);
	void changeView();
	void toRequest();
	void toCertificate();
	void toToken();
	void toOtherToken();
	void genCrl();
	void loadPKCS7();
	void loadPKCS12();
	void deleteFromToken();
	void manageRevocations();
	void certRenewal();
	void caProperties();
	void revoke();
	void unRevoke();
	void load();
	void loadTaKey();
	void toggleHideExpired(bool);
};
#endif
