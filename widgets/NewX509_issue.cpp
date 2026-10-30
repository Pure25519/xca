/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 *
 * GUI glue of certificate issuance (BTD-31): the entry points that open
 * the New Certificate dialog. They moved here from lib/db_x509.cpp so
 * that lib/ issues certificates from an IssuanceSpec only, and from the
 * db_x509 class into the certificate view with BTD-36.
 */

#include "CertTreeView.h"
#include "NewX509.h"

#include "lib/audit.h"
#include "lib/db_x509.h"
#include "lib/exception.h"
#include "lib/issuance.h"
#include "lib/pki_scard.h"
#include "lib/pki_temp.h"
#include "lib/pki_x509.h"
#include "lib/pki_x509req.h"
#include "lib/XcaWarningCore.h"

/* After the dialog issued the certificate in accept() (BTD-212): the
 * success message and the token copy */
static void issueFromDialog(db_x509 *certs, NewX509 *dlg)
{
	pki_x509 *cert = dlg->issued();
	if (!cert)
		return;
	certs->createSuccess(cert);
	pki_key *clientkey = cert->getRefKey();
	if (clientkey && clientkey->isToken()) {
		pki_scard *card = (pki_scard*)clientkey;
		if (XCA_YESNO("token.store_certificate", QObject::tr("Store the certificate to the key on the token '%1 (#%2)' ?").
			arg(card->getCardLabel()).arg(card->getSerial())))
		{
			try {
				cert->store_token(false);
			} catch (errorEx &err) {
				XCA_ERROR(err);
			}
		}
	}
}

/* The current certificate of the view, the default signer */
static pki_x509 *selectedSigner(db_x509 *certs)
{
	pki_x509 *sigcert = Store.lookupPki<pki_x509>(certs->getSelected());
	qDebug() << "SIGCERT" << (sigcert ? sigcert->getIntName() : "NULL");
	return sigcert;
}

void CertTreeView::newItem()
{
	if (!basemodel)
		return;
	NewX509 *dlg = new NewX509();
	dlg->setCert();
	dlg->issueOnAccept(certs());
	dlg->defineSigner(selectedSigner(certs()), true);
	if (dlg->exec()) {
		issueFromDialog(certs(), dlg);
	}
	delete dlg;
}

void CertTreeView::newCert(pki_x509req *req)
{
	if (!basemodel)
		return;
	NewX509 *dlg = new NewX509();
	pki_x509 *sigcert = selectedSigner(certs());
	dlg->setCert();
	dlg->issueOnAccept(certs());
	dlg->defineRequest(req);
	dlg->defineSigner(sigcert, true);
	if (dlg->exec()) {
		issueFromDialog(certs(), dlg);
	}
	delete dlg;
}

void CertTreeView::newCert(pki_temp *temp)
{
	if (!basemodel)
		return;
	NewX509 *dlg = new NewX509();
	dlg->setCert();
	dlg->issueOnAccept(certs());
	dlg->defineTemplate(temp);
	if (dlg->exec()) {
		issueFromDialog(certs(), dlg);
	}
	delete dlg;
}

void CertTreeView::newCert(pki_x509 *cert)
{
	if (!basemodel)
		return;
	NewX509 *dlg = new NewX509();
	dlg->setCert();
	dlg->issueOnAccept(certs());
	dlg->fromX509super(cert, false);
	if (dlg->exec()) {
		issueFromDialog(certs(), dlg);
	}
	delete dlg;
}
