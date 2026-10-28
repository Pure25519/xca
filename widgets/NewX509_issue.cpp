/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 *
 * GUI glue of certificate issuance (BTD-31): the db_x509 entry points
 * that open the New Certificate dialog. They moved here from
 * lib/db_x509.cpp so that lib/ issues certificates from an IssuanceSpec
 * only; BTD-36 moves them out of the db_x509 class.
 */

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

/* Issues the certificate the accepted dialog describes */
static void issueFromDialog(db_x509 *certs, NewX509 *dlg)
{
	IssuanceSpec spec = dlg->getIssuanceSpec();
	/* The dialog used to return silently without a selection */
	if (!spec.request && !spec.key)
		return;
	if (dlg->foreignSignRB->isChecked() && !spec.signer)
		return;
	try {
		pki_x509 *cert = certs->newCert(
			ServiceContext::localUser(ServiceContext::gui), spec);
		certs->createSuccess(cert);
		pki_key *clientkey = cert->getRefKey();
		if (clientkey && clientkey->isToken()) {
			pki_scard *card = (pki_scard*)clientkey;
			if (XCA_YESNO(QObject::tr("Store the certificate to the key on the token '%1 (#%2)' ?").
				arg(card->getCardLabel()).arg(card->getSerial())))
			{
				try {
					cert->store_token(false);
				} catch (errorEx &err) {
					XCA_ERROR(err);
				}
			}
		}
	} catch (errorEx &err) {
		XCA_ERROR(err);
	}
}

void db_x509::newItem()
{
	NewX509 *dlg = new NewX509();
	dlg->setCert();
	pki_x509 *sigcert = Store.lookupPki<pki_x509>(selected);
	qDebug() << "SIGCERT" << (sigcert ? sigcert->getIntName() : "NULL");
	dlg->defineSigner(sigcert, true);
	if (dlg->exec()) {
		issueFromDialog(this, dlg);
	}
	delete dlg;
}

void db_x509::newCert(pki_x509req *req)
{
	NewX509 *dlg = new NewX509();
	pki_x509 *sigcert = Store.lookupPki<pki_x509>(selected);
	qDebug() << "SIGCERT" << (sigcert ? sigcert->getIntName() : "NULL");
	dlg->setCert();
	dlg->defineRequest(req);
	dlg->defineSigner(sigcert, true);
	if (dlg->exec()) {
		issueFromDialog(this, dlg);
	}
	delete dlg;
}

void db_x509::newCert(pki_temp *temp)
{
	NewX509 *dlg = new NewX509();
	dlg->setCert();
	dlg->defineTemplate(temp);
	if (dlg->exec()) {
		issueFromDialog(this, dlg);
	}
	delete dlg;
}

void db_x509::newCert(pki_x509 *cert)
{
	NewX509 *dlg = new NewX509();
	dlg->setCert();
	dlg->fromX509super(cert, false);
	if (dlg->exec()) {
		issueFromDialog(this, dlg);
	}
	delete dlg;
}
