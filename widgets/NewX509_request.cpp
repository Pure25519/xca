/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 *
 * GUI glue of request creation (BTD-32): the entry points that open the
 * New Request dialog. They moved here from lib/db_x509req.cpp so that
 * lib/ creates requests from a RequestSpec only, and from the db_x509req
 * class into the request view with BTD-36.
 */

#include "NewX509.h"
#include "ReqTreeView.h"

#include "lib/audit.h"
#include "lib/db_x509req.h"
#include "lib/exception.h"
#include "lib/pki_temp.h"
#include "lib/pki_x509req.h"
#include "lib/request.h"
#include "lib/XcaWarningCore.h"

void ReqTreeView::newItem()
{
	newItem(NULL, NULL);
}

void ReqTreeView::newItem(pki_temp *temp, pki_x509req *orig)
{
	if (!basemodel)
		return;
	NewX509 *dlg = new NewX509();

	if (temp) {
		dlg->defineTemplate(temp);
	} else if (orig) {
		dlg->fromX509super(orig, true);
	}
	dlg->setRequest();
	if (!dlg->exec()) {
		delete dlg;
		return;
	}
	RequestSpec spec = dlg->getRequestSpec();
	delete dlg;
	try {
		reqs()->createSuccess(reqs()->newRequest(
			ServiceContext::localUser(ServiceContext::gui), spec));
	} catch (errorEx &err) {
		XCA_ERROR(err);
	}
}
