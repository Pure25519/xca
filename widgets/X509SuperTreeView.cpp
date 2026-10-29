/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "lib/db_x509super.h"
#include "lib/database_model.h"
#include "lib/db_temp.h"
#include "lib/pki_temp.h"
#include "lib/audit.h"
#include "lib/exception.h"
#include "lib/func.h"
#include "lib/template.h"
#include "XcaWarning.h"
#include "X509SuperTreeView.h"
#include "CertDetail.h"
#include "MainWindow.h"
#include "AutomationId.h"

#include <QAbstractItemModel>
#include <QAbstractItemView>
#include <QFileDialog>
#include <QMenu>

void X509SuperTreeView::fillContextMenu(QMenu *menu, QMenu *,
		const QModelIndex &index, QModelIndexList indexes)
{
	pki_x509super *x = dynamic_cast<pki_x509super*>(
					db_base::fromIndex(index));

	if (indexes.size() != 1 || !x)
		return;

	transform = setAutomationId(menu->addMenu(tr("Transform")),
			ctxId("transform"));
	setAutomationId(transform->addAction(tr("Template"), this,
		SLOT(toTemplate())), ctxId("transform_template"));
	setAutomationId(transform->addAction(tr("Public key"), this,
		SLOT(extractPubkey())), ctxId("transform_publicKey"))->
		setEnabled(!x->getRefKey());
}

void X509SuperTreeView::extractPubkey()
{
	QModelIndex idx = currentIndex();

	if (idx.isValid() && basemodel)
		x509super()->extractPubkey(idx);
}

/* Transform > Template: db_temp::newTemplate() (BTD-35) */
void X509SuperTreeView::toTemplate()
{
	pki_x509super *pki = db_base::fromIndex<pki_x509super>(currentIndex());
	db_temp *temps = Database.model<db_temp>();
	extList notPorted;

	if (!pki || !temps)
		return;

	TemplateSpec spec = TemplateSpec::fromObject(pki, &notPorted);
	if (notPorted.size())
		xcaWarning::warningv3(tr("The following extensions were not ported into the template"), notPorted);
	spec.comment = appendXcaComment(QString(), tr("Transformed from %1 '%2'")
		.arg(pki->getType() == x509 ?
			tr("Certificate") : tr("Certificate request"))
		.arg(pki->getIntName()));
	try {
		temps->createSuccess(temps->newTemplate(
			ServiceContext::localUser(ServiceContext::gui), spec));
	} catch (errorEx &err) {
		XCA_ERROR(err);
	}
}

void X509SuperTreeView::showPki(pki_base *pki)
{
	pki_x509super *x = dynamic_cast<pki_x509super *>(pki);
	CertDetail::showCert(this, x);
}
