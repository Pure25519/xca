/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2015 - 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "lib/pki_temp.h"
#include "lib/load_obj.h"
#include "lib/audit.h"
#include "lib/exception.h"
#include "lib/template.h"
#include "lib/profile_store.h"
#include "TempTreeView.h"
#include "ExportDialog.h"
#include "NewX509.h"
#include "XcaDialog.h"
#include "MainWindow.h"
#include "AutomationId.h"
#include <QAbstractItemModel>
#include <QAbstractItemView>
#include <QMenu>

void TempTreeView::fillContextMenu(QMenu *menu, QMenu *,
		const QModelIndex &, QModelIndexList indexes)
{
	if (indexes.size() != 1)
		return;

	setAutomationId(menu->addAction(tr("Duplicate"), this,
			SLOT(duplicateTemp())), ctxId("duplicate"));
	setAutomationId(menu->addAction(tr("Create certificate"), this,
			SLOT(certFromTemp())), ctxId("createCertificate"));
	setAutomationId(menu->addAction(tr("Create request"), this,
			SLOT(reqFromTemp())), ctxId("createRequest"));
	setAutomationId(menu->addAction(tr("Migrate to profile"), this,
			SLOT(migrateTemp())), ctxId("migrateToProfile"));
}

/* The template dialogs fill a TemplateSpec; storing is the service
 * function of db_temp (BTD-35) */
void TempTreeView::duplicateTemp()
{
	pki_temp *temp = db_base::fromIndex<pki_temp>(currentIndex());
	if (!temp || !temps())
		return;

	/* as pki_temp(const pki_temp *) always did: without the comment */
	TemplateSpec spec = TemplateSpec::fromTemplate(temp);
	spec.name += " " + tr("copy");
	spec.comment.clear();
	spec.source = unknown;
	try {
		temps()->newTemplate(ServiceContext::localUser(
				ServiceContext::gui), spec);
	} catch (errorEx &err) {
		XCA_ERROR(err);
	}
}

/* The template as a generic profile in the profile store (BTD-167);
 * the template stays */
void TempTreeView::migrateTemp()
{
	pki_temp *temp = db_base::fromIndex<pki_temp>(currentIndex());
	if (!temp)
		return;
	try {
		ProfileStore::Document d = ProfileStore::migrateTemplate(
			ServiceContext::localUser(ServiceContext::gui),
			TemplateSpec::fromTemplate(temp));
		QString msg = tr("The template '%1' is now the profile '%2', version %3")
			.arg(temp->getIntName(), d.name).arg(d.version);
		if (!d.dropped.isEmpty())
			msg += "\n" + tr("Not migrated, a profile has no place for: %1")
				.arg(d.dropped.join(", "));
		XCA_INFO(msg);
	} catch (errorEx &err) {
		XCA_ERROR(err);
	}
}

void TempTreeView::certFromTemp()
{
	pki_temp *temp = db_base::fromIndex<pki_temp>(currentIndex());
	if (temp)
		emit newCert(temp);
}

void TempTreeView::reqFromTemp()
{
	pki_temp *temp = db_base::fromIndex<pki_temp>(currentIndex());
	if (temp)
		emit newReq(temp);
}

void TempTreeView::showPki(pki_base *pki)
{
	alterTemp(dynamic_cast<pki_temp *>(pki));
}

/* Shows temp in the template dialog; *spec receives the input */
bool TempTreeView::runTempDlg(pki_temp *temp, TemplateSpec *spec)
{
	NewX509 *dlg = new NewX509(this);

	dlg->setTemp(temp, true);
	if (!dlg->exec()) {
		delete dlg;
		return false;
	}
	*spec = dlg->templateSpec();
	delete dlg;
	return true;
}

void TempTreeView::newItem()
{
	if (!temps())
		return;

	itemComboTemp *ic = new itemComboTemp(NULL);
	ic->insertPkiItems(temps()->getPredefs());
	XcaDialog *dlg = new XcaDialog(this, tmpl, ic,
				tr("Preset Template values"), QString());
	pki_temp *preset = dlg->exec() ? ic->currentPkiItem() : nullptr;
	delete dlg;
	if (!preset)
		return;

	/* the dialog shows a copy of the preset */
	pki_temp *temp = new pki_temp(preset);
	TemplateSpec spec;
	bool ok = runTempDlg(temp, &spec);
	delete temp;
	if (!ok)
		return;
	spec.source = generated;
	try {
		temps()->createSuccess(temps()->newTemplate(
			ServiceContext::localUser(ServiceContext::gui), spec));
	} catch (errorEx &err) {
		XCA_ERROR(err);
	}
}

bool TempTreeView::alterTemp(pki_temp *temp)
{
	TemplateSpec spec;

	if (!temps() || !temp)
		return false;

	if (!runTempDlg(temp, &spec))
		return false;

	spec.source = temp->pkiSource;
	try {
		temps()->updateTemplate(ServiceContext::localUser(
				ServiceContext::gui), temp, spec);
	} catch (errorEx &err) {
		XCA_ERROR(err);
		return false;
	}
	return true;
}

void TempTreeView::load()
{
	load_temp l;
	load_default(&l);
}

ExportDialog *TempTreeView::exportDialog(const QModelIndexList &indexes)
{
	return new ExportDialog(this,
		tr("Template export"),
		tr("XCA Templates ( *.xca )"),
		indexes, QPixmap(":tempImg"),
		pki_export::select(tmpl, basemodel->exportFlags(items(indexes))));
}
