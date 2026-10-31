/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "ui_CaProperties.h"
#include "CertTreeView.h"
#include "XcaWarning.h"
#include "XcaDialog.h"
#include "MainWindow.h"
#include "RevocationList.h"
#include "ExportDialog.h"
#include "NewCrl.h"
#include "AutomationId.h"
#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/db_crl.h"
#include "lib/load_obj.h"

#include <QAbstractItemModel>
#include <QAbstractItemView>
#include <QFileDialog>
#include <QMenu>

void CertTreeView::fillContextMenu(QMenu *menu, QMenu *subExport,
		const QModelIndex &index, QModelIndexList indexes)
{
	QMenu *subCa;
	bool parentCanSign, multi, hasScard, sameParent,
		allRevoked, allUnrevoked;

	X509SuperTreeView::fillContextMenu(menu, subExport, index, indexes);

	QAction *a = menu->addAction(tr("Hide unusable certificates"));
	a->setObjectName(ctxId("hideUnusable"));
	a->setCheckable(true);
	a->setChecked(Settings["hide_unusable"]);

	connect(a, SIGNAL(triggered(bool)),
		this, SLOT(toggleHideExpired(bool)));

	setAutomationId(menu->addAction(tr("Import PKCS#12"), this,
			SLOT(loadPKCS12())), ctxId("importPkcs12"));
	setAutomationId(menu->addAction(tr("Import from PKCS#7"), this,
			SLOT(loadPKCS7())), ctxId("importPkcs7"));

	pki_x509 *cert = db_base::fromIndex<pki_x509>(index);

	if (indexes.size() == 0 || !cert)
		return;

	pki_key *privkey = cert->getRefKey();
	pki_x509 *parent = cert->getSigner();
	parentCanSign = parent && parent->canSign() && (parent != cert);
	hasScard = pkcs11::libraries.loaded();

	multi = indexes.size() > 1;

	allUnrevoked = allRevoked = sameParent = true;
	foreach(QModelIndex i, indexes) {
		pki_x509 *c = db_base::fromIndex<pki_x509>(i);
		if (!c)
			continue;
		if (c->getSigner() != parent)
			sameParent = false;
		if (c->isRevoked())
			allUnrevoked = false;
		else
			allRevoked = false;
	}

	if (!multi) {
		setAutomationId(transform->addAction(tr("Request"), this,
			SLOT(toRequest())), ctxId("transform_request"))->
			setEnabled(privkey && privkey->isPrivKey());
		setAutomationId(subExport->addAction(tr("Security token"), this,
			SLOT(toToken())), ctxId("export_token"))->
			setEnabled(hasScard);
		setAutomationId(subExport->addAction(tr("Other token"), this,
			SLOT(toOtherToken())), ctxId("export_otherToken"))->
			setEnabled(hasScard && privkey && privkey->isToken());

		setAutomationId(transform->addAction(tr("Similar Certificate"), this,
			SLOT(toCertificate())), ctxId("transform_similarCertificate"));

		setAutomationId(menu->addAction(tr("Delete from Security token"),
			this, SLOT(deleteFromToken())), ctxId("deleteFromToken"))->
			setEnabled(hasScard);

		subCa = setAutomationId(menu->addMenu(tr("CA")), ctxId("ca"));
		setAutomationId(subCa->addAction(tr("Properties"), this,
			SLOT(caProperties())), ctxId("ca_properties"));
		setAutomationId(subCa->addAction(tr("Generate CRL"), this,
			SLOT(genCrl())), ctxId("ca_generateCrl"));
		setAutomationId(subCa->addAction(tr("Manage revocations"), this,
			SLOT(manageRevocations())), ctxId("ca_manageRevocations"));
		subCa->setEnabled(cert->canSign());

		setAutomationId(menu->addAction(tr("Import OpenVPN tls-auth key"),
			this, SLOT(loadTaKey())), ctxId("importTaKey"))->
			setEnabled(cert->isCA());
	}
	if (parent == cert && parent->canSign())
		setAutomationId(menu->addAction(tr("Renewal"), this,
			SLOT(certRenewal())), ctxId("renewal"));
	if (sameParent && parentCanSign) {
		QString n = multi ? QString(" [%1]").arg(indexes.size()) : "";
		setAutomationId(menu->addAction(tr("Renewal") +n, this,
			SLOT(certRenewal())), ctxId("renewal"));
		if (allUnrevoked)
			setAutomationId(menu->addAction(tr("Revoke") +n, this,
				SLOT(revoke())), ctxId("revoke"));
		if (allRevoked)
			setAutomationId(menu->addAction(tr("Unrevoke") +n, this,
				SLOT(unRevoke())), ctxId("unrevoke"));
	}
}

void CertTreeView::toRequest()
{
	if (basemodel)
		certs()->toRequest(currentIndex());
}

void CertTreeView::toToken()
{
	if (basemodel)
		certs()->toToken(currentIndex(), false);
}

void CertTreeView::toOtherToken()
{
	if (basemodel)
		certs()->toToken(currentIndex(), true);
}

void CertTreeView::loadPKCS12()
{
	load_pkcs12 l;
	load_default(&l);
}

void CertTreeView::loadPKCS7()
{
	load_pkcs7 l;
	load_default(&l);
}

void CertTreeView::loadTaKey()
{
	pki_x509 *ca = db_base::fromIndex<pki_x509>(currentIndex());
	if (!ca || !ca->isCA())
		return;

	load_takey l;
	QString fname = QFileDialog::getOpenFileName(this, l.caption,
					getHomeDir(), l.filter);
	if (fname.isEmpty())
		return;
	XFile f(fname);
	f.open_read();
	ca->importTaKey(f.read(4096));
}

void CertTreeView::genCrl()
{
	pki_x509 *ca = db_base::fromIndex<pki_x509>(currentIndex());

	NewCrl::newCrl(this, ca);
}

void CertTreeView::toCertificate()
{
	if (!basemodel)
		return;
	QModelIndex index = currentIndex();
	pki_x509 *cert = db_base::fromIndex<pki_x509>(index);
	if (!cert)
		return;
	if (!cert->getRefKey() && cert->getSigner() != cert)
		certs()->extractPubkey(index);
	cert->pkiSource = transformed;
	newCert(cert);
}

void CertTreeView::deleteFromToken()
{
	pki_x509 *cert = db_base::fromIndex<pki_x509>(currentIndex());
	/* no current certificate (BTD-240) */
	if (!cert) {
		XCA_WARN(tr("No certificate selected"));
		return;
	}
	try {
		cert->deleteFromToken();
	} catch (errorEx &err) {
		XCA_ERROR(err);
	}
}

void CertTreeView::changeView()
{
	if (!basemodel)
		return;
	XcaTreeView::changeView();
	mainwin->BNviewState->setText(basemodel->treeViewMode() ?
		tr("Plain View") : tr("Tree View"));
}

void CertTreeView::manageRevocations()
{
	pki_x509 *cert = db_base::fromIndex<pki_x509>(currentIndex());
	if (!cert)
		return;

	RevocationList *dlg = new RevocationList();
	dlg->setRevList(cert->getRevList(), cert);
	if (dlg->exec()) {
		try {
			certs()->setRevocations(ServiceContext::localUser(
				ServiceContext::gui), cert, dlg->getRevList());
		} catch (errorEx &err) {
			XCA_ERROR(err);
		}
		columnsChanged();
	}
}

void CertTreeView::caProperties()
{
	Ui::CaProperties ui;
	XcaDialog *dlg;
	QWidget *w;

	pki_x509 *cert = db_base::fromIndex<pki_x509>(currentIndex());
	if (!cert || !basemodel)
		return;

	w = new QWidget();
	ui.setupUi(w);
	ui.days->setSuffix(QString(" ") + tr("days"));
	ui.days->setMaximum(1000000);
	ui.days->setValue(cert->getCrlDays());

	QVariant tmplId = cert->getTemplateSqlId();
	pki_temp *templ = Store.lookupPki<pki_temp>(tmplId);

	ui.temp->insertPkiItems(Store.getAll<pki_temp>());
	ui.temp->setNullItem(tr("No template"));
	ui.temp->setCurrentIndex(0);
	if (templ)
		ui.temp->setCurrentPkiItem(templ);

	dlg = new XcaDialog(this, x509, w, tr("CA Properties"),
		cert->getIntName(), "ca_properties");

	if (dlg->exec()) {
		int oldDays = cert->getCrlDays();
		templ = ui.temp->currentPkiItem();
		cert->setTemplateSqlId(templ ? templ->getSqlItemId() :
						QVariant());
		cert->setCrlDays(ui.days->value());
		try {
			certs()->updateCaProperties(cert);
		} catch (errorEx &err) {
			/* not stored: memory keeps the stored values (BTD-50) */
			cert->setTemplateSqlId(tmplId);
			cert->setCrlDays(oldDays);
			XCA_ERROR(err);
		}
		columnsChanged();
	}
	delete dlg;
}

void CertTreeView::certRenewal()
{
	renewal(getSelectedIndexes());
}

void CertTreeView::revoke()
{
	QModelIndexList indexes = getSelectedIndexes();

	if (!basemodel || indexes.isEmpty())
		return;
	Revocation *dlg = new Revocation(indexes);
	if (dlg->exec()) {
		ServiceContext ctx = ServiceContext::localUser(
					ServiceContext::gui);
		x509rev rev = dlg->getRevocation();
		try {
			foreach(QModelIndex idx, indexes) {
				pki_x509 *cert = db_base::fromIndex<pki_x509>(idx);
				if (cert && !cert->isRevoked())
					certs()->revoke(ctx, cert, rev);
			}
		} catch (errorEx &err) {
			XCA_ERROR(err);
		}
		columnsChanged();
	}
	delete dlg;
}

void CertTreeView::unRevoke()
{
	if (!basemodel)
		return;
	ServiceContext ctx = ServiceContext::localUser(ServiceContext::gui);
	try {
		foreach(QModelIndex idx, getSelectedIndexes()) {
			pki_x509 *cert = db_base::fromIndex<pki_x509>(idx);
			if (cert && cert->isRevoked())
				certs()->unrevoke(ctx, cert);
		}
	} catch (errorEx &err) {
		XCA_ERROR(err);
	}
	columnsChanged();
}

void CertTreeView::load()
{
	load_cert c;
	load_default(&c);
}

ExportDialog *CertTreeView::exportDialog(const QModelIndexList &indexes)
{
	return new ExportDialog(this,
		tr("Certificate export"),
		tr("X509 Certificates ( *.pem *.cer *.crt *.p12 *.pfx *.p7b )") + ";;"+
		tr("vCalendar entry ( *.ics )") + ";;" +
		tr("OpenVPN file ( *.ovpn )") + ";;" +
		tr("OpenVPN tls-auth key ( *.key )"), indexes, QPixmap(":certImg"),
		pki_export::select(x509, basemodel->exportFlags(items(indexes))),
		                   "certexport");
}

void CertTreeView::toggleHideExpired(bool hide)
{
	qDebug() << "Hide expired certificates" << hide;
	Settings["hide_unusable"] = hide;
	columnsChanged();
}