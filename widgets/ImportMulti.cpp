/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "ImportMulti.h"
#include "XcaWarning.h"
#include "MainWindow.h"
#include "lib/pki_base.h"
#include "lib/pki_pkcs7.h"
#include "lib/pki_pkcs12.h"
#include "lib/pki_crl.h"
#include "lib/pki_multi.h"
#include "lib/pki_scard.h"
#include "lib/pki_evp.h"
#include "lib/pki_temp.h"
#include "lib/audit.h"
#include "lib/importexport.h"
#include "CrlDetail.h"
#include "CertDetail.h"
#include "KeyDetail.h"
#include "NewX509.h"

#include <QPushButton>
#include <QMessageBox>
#include <QLabel>
#include <QInputDialog>
#include <QUrl>
#include <QMimeData>
#include <typeinfo>

ImportMulti::ImportMulti(QWidget *w)
	: QDialog(w && w->isVisible() ? w : nullptr)
{
	setupUi(this);
	setWindowTitle(XCA_TITLE);
	image->setPixmap(QPixmap(":certImg"));
	listView->setEditTriggers(QAbstractItemView::NoEditTriggers);
	mcont = new db_token();
	listView->setModel(mcont);
	listView->setIconSize(QPixmap(":key").size());
	listView->setSelectionMode(QAbstractItemView::ExtendedSelection);
	connect( listView, SIGNAL(doubleClicked(const QModelIndex &)),
		this, SLOT(on_butDetails_clicked()));
	deleteToken->hide();
	renameToken->hide();
	slotInfo->hide();
	setAcceptDrops(true);
	setWindowModality(Qt::WindowModal);
}

void ImportMulti::tokenInfo(const slotid &s)
{
	slot = s;
	mcont->setSlot(slot);
	deleteToken->show();
	renameToken->show();
	slotInfo->show();
	listView->setEditTriggers(QAbstractItemView::EditKeyPressed);

	pkcs11 p11;

	QString info = p11.driverInfo(slot);
	tkInfo ti = p11.tokenInfo(slot);
	info += tr("\nName: %1\nModel: %2\nSerial: %3").
		arg(ti.label()).arg(ti.model()).arg(ti.serial());

	slotInfo->setText(info);
	image->setPixmap(QPixmap(":scardImg"));
	heading->setText(tr("Manage security token"));
	setAcceptDrops(false);
}

void ImportMulti::addItem(pki_base *pki)
{
	if (!pki)
		return;

	if (pki->pkiSource == unknown)
		pki->pkiSource = imported;
	pki_multi *pm = dynamic_cast<pki_multi*>(pki);
	if (pm) {
		QList<pki_base*> items = pm->pull();
		foreach(pki_base *inner, items)
			addItem(inner);
		delete pm;
		return;
	}

	if (Database.isOpen()) {
		pki_x509 *cert = dynamic_cast<pki_x509 *>(pki);
		pki_crl *crl = dynamic_cast<pki_crl *>(pki);
		pki_x509super *cert_or_req = dynamic_cast<pki_x509super *>(pki);

		if (cert)
			cert->setSigner(cert->findIssuer());
		if (cert_or_req)
			cert_or_req->lookupKey();
		if (crl)
			crl->lookupIssuer();
	}
	if (!dynamic_cast<pki_key*>(pki) &&
	    !dynamic_cast<pki_x509name*>(pki))
	{
		XCA_WARN(tr("The type of the item '%1' is not recognized").
			arg(pki->getClassName()));
		delete pki;
		return;
	}
	/* Best effort, and before the card is in the dialog: a write error
	 * (since BTD-50 a typed error) must not leave the dialog holding a
	 * card that its caller frees (review of xca#68) */
	pki_scard *card = dynamic_cast<pki_scard*>(pki);
	if (card && Database.isOpen()) {
		try {
			mcont->rename_token_in_database(card);
		} catch (errorEx &err) {
			qWarning() << "Token label not stored:"
				<< err.getString();
		}
	}
	mcont->inToCont(pki);
}

bool ImportMulti::openDB() const
{
	if (!Database.isOpen()) {
		if (mainwin->init_database(QString()) == 2)
			return false;
		if (!Database.isOpen())
			mainwin->load_database();
	}
	return Database.isOpen();
}

void ImportMulti::dragEnterEvent(QDragEnterEvent *event)
{
	if (event->mimeData()->hasUrls())
		event->acceptProposedAction();
}

void ImportMulti::dropEvent(QDropEvent *event)
{
	QList<QUrl> urls = event->mimeData()->urls();
	QUrl u;
	QStringList failed;
	pki_multi *pki = new pki_multi();

	foreach(u, urls)
		pki->probeAnything(u.toLocalFile());

	failed << pki->failed_files;
	importError(failed);
	addItem(pki);
	event->acceptProposedAction();
}

void ImportMulti::on_butRemove_clicked()
{
	QItemSelectionModel *selectionModel = listView->selectionModel();
	QModelIndexList indexes = selectionModel->selectedIndexes();
	QModelIndex index;
	QString items;

	foreach(index, indexes) {
		if (index.column() != 0)
			continue;
		pki_base *pki = db_base::fromIndex(index);
		mcont->remFromCont(pki);
		delete pki;
	}
	if (mcont->rowCount(QModelIndex()) == 0)
		accept();
}

void ImportMulti::on_butOk_clicked()
{
	QModelIndexList indexes;

	for (int i = 0; i < mcont->rowCount(); i++)
		indexes << mcont->index(i, 0, QModelIndex());

	importIndexes(indexes);
}

void ImportMulti::on_butImport_clicked()
{
	QItemSelectionModel *selectionModel = listView->selectionModel();

	importIndexes(selectionModel->selectedIndexes());
}

void ImportMulti::importIndexes(const QModelIndexList &indexes)
{
	QList<pki_base *> items;

	if (!openDB())
		return;

	foreach(QModelIndex index, indexes) {
		pki_base *pki = index.column() == 0 ?
				mcont->fromIndex(index) : nullptr;
		if (pki && !pki->getSqlItemId().isValid())
			items << pki;
	}
	/* One by one: a failure neither rolls back nor drops the others,
	 * and the failed item stays in the dialog (BTD-114) */
	QStringList errors;
	foreach(pki_base *pki, items) {
		QString name = pki->getIntName(), code, error;
		importOne(pki, &code, &error);
		/* a cancelled prompt ends the import, the rest stays */
		if (code == "cancelled")
			break;
		if (!error.isEmpty())
			errors << QString("%1: %2").arg(name).arg(error);
	}
	if (!errors.isEmpty())
		XCA_ERROR(errorEx(errors.join("\n")));
	if (mcont->rowCount(QModelIndex()) == 0)
		accept();
}

/* Stores one item of the dialog. An item the service did not consume
 * goes back into the dialog (ImportSpec::unstored, BTD-114); code and
 * error name the failure, both empty on success */
pki_base *ImportMulti::importOne(pki_base *pki, QString *code,
				QString *error)
{
	QList<pki_base *> unstored;
	ImportSpec spec;
	pki_base *stored = nullptr;

	spec.items << pki;
	spec.unstored = &unstored;
	mcont->remFromCont(pki);
	try {
		ImportResult result = Database.importItems(
			ServiceContext::localUser(ServiceContext::gui), spec);
		foreach(pki_base *existing, result.existing)
			XCA_INFO(importExistsMessage(existing));
		foreach(const QString &w, result.warnings)
			XCA_WARN(w);
		stored = result.created.value(0);
	} catch (serviceError &err) {
		*code = err.code;
		*error = err.getString();
	} catch (errorEx &err) {
		*code = "internal_error";
		*error = err.getString();
	}
	foreach(pki_base *back, unstored)
		mcont->inToCont(back);
	return stored;
}

QList<pki_base *> ImportMulti::importItems(QList<pki_base *> items)
{
	ImportSpec spec;
	spec.items = items;
	try {
		ImportResult result = Database.importItems(
			ServiceContext::localUser(ServiceContext::gui), spec);
		foreach(pki_base *pki, result.existing)
			XCA_INFO(importExistsMessage(pki));
		foreach(const QString &w, result.warnings)
			XCA_WARN(w);
		return result.created;
	} catch (serviceError &err) {
		if (err.code != "cancelled")
			XCA_ERROR(err);
	} catch (errorEx &err) {
		XCA_ERROR(err);
	}
	return QList<pki_base *>();
}

void ImportMulti::on_deleteToken_clicked()
{
	QItemSelectionModel *selectionModel = listView->selectionModel();
	QModelIndexList indexes = selectionModel->selectedIndexes();
	QModelIndex index;
	QString items;

	foreach(index, indexes) {
		if (index.column() != 0)
			continue;
		pki_base *pki = db_base::fromIndex(index);
		try {
			pki->deleteFromToken(slot);
			mcont->remFromCont(pki);
			delete pki;
		} catch (errorEx &err) {
			XCA_ERROR(err);
		}
	}
}
void ImportMulti::on_renameToken_clicked()
{
	QItemSelectionModel *selectionModel = listView->selectionModel();
	QModelIndexList indexes = selectionModel->selectedIndexes();
	QModelIndex index;

	foreach(index, indexes) {
		if (index.column() != 0)
			continue;
		listView->edit(index);
		break;
	}
}

pki_base *ImportMulti::import(const QModelIndex &idx)
{
	return idx.column() == 0 ? import(mcont->fromIndex(idx)) : nullptr;
}

pki_base *ImportMulti::import(pki_base *pki)
{
	if (!pki || pki->getSqlItemId().isValid())
		return NULL;

	if (!Database.isOpen()) {
		try {
			Database.open_default();
		} catch(...) {
			XCA_INFO(tr("Could not open the default database"));
		};
	}
	/* without a database the item stays in the dialog (BTD-114) */
	if (!Database.isOpen())
		return NULL;
	QString code, error;
	pki_base *stored = importOne(pki, &code, &error);
	if (!error.isEmpty() && code != "cancelled")
		XCA_ERROR(errorEx(error));
	return stored;
}

void ImportMulti::on_butDetails_clicked()
{
	QItemSelectionModel *selectionModel = listView->selectionModel();

	if (selectionModel->selectedIndexes().count())
		showDetail(selectionModel->selectedIndexes().first());
	if (mcont->rowCount(QModelIndex()) == 0)
		accept();
}

void ImportMulti::showDetail(const QModelIndex &idx)
{
	showDetail(db_base::fromIndex(idx));
}

void ImportMulti::showDetail(pki_base *pki)
{
	if (pki) try {
		pki_x509super *pki_super = dynamic_cast<pki_x509super*>(pki);
		if (pki_super) {
			CertDetail::showCert(this, pki_super);
			return;
		}
		pki_key *key = dynamic_cast<pki_key*>(pki);
		if (key) {
			KeyDetail::showKey(this, key);
			return;
		}
		pki_crl *crl = dynamic_cast<pki_crl*>(pki);
		if (crl) {
			CrlDetail::showCrl(this, crl);
			return;
		}
		pki_temp *temp = dynamic_cast<pki_temp*>(pki);
		if (temp) {
			NewX509::showTemp(this, temp);
			return;
		}
		XCA_WARN(tr("The type of the item '%1' is not recognized").
			arg(pki->getClassName()));
	}
	catch (errorEx &err) {
		XCA_ERROR(err);
	}
}

ImportMulti::~ImportMulti()
{
	QModelIndex idx = listView->currentIndex();
	while (idx != QModelIndex()) {
		pki_base *pki = db_base::fromIndex(idx);
		mcont->remFromCont(pki);
		delete pki;
		idx = listView->currentIndex();
	}
	listView->setModel(NULL);
	delete mcont;
}

int ImportMulti::entries()
{
	return mcont->allItemsCount();
}

void ImportMulti::importError(QStringList failed)
{
	if (failed.count() == 1) {
		XCA_INFO(tr("The file '%1' did not contain PKI data").
			arg(failed[0]));
	} else if (failed.count() > 1) {
		XCA_INFO(tr("The %1 files: '%2' did not contain PKI data").
			arg(failed.count()).
			arg(failed.join("', '")));
	}
}

void ImportMulti::execute(int force, QStringList failed)
{
	importError(failed);

	/* if there is nothing to import don't pop up */
	if (entries() == 0) {
		accept();
		return;
	}
	/* if there is only 1 item and force is 0 import it silently */
	if (entries() == 1) {
		QModelIndex idx = mcont->index(0, 0, QModelIndex());
		if (force == 0 && openDB()) {
			pki_base *pki = import(idx);
			if (pki && !Settings["suppress_messages"])
				XCA_INFO(pki->getMsg(pki_base::msg_import).
					arg(pki->getIntName()));

		} else {
			showDetail(idx);
		}
		return;
	}
	/* the behaviour for more than one item */
	exec();
}
