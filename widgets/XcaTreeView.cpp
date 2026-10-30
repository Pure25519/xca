/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2006 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QAbstractItemModel>
#include <QAbstractItemView>
#include <QContextMenuEvent>
#include <QMenu>
#include <QVariant>
#include <QRegularExpression>
#include <QFileDialog>
#include <QClipboard>
#include <QActionGroup>

#include "OidResolver.h"
#include "XcaHeaderView.h"
#include "XcaTreeView.h"
#include "XcaProxyModel.h"
#include "MainWindow.h"
#include "XcaWarning.h"
#include "XcaDialog.h"
#include "XcaApplication.h"
#include "ExportDialog.h"
#include "ImportMulti.h"
#include "AutomationId.h"
#include "XcaPresentationGui.h"
#include "lib/load_obj.h"
#include "lib/pass_info.h"
#include "lib/PwDialogCore.h"
#include "lib/audit.h"
#include "lib/importexport.h"

#include "ui_ItemProperties.h"

XcaTreeView::XcaTreeView(QWidget *parent)
	:QTreeView(parent)
{
	setHeader(new XcaHeaderView());
	setAlternatingRowColors(true);
	setSelectionMode(QAbstractItemView::ExtendedSelection);
	setEditTriggers(QAbstractItemView::EditKeyPressed);
	setRootIsDecorated(false);
	setUniformRowHeights(true);
	setDragEnabled(true);
	//setAnimated(true);

	proxy = new XcaProxyModel(this);
	proxy->setDynamicSortFilter(true);
	sortByColumn(0, Qt::AscendingOrder);
	connect(header(), SIGNAL(sectionHandleDoubleClicked(int)),
		this, SLOT(resizeColumnToContents(int)));
	connect(this, SIGNAL(doubleClicked(const QModelIndex &)),
		this, SLOT(doubleClick(const QModelIndex &)));
	header()->setSectionsClickable(true);
	throttle.setSingleShot(true);
	connect(&throttle, SIGNAL(timeout()), this, SLOT(columnsResize()));
	connect(&throttle, SIGNAL(timeout()), proxy, SLOT(invalidate()));
	setFocusPolicy(Qt::StrongFocus);
	setExpandsOnDoubleClick(false);
}

XcaTreeView::~XcaTreeView()
{
	delete proxy;
}

void XcaTreeView::contextMenuEvent(QContextMenuEvent * e)
{
	QModelIndex index;
	if (!basemodel)
		return;
	index = indexAt(e->pos());
	showContextMenu(e, getIndex(index));
}

void XcaTreeView::showHideSections()
{
	if (!basemodel)
		return;
	int i, max = basemodel->columnCount(QModelIndex());
	basemodel->colResizeStart();
	for (i=0; i<max; i++) {
		if (basemodel->columnHidden(i))
			header()->hideSection(i);
		else
			header()->showSection(i);
	}
	basemodel->colResizeEnd();
	columnsResize();
}

void XcaTreeView::setMainwin(MainWindow *mw, QLineEdit *filter)
{
	mainwin = mw;
	connect(filter, SIGNAL(textChanged(const QString &)),
		this, SLOT(setFilter(const QString&)));
}

void XcaTreeView::setModel(QAbstractItemModel *model)
{
	QByteArray ba;

	header()->setStretchLastSection(false);
	setSortingEnabled(false);

	basemodel = dynamic_cast<db_base*>(model);
	proxy->setSourceModel(model);
	QTreeView::setModel(model ? proxy : nullptr);

	if (basemodel) {
		setRootIsDecorated(basemodel->treeViewMode());
		connect(basemodel, SIGNAL(resetHeader()),
			header(), SLOT(resetMoves()));
		connect(basemodel, SIGNAL(resetHeader()),
			this, SLOT(columnsResize()));
		connect(header(), SIGNAL(sectionMoved(int,int,int)),
			this, SLOT(sectionMoved(int,int,int)));
		connect(header(), SIGNAL(sectionResized(int,int,int)),
			basemodel, SLOT(sectionResized(int,int,int)));
		connect(header(), SIGNAL(sortIndicatorChanged(int,Qt::SortOrder)),
			basemodel, SLOT(sortIndicatorChanged(int,Qt::SortOrder)));
		connect(basemodel, SIGNAL(columnsContentChanged()),
			this, SLOT(columnsChanged()));
		connect(selectionModel(), SIGNAL(currentChanged(const QModelIndex &,
										const QModelIndex &)),
			this, SLOT(itemSelectionChanged(const QModelIndex &,
										const QModelIndex &)));

		initHeaderView();
		setSortingEnabled(true);
		header()->setStretchLastSection(true);

	}
	showHideSections();
}

void XcaTreeView::initHeaderView()
{
	QHeaderView *hv = header();
	dbheaderList allHeaders = basemodel->getAllHeaders();
	int max = allHeaders.count();
	basemodel->colResizeStart();
	for (int i=0; i<max; i++) {
		dbheader *hd = allHeaders[i];
		hv->setSectionHidden(i, !hd->show);
		if (hd->size != -1)
			hv->resizeSection(i, hd->size);
		if (hd->sortIndicator != -1) {
			hv->setSortIndicator(i, hd->sortIndicator ?
				Qt::DescendingOrder : Qt::AscendingOrder);
		}
	}
	for (int i=0; i<max; i++) {
		if (allHeaders[i]->visualIndex == -1)
			continue;
		if (hv->visualIndex(i) != allHeaders[i]->visualIndex) {
			hv->moveSection(hv->visualIndex(i),
					allHeaders[i]->visualIndex);
		}
	}
	basemodel->colResizeEnd();
}

void XcaTreeView::headerEvent(QContextMenuEvent *e, int col)
{
	contextMenu(e, NULL, col);
}

QModelIndex XcaTreeView::getIndex(const QModelIndex &index)
{
	return proxy->mapToSource(index);
}

QModelIndex XcaTreeView::getProxyIndex(const QModelIndex &index)
{
	return proxy->mapFromSource(index);
}

void XcaTreeView::itemSelectionChanged(const QModelIndex &m, const QModelIndex &)
{
	QModelIndex index = getIndex(m);
	QVariant v;
	qDebug() << "selectionChanged()" << index.isValid() << index.row() << index.column();
	if (m.isValid()) {
		pki_base *pki = db_base::fromIndex(index);
		if (pki)
			v = pki->getSqlItemId();
	}
	if (basemodel)
		basemodel->setSelected(v);
}

QList<pki_base *> XcaTreeView::items(const QModelIndexList &indexes)
{
	QList<pki_base *> list;
	foreach(const QModelIndex &idx, indexes) {
		pki_base *pki = db_base::fromIndex(idx);
		if (idx.column() == 0 && pki)
			list << pki;
	}
	return list;
}

QModelIndexList XcaTreeView::getSelectedIndexes()
{
	QModelIndexList list;
	QItemSelection indexes = selectionModel()->selection();
	list = proxy->mapSelectionToSource(indexes).indexes();

	/* Reduce list to column 0 items */
	QModelIndexList::iterator it = list.begin();
	while (it != list.end()) {
		if ((*it).column() != 0)
			it = list.erase(it);
		else
			++it;
	}
	return list;
}

void XcaTreeView::columnsChanged()
{
	throttle.start(200);
}

void XcaTreeView::columnsResize()
{
	int cnt, i;
	if (!basemodel)
		return;
	cnt = basemodel->columnCount(QModelIndex());
	basemodel->colResizeStart();
	for (i=0; i<cnt; i++) {
		if (!basemodel->fixedHeaderSize(i)) {
			resizeColumnToContents(i);
		}
	}
	basemodel->colResizeEnd();
}

void XcaTreeView::sectionMoved(int, int, int)
{
	int cnt = header()->count();
	for (int i=0; i<cnt; i++) {
		basemodel->setVisualIndex(i, header()->visualIndex(i));
	}
}

QModelIndex XcaTreeView::currentIndex()
{
	QModelIndex idx = QTreeView::currentIndex();
	idx = getIndex(idx);
	idx = basemodel->index(idx.row(), 0, idx.parent());
	if (!idx.isValid()) {
		QModelIndexList l = getSelectedIndexes();
		if (l.size() > 0)
			idx = l[0];
	}
	return idx;
}

void XcaTreeView::editIdx()
{
	edit(getProxyIndex(currentIndex()));
}

void XcaTreeView::setFilter(const QString &pattern)
{
	pki_base::limitPattern = QRegularExpression(pattern,
			QRegularExpression::CaseInsensitiveOption);
	// Only to tell the model about the changed filter
	proxy->setFilterFixedString(pattern);
}

/* The question and the deletion on a token stay here, the deletion
 * itself is the service function db_base::deleteItems() (BTD-35) */
void XcaTreeView::deleteItems()
{
	QList<pki_base *> list = items(getSelectedIndexes());
	QStringList names;
	ServiceContext ctx = ServiceContext::localUser(ServiceContext::gui);

	if (list.isEmpty() || !basemodel)
		return;

	foreach(pki_base *pki, list)
		names << pki->getIntName();

	if (!xcaWarning::confirmOkCancel(ctx, "item.delete",
			list.last()->getMsg(pki_base::msg_delete,
			names.size()).arg(names.join("', '"))))
		return;

	foreach(pki_base *pki, list) {
		try {
			pki->deleteFromToken();
		} catch (errorEx &err) {
			XCA_ERROR(err);
		}
	}
	try {
		basemodel->deleteItems(ctx, list);
	} catch (errorEx &err) {
		XCA_ERROR(err);
	}
}

void XcaTreeView::exportItems()
{
	exportItems(getSelectedIndexes());
}

void XcaTreeView::showItems()
{
	QModelIndexList indexes = getSelectedIndexes();
	foreach(QModelIndex index, indexes)
		showItem(index);
}

void XcaTreeView::load_default(load_base *load)
{
	QString s;
	QStringList slist = QFileDialog::getOpenFileNames(NULL, load->caption,
				Settings["workingdir"], load->filter);

	if (!slist.count())
		return;

	update_workingdir(slist[0]);

	ImportMulti *dlgi = new ImportMulti(NULL);
	foreach(s, slist) {
		pki_base *item = NULL;
		try {
			item = load->loadItem(s);
			dlgi->addItem(item);
		}
		catch (errorEx &err) {
			XCA_ERROR(err);
			delete item;
		}
	}
	dlgi->execute();
	delete dlgi;
}

void XcaTreeView::doubleClick(const QModelIndex &m)
{
	showItem(getIndex(m));
}

void XcaTreeView::editComment()
{
	pki_base *item = db_base::fromIndex(currentIndex());
	if (!basemodel || !item)
		return;

	QWidget *w = new QWidget(nullptr);
	Ui::ItemProperties *prop = new Ui::ItemProperties();
	prop->setupUi(w);
	prop->comment->setPlainText(item->getComment());
	prop->name->setText(item->getIntName());
	prop->source->setText(item->pki_source_name());
	prop->insertionDate->setText(item->getInsertionDate().toPretty());
	XcaDialog *d = new XcaDialog(this, item->getType(), w,
		tr("Item properties"), QString(), "itemproperties");
	if (d->exec()) try {
		basemodel->updateProperties(
			ServiceContext::localUser(ServiceContext::gui), item,
			prop->name->text(), prop->comment->toPlainText());
	} catch (errorEx &err) {
		XCA_ERROR(err);
	}
	delete d;
}

void XcaTreeView::pem2clipboard()
{
	if (basemodel) try {
		ExportSpec spec;
		spec.clipboard = true;
		spec.items = items(getSelectedIndexes());
		QString msg = QString::fromUtf8(basemodel->exportItems(
			ServiceContext::localUser(ServiceContext::gui), spec));
		QClipboard *cb = QApplication::clipboard();

		if (cb->supportsSelection())
			cb->setText(msg, QClipboard::Selection);
		cb->setText(msg);
	} catch (errorEx &err) {
		XCA_ERROR(err);
	}
}

void XcaTreeView::headerDetails()
{
	if (curr_hd && curr_hd->id > 0 && mainwin)
		mainwin->getResolver()->searchOid(QString::number(curr_hd->id));
}

void XcaTreeView::columnRemove(void)
{
	QAction *a = headerActions.value(curr_hd);
	if (a)
		a->setChecked(false);
}

void XcaTreeView::showItem(const QModelIndex &index)
{
	pki_base *pki = db_base::fromIndex(index);
	showItem(pki);
}

void XcaTreeView::showItem(const QString &name)
{
	pki_base *pki = Store.lookupPki<pki_base>(name.toULongLong());
	showItem(pki);
}

void XcaTreeView::showItem(pki_base *pki)
{
	if (pki && pki->isVisible() == 1)
		showPki(pki);
}

QString XcaTreeView::ctxId(const QString &action) const
{
	QString id = "ctx_" + objectName().remove(QRegularExpression("View$"));
	return action.isEmpty() ? id : id + "_" + action;
}

/* Automation ID of a column entry: col_<OpenSSL short name> for the
 * subject and extension columns, a fixed name for the others */
static QString columnId(const dbheader *hd)
{
	static const QMap<int, QString> names {
		{ HD_internal_name, "internalName" },
		{ HD_subject_name, "subject" },
		{ HD_subject_hash, "subjectHash" },
		{ HD_x509key_name, "keyName" },
		{ HD_counter, "counter" },
		{ HD_x509_sigalg, "signatureAlgorithm" },
		{ HD_creation, "creation" },
		{ HD_comment, "comment" },
		{ HD_source, "source" },
		{ HD_primary_key, "primaryKey" },
		{ HD_cert_serial, "serial" },
		{ HD_cert_notBefore, "notBefore" },
		{ HD_cert_notAfter, "notAfter" },
		{ HD_cert_revocation, "revocation" },
		{ HD_cert_ca, "ca" },
		{ HD_cert_md5fp, "md5Fingerprint" },
		{ HD_cert_sha1fp, "sha1Fingerprint" },
		{ HD_cert_sha256fp, "sha256Fingerprint" },
		{ HD_cert_crl_expire, "crlExpiration" },
		{ HD_req_signed, "signed" },
		{ HD_req_unstr_name, "unstructuredName" },
		{ HD_req_chall_pass, "challengePassword" },
		{ HD_req_certs, "certificateCount" },
		{ HD_crl_signer, "signer" },
		{ HD_crl_revoked, "revoked" },
		{ HD_crl_lastUpdate, "lastUpdate" },
		{ HD_crl_nextUpdate, "nextUpdate" },
		{ HD_crl_crlnumber, "crlNumber" },
		{ HD_key_type, "keyType" },
		{ HD_key_size, "keySize" },
		{ HD_key_use, "keyUse" },
		{ HD_key_passwd, "keyPassword" },
		{ HD_key_curve, "keyCurve" },
	};
	if (hd->id > 0)
		return "col_" + AutomationId::sanitize(OBJ_nid2sn(hd->id));
	return "col_" + names.value(hd->id, QString("id%1").arg(-hd->id));
}

static void addSubmenu(tipMenu *menu, tipMenu *sub)
{
	if (sub->isEmpty())
		delete sub;
	else
		menu->addMenu(sub);
}

void XcaTreeView::contextMenu(QContextMenuEvent *e, QMenu *parent, int col)
{
	int shown = 0;
	tipMenu *menu, *dn, *v3ext, *current, *v3ns, *keyprop;
	QAction *a;
	dbheader *hd;
	dbheaderList allHeaders = basemodel->getAllHeaders();

	menu = new tipMenu(QString(), mainwin);
	dn = new tipMenu(tr("Subject entries"), mainwin);
	v3ext = new tipMenu(tr("X509v3 Extensions"), mainwin);
	v3ns = new tipMenu(tr("Netscape extensions"), mainwin);
	keyprop = new tipMenu(tr("Key properties"), mainwin);
	setAutomationId(menu, ctxId("columns"));
	setAutomationId(dn, ctxId("columns_subject"));
	setAutomationId(v3ext, ctxId("columns_v3ext"));
	setAutomationId(v3ns, ctxId("columns_netscape"));
	setAutomationId(keyprop, ctxId("columns_key"));
	setAutomationId(menu->addAction(tr("Reset"), basemodel,
			SLOT(columnResetDefaults())), ctxId("columns_reset"));
	if (col >= 0 && col < allHeaders.size()) {
		curr_hd = allHeaders[col];
		setAutomationId(menu->addAction(tr("Hide Column"), this,
				SLOT(columnRemove())), ctxId("columns_hide"));
		if (curr_hd->id > 0)
			setAutomationId(menu->addAction(tr("Details"), this,
						SLOT(headerDetails())),
					ctxId("columns_details"));
	}
	menu->addSeparator();
	foreach(hd, allHeaders) {
		switch (hd->type) {
			case dbheader::hd_x509name:
				current = dn;
				break;
			case dbheader::hd_v3ext:
				current = v3ext;
				break;
			case dbheader::hd_v3ext_ns:
				if (Settings["disable_netscape"])
					continue;
				current = v3ns;
				break;
			case dbheader::hd_key:
				current = keyprop;
				break;
			default:
				current = menu;
				break;
		}
		a = current->addAction(hd->getName());
		a->setObjectName(columnId(hd));
		a->setCheckable(true);
		a->setChecked(hd->show);
		a->setToolTip(hd->getTooltip());
		headerActions[hd] = a;
	}

	menu->addSeparator();

	addSubmenu(menu, dn);
	addSubmenu(v3ext, v3ns);
	addSubmenu(menu, v3ext);
	addSubmenu(menu, keyprop);


	if (parent) {
		parent->addSeparator();
		parent->addMenu(menu)->setText(tr("Columns"));
		parent->exec(e->globalPos());
	} else {
		menu->exec(e->globalPos());
	}
	foreach(hd, allHeaders) {
		a = headerActions.value(hd);
		if (a)
			hd->show = a->isChecked();
		shown += hd->show ? 1 : 0;
	}
	headerActions.clear();
	if (!shown)
		allHeaders[0]->show = true;
	delete menu;
	delete parent;
	showHideSections();
}

void XcaTreeView::changeView()
{
	if (!basemodel)
		return;
	hide();
	basemodel->changeView();
	show();
}

void XcaTreeView::exportItems(const QModelIndexList &indexes)
{
	if (!basemodel || indexes.empty())
		return;

	ExportDialog *dlg = exportDialog(indexes);
	if (dlg && dlg->exec()) {
		ServiceContext ctx = ServiceContext::localUser(ServiceContext::gui);
		try {
			ExportSpec spec = dlg->exportSpec(items(indexes));
			QString fname = spec.fileName;
			const pki_export *xport = spec.format;

			if (dlg->separateFiles->isChecked()) {
				Passwd pass;
				if (xport->match_all(F_CRYPT) && dlg->samePassword->isChecked())
				{
					// Plural form not required for < 2 items
					// Will only be called for 2 or more items
					pass_info p(tr("Export Password"),
							tr("Please enter the password to encrypt all %n "
							   "exported private key(s) in:\n%1",
							   "Singular form for 0 or 1 item can be ignored. Will always be called with n >= 2",
									indexes.size()).arg(fname));

					// Ask for an encryption password once
					if (PwDialogCore::execute(&p, &pass, true) != 1)
						return;
				}
				try {
					for (pki_base *pki : spec.items) {
						ExportSpec one = spec;
						one.items = QList<pki_base *>() << pki;
						/* the ML-DSA encoding only for an
						 * ML-DSA private key (BTD-190) */
						if (!ExportDialog::mlDsaApplies(
								one.items, xport))
							one.privateKeyFormat.clear();
						one.fileName = pki->get_dump_filename(fname,
							QString(".%1").arg(xport->extension));
						// Will be cleared by PwDialogCore
						PwDialogCore::cmdline_passwd = pass;
						basemodel->exportItems(ctx, one);
					}
				} catch (...) {
					PwDialogCore::cmdline_passwd.cleanse();
					throw;
				}
				PwDialogCore::cmdline_passwd.cleanse();
			} else {
				basemodel->exportItems(ctx, spec);
			}
		} catch (serviceError &err) {
			/* the password dialog was cancelled: nothing to say */
			if (err.code != "cancelled")
				XCA_ERROR(err);
		} catch (errorEx &err) {
			XCA_ERROR(err);
		}
	}
	delete dlg;
}

ExportDialog *XcaTreeView::exportDialog(const QModelIndexList &)
{
	return nullptr;
}

void XcaTreeView::showContextMenu(QContextMenuEvent *e,
		const QModelIndex &idx)
{
	QMenu *menu = new QMenu(mainwin);
	QMenu *subExport = NULL;
	QModelIndexList indexes = getSelectedIndexes();
	QModelIndex index;

	menu->setObjectName(ctxId());
	index = idx.isValid() ? idx : currentIndex();
	setAutomationId(menu->addAction(tr("New"), this, SLOT(newItem())),
			ctxId("new"));
	setAutomationId(menu->addAction(tr("Import"), this, SLOT(load())),
			ctxId("import"));
	setAutomationId(menu->addAction(tr("Paste PEM data"), mainwin,
			SLOT(pastePem())), ctxId("pastePem"))->
			setShortcut(QKeySequence::Paste);

	if (indexes.size() == 1) {
		setAutomationId(menu->addAction(tr("Rename"), this,
				SLOT(editIdx())), ctxId("rename"));
		setAutomationId(menu->addAction(tr("Properties"), this,
				SLOT(editComment())), ctxId("properties"));
	}
	if (indexes.size() > 0) {
		setAutomationId(menu->addAction(tr("Delete"), this,
				SLOT(deleteItems())), ctxId("delete"))->
				setShortcut(QKeySequence::Delete);
		subExport = setAutomationId(menu->addMenu(tr("Export")),
				ctxId("export"));
		const pki_export *xport = pki_export::by_id(Settings[ClipboardSettings]);
		QString clipboard = tr("Clipboard");
		if (xport)
			clipboard = QString("%1 (%2)").arg(clipboard).arg(xport->desc);

		setAutomationId(subExport->addAction(clipboard, this,
				SLOT(pem2clipboard())), ctxId("export_clipboard"))->
				setShortcut(QKeySequence::Copy);
		setAutomationId(subExport->addAction(tr("File"), this,
				SLOT(exportItems())), ctxId("export_file"))->
				setShortcut(QKeySequence::Save);
	}

	clipboardFormatMenu(menu);

	fillContextMenu(menu, subExport, index, indexes);

	contextMenu(e, menu, -1);
}

void XcaTreeView::keyPressEvent(QKeyEvent *event)
{
	switch (event->key()) {
		case Qt::Key_Backspace:
		case Qt::Key_Delete:
			deleteItems();
			return;
		case Qt::Key_Enter:
		case Qt::Key_Return:
			if (state() != QAbstractItemView::EditingState)
				showItems();
			return;
		case Qt::Key_F2:
			editIdx();
			return;
		case Qt::Key_Escape:
			clearSelection();
			return;
	}
	if (event->matches(QKeySequence::Save)) {
		exportItems();
		return;
	}
	if (event->matches(QKeySequence::Copy)) {
		pem2clipboard();
		return;
	}
	QTreeView::keyPressEvent(event);
}

void XcaTreeView::changeEvent(QEvent *event)
{
    switch (event->type()) {
		case QEvent::StyleChange:
		case QEvent::PaletteChange:
			qDebug() << "Style change event" << event->type();
			XcaPresentationGui::setupColors(palette());
			break;
		default:
			break;
	}
    QTreeView::changeEvent(event);
}

void XcaTreeView::clipboardFormatMenu(QMenu *menu)
{
	if (!ClipboardSettings || !ClipboardPki_type)
		return;
	int exp_type = Settings[ClipboardSettings];

	QActionGroup *group = new QActionGroup(menu);
	QMenu *clipboard = menu->addMenu(tr("Clipboard format"));
	setAutomationId(clipboard, ctxId("clipboardFormat"));
	foreach(const pki_export *x, pki_export::select(ClipboardPki_type, 0)) {
		if (!(x->flags & F_CLIPBOARD))
			continue;
		QAction *a = clipboard->addAction(x->desc);
		a->setObjectName(ctxId(QString("clipboardFormat_%1").arg(x->id)));
		a->setData(x->id);
		a->setCheckable(true);
		a->setChecked(exp_type == x->id);
		group->addAction(a);
	}

	connect(group, SIGNAL(triggered(QAction*)),
		this, SLOT(clipboardFormat(QAction*)));
}

void XcaTreeView::clipboardFormat(QAction *a)
{
	if (ClipboardSettings)
		Settings[ClipboardSettings] = a->data().toInt();
}
