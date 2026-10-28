/* vi: set sw=4 ts=4:
 *
 * Automation IDs (BTD-61): every menu entry, context menu entry and
 * code-created widget has a well-formed, unique objectName.
 * Scheme: doc/automation-ids.md
 */

#include <QTest>
#include <QTimer>
#include <QMenuBar>
#include <QLineEdit>
#include <QLabel>
#include <QDialogButtonBox>
#include <QPushButton>
#include <QContextMenuEvent>
#include <QRegularExpression>

#include "widgets/MainWindow.h"
#include "ui_MainWindow.h"
#include "widgets/ImportMulti.h"
#include "widgets/NewKey.h"
#include "widgets/NewX509.h"
#include "ui_NewX509.h"
#include "widgets/XcaWarning.h"
#include "widgets/distname.h"

#include "lib/audit.h"
#include "lib/pki_multi.h"
#include "lib/pki_x509.h"
#include "lib/database_model.h"
#include "lib/db_crl.h"
#include "lib/pki_crl.h"

#include "main.h"

static const QRegularExpression idPattern(
	"^(menu|act|ctx|col|btn|dlg|dn|dnLabel|fp|fpLabel|attr|attrLabel)"
	"(_[A-Za-z0-9]+)+$");

static const char automationCsr[] = R"PEM(
-----BEGIN CERTIFICATE REQUEST-----
MIHYMH8CAQAwHTEbMBkGA1UEAwwSQXV0b21hdGlvbiByZXF1ZXN0MFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAEHuP1CRuf29dvvOiiCOlzEjVfLQFLJyK8WbT4UGYt
uKBPOX734pfft1b3CRFhD0DNMkDrkPuANVvY+WXwwBT+0qAAMAoGCCqGSM49BAMC
A0kAMEYCIQCgOwbajVCcoqJqL3WPt2wITSjnog4ZqbJ0bFuFtUtH4wIhAOdtZTTS
r8Xp3n3DkFdkpm3CZilyGio3Fuqs+tWtoLtb
-----END CERTIFICATE REQUEST-----
)PEM";

static QMenu *subMenu(QAction *a)
{
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
	return QMenu::menuInAction(a);
#else
	return a->menu();
#endif
}

static void checkId(const QString &where, const QString &id,
			QStringList &ids, QStringList &errors)
{
	if (!idPattern.match(id).hasMatch())
		errors << QString("%1: malformed ID '%2'").arg(where, id);
	else if (ids.contains(id))
		errors << QString("%1: duplicate ID '%2'").arg(where, id);
	ids << id;
}

/* IDs of all entries and submenus below menu, recursively */
static void collectMenuIds(QMenu *menu, QStringList &ids, QStringList &errors)
{
	foreach(QAction *a, menu->actions()) {
		if (a->isSeparator())
			continue;
		QMenu *sub = subMenu(a);
		QString where = QString("%1 > '%2'").arg(menu->objectName())
						.arg(a->text());
		checkId(where, sub ? sub->objectName() : a->objectName(),
			ids, errors);
		/* The accessibility tree shows a submenu as its menuAction() */
		if (sub && a->objectName() != sub->objectName())
			errors << QString("%1: menu action ID '%2', menu ID '%3'")
				.arg(where, a->objectName(), sub->objectName());
		if (sub)
			collectMenuIds(sub, ids, errors);
	}
}

/* Sends a context menu event to w, collects the IDs of the popup that
 * opens and closes it again. Returns the ID of the popup itself. */
static QString popupIds(QWidget *w, const QPoint &pos, QStringList &ids,
			QStringList &errors)
{
	QString top;
	QStringList found;
	QTimer timer;

	timer.setInterval(20);
	QObject::connect(&timer, &QTimer::timeout, [&]() {
		QMenu *m = qobject_cast<QMenu*>(QApplication::activePopupWidget());
		if (!m)
			return;
		timer.stop();
		top = m->objectName();
		collectMenuIds(m, found, errors);
		m->close();
	});
	timer.start();
	QContextMenuEvent ev(QContextMenuEvent::Mouse, pos, w->mapToGlobal(pos));
	QApplication::sendEvent(w, &ev);
	timer.stop();

	if (top.isEmpty())
		errors << QString("%1: no named context menu opened")
				.arg(w->parentWidget()->objectName());
	ids << found;
	return top;
}

static QModelIndexList allRows(QAbstractItemModel *m,
				const QModelIndex &parent = QModelIndex())
{
	QModelIndexList list;
	for (int r = 0; r < m->rowCount(parent); r++) {
		QModelIndex idx = m->index(r, 0, parent);
		list << idx << allRows(m, idx);
	}
	return list;
}

/* Opens the context menu of every row alone, of all rows together, of
 * the empty area and of the header; returns all IDs seen */
static QStringList contextMenuIds(XcaTreeView *v, QStringList &errors)
{
	QStringList ids;
	QString prefix = "ctx_" + v->objectName().remove("View");

	for (int i = 0; i < mainwin->tabView->count(); i++)
		if (mainwin->tabView->widget(i)->isAncestorOf(v))
			mainwin->tabView->setCurrentIndex(i);
	v->expandAll();
	QApplication::processEvents();

	/* Persistent: each context menu runs an event loop, in which the
	 * view's throttle timer may invalidate the proxy model (BTD-83) */
	QList<QPersistentModelIndex> rows;
	foreach(QModelIndex idx, allRows(v->model()))
		rows << idx;
	if (rows.isEmpty())
		errors << QString("%1: no items to open a context menu for")
				.arg(v->objectName());

	foreach(QPersistentModelIndex idx, rows) {
		v->selectionModel()->setCurrentIndex(idx,
			QItemSelectionModel::ClearAndSelect |
			QItemSelectionModel::Rows);
		QString top = popupIds(v->viewport(),
				v->visualRect(idx).center(), ids, errors);
		if (top != prefix)
			errors << QString("context menu ID '%1', expected '%2'")
					.arg(top, prefix);
	}
	if (rows.size() > 1) {
		v->selectAll();
		popupIds(v->viewport(), v->visualRect(rows[0]).center(),
			ids, errors);
	}

	v->clearSelection();
	v->selectionModel()->clearCurrentIndex();
	QWidget *vp = v->viewport();
	popupIds(vp, QPoint(vp->width() - 2, vp->height() - 2), ids, errors);

	QHeaderView *hv = v->header();
	QString top = popupIds(hv->viewport(),
		QPoint(hv->sectionViewportPosition(hv->logicalIndex(0)) + 2,
		       hv->height() / 2), ids, errors);
	if (top != prefix + "_columns")
		errors << QString("header menu ID '%1', expected '%2_columns'")
				.arg(top, prefix);
	return ids;
}

/* Every standard button of every button box below w is btn_<name> */
static void checkButtons(QWidget *w, QStringList &errors)
{
	foreach(QDialogButtonBox *box, w->findChildren<QDialogButtonBox*>()) {
		QStringList ids;
		foreach(QAbstractButton *b, box->buttons()) {
			if (box->standardButton(b) == QDialogButtonBox::NoButton)
				continue;
			checkId(w->objectName() + " > '" + b->text() + "'",
				b->objectName(), ids, errors);
			if (!b->objectName().startsWith("btn_"))
				errors << QString("%1: button ID '%2'")
					.arg(w->objectName(), b->objectName());
		}
	}
}

static void expectIds(const QString &where, const QStringList &ids,
			const QStringList &expected, QStringList &errors)
{
	foreach(QString id, expected)
		if (!ids.contains(id))
			errors << QString("%1: ID '%2' missing").arg(where, id);
}

void test_main::automationIds()
{
	QStringList errors, ids;

	try {
	ign_openssl_error();
	openDB();

	/* One item of every type: keys, certificates (root CA, intermediate
	 * CA with key, end entity), a request and a template */
	pki_multi *pem = new pki_multi();
	foreach(QString name, QStringList({ "Root CA", "Inter CA 1",
			"Endentity", "Inter CA 1 Key", "Root CA Key",
			"XCA Template", "CA CRL Test" }))
		pem->fromPEMbyteArray(pemdata[name].toUtf8(), QString());
	pem->fromPEMbyteArray(QByteArray(automationCsr), QString());
	ImportMulti *dlg = new ImportMulti(mainwin);
	dlg->addItem(pem);
	dlg->show();
	Q_ASSERT(QTest::qWaitForWindowActive(dlg));
	dlg->on_butOk_clicked();
	delete dlg;

	/* A CRL, issued by a CA with private key */
	pki_x509 *ca = nullptr;
	foreach(pki_x509 *c, Store.getAll<pki_x509>())
		if (c->canSign())
			ca = c;
	QVERIFY(ca);
	QVERIFY(Database.model<db_crl>()->newCrl(
		ServiceContext::localUser(ServiceContext::gui), crljob(ca)));

	/* Menu bar */
	QCOMPARE(mainwin->menuBar()->objectName(), QString("menu_bar"));
	foreach(QAction *a, mainwin->menuBar()->actions()) {
		QMenu *m = subMenu(a);
		if (!m)
			continue;
		checkId("menu bar > '" + a->text() + "'", m->objectName(),
			ids, errors);
		if (a->objectName() != m->objectName())
			errors << QString("menu bar > '%1': menu action ID '%2'")
				.arg(a->text(), a->objectName());
		collectMenuIds(m, ids, errors);
	}
	expectIds("menu bar", ids, { "menu_file", "act_file_newDatabase",
		"menu_language", "act_lang_system", "act_import_pastePem",
		"act_token_manage", "act_extra_oidResolver",
		"act_help_about" }, errors);
	qDebug() << "Menu bar IDs:" << ids.size();

	/* Context menus of the tree views */
	struct {
		XcaTreeView *view;
		QStringList expected;
	} views[] = {
		{ mainwin->keyView, { "ctx_key_new", "ctx_key_delete",
			"ctx_key_export_file", "ctx_key_clipboardFormat",
			"ctx_key_columns", "col_keyType" } },
		{ mainwin->reqView, { "ctx_req_sign", "ctx_req_markSigned",
			"ctx_req_transform_similarRequest", "col_subject",
			"ctx_req_columns_netscape" } },
		{ mainwin->certView, { "ctx_cert_hideUnusable",
			"ctx_cert_ca_generateCrl", "ctx_cert_renewal",
			"ctx_cert_revoke", "ctx_cert_transform_request",
			"ctx_cert_columns_v3ext", "col_subjectAltName",
			"col_notAfter" } },
		{ mainwin->tempView, { "ctx_temp_createCertificate",
			"ctx_temp_duplicate" } },
		{ mainwin->crlView, { "ctx_crl_rename",
			"ctx_crl_export_clipboard", "col_signer" } },
	};
	for (auto &v : views) {
		QStringList ctx = contextMenuIds(v.view, errors);
		expectIds(v.view->objectName(), ctx, v.expected, errors);
		ctx.removeDuplicates();
		qDebug() << v.view->objectName() << "context menu IDs:" << ctx;
	}

	/* Widgets without a label have an accessible name */
	foreach(XcaTreeView *v, mainwin->findChildren<XcaTreeView*>())
		if (v->accessibleName().isEmpty())
			errors << v->objectName() + ": no accessible name";
	QLineEdit *search = mainwin->findChild<QLineEdit*>("dlg_main_search");
	if (!search || search->accessibleName().isEmpty())
		errors << "dlg_main_search missing or without accessible name";
	if (!mainwin->findChild<QLabel*>("dlg_main_dbStatus"))
		errors << "dlg_main_dbStatus missing";

	/* Dialog buttons, named when the dialog is shown */
	NewKey *nk = new NewKey(mainwin, "automation");
	nk->show();
	Q_ASSERT(QTest::qWaitForWindowActive(nk));
	checkButtons(nk, errors);
	if (!nk->findChild<QPushButton*>("btn_ok"))
		errors << "NewKey: btn_ok missing";
	delete nk;

	xcaWarningBox *box = new xcaWarningBox(mainwin, "automation");
	box->addButton(QMessageBox::Apply, "Copy");
	box->addButton(QMessageBox::Ok);
	box->show();
	QCOMPARE(box->objectName(), QString("dlg_warning"));
	checkButtons(box, errors);
	if (!box->findChild<QPushButton*>("btn_apply"))
		errors << "dlg_warning: btn_apply missing";
	delete box;

	/* Subject fields created in code, with the label text as name */
	NewX509 *nx = new NewX509(mainwin);
	nx->show();
	QStringList dnIds;
	foreach(QLineEdit *e, nx->findChildren<QLineEdit*>(
			QRegularExpression("^dlg_newX509_"))) {
		checkId("NewX509", e->objectName(), dnIds, errors);
		if (e->accessibleName().isEmpty())
			errors << e->objectName() + ": no accessible name";
	}
	expectIds("NewX509", dnIds, { "dlg_newX509_dn_CN", "dlg_newX509_dn_O",
		"dlg_newX509_attr_challengePassword" }, errors);
	checkButtons(nx, errors);
	delete nx;

	/* Distinguished name display */
	DistName dn(nullptr);
	dn.setX509name(ca->getSubject());
	QStringList dnLabels;
	foreach(QLabel *l, dn.findChildren<QLabel*>(QRegularExpression("^dn")))
		checkId("DistName", l->objectName(), dnLabels, errors);
	expectIds("DistName", dnLabels, { "dn_CN", "dnLabel_CN" }, errors);
	if (!dn.findChild<QLineEdit*>("dn_rfc2253"))
		errors << "DistName: dn_rfc2253 missing";

	} catch (...) {
		QVERIFY2(false, "Exception thrown");
	}
	QVERIFY2(errors.isEmpty(), CCHAR(errors.join("\n")));
}
