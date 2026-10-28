/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "MainWindow.h"
#include "XcaApplication.h"
#include "PwDialog.h"
#include "Options.h"
#include "lib/load_obj.h"
#include "lib/pass_info.h"
#include "lib/pkcs11.h"
#include "lib/pki_evp.h"
#include "lib/pki_scard.h"
#include "lib/func.h"
#include "lib/db_x509super.h"
#include "lib/database_model.h"
#include "ui_Options.h"
#include "hashBox.h"
#include "OidResolver.h"
#include "OpenDb.h"
#include "Help.h"
#include "AutomationId.h"
#include <QApplication>
#include <QClipboard>
#include <QMenuBar>
#include <QMessageBox>
#include <QFileDialog>
#include <QActionGroup>

QAction *MainWindow::languageMenuEntry(const QStringList &sl)
{
	QString lang, tooltip;
	QLocale locale;

	if (sl[0].isEmpty()) {
		locale = QLocale::system();
		lang = MainWindow::tr("System");
	} else {
		locale = QLocale(sl[0]);
		lang = QString("%1 (%2)").arg(sl[1])
			.arg(QLocale::languageToString(locale.language()));
	}
	tooltip = locale.nativeLanguageName();

	if (sl.length() > 2)
		tooltip += " - " + sl[2];

	QAction *a = new QAction(lang, this);
	a->setObjectName("act_lang_" + (sl[0].isEmpty() ? QString("system") :
					AutomationId::sanitize(sl[0])));
	a->setToolTip(tooltip);
	a->setData(QVariant(locale));
	a->setDisabled(!XcaApplication::languageAvailable(locale));

	a->setCheckable(true);
	if (locale == QLocale())
		a->setChecked(true);
	return a;
}

void MainWindow::init_menu()
{
	static QMenu *file = NULL, *help = NULL, *import = NULL,
			*token = NULL, *languageMenu = NULL, *extra = NULL;
	static QActionGroup * langGroup = NULL;
	QAction *a, *options;

	delete file;
	delete help;
	delete import;
	delete token;
	delete extra;
	delete languageMenu;
	delete historyMenu;
	delete langGroup;

	wdMenuList.clear();
	scardList.clear();
	acList.clear();
	setMenuBar(setAutomationId(new QMenuBar(nullptr), "menu_bar"));

	langGroup = new QActionGroup(this);

	languageMenu = new tipMenu(tr("Language"), this);
	setAutomationId(languageMenu, "menu_language");
	connect(languageMenu, SIGNAL(triggered(QAction*)),
		qApp, SLOT(switchLanguage(QAction*)));

	foreach(const QStringList &sl, getTranslators()) {
		a = languageMenuEntry(sl);
		langGroup->addAction(a);
		languageMenu->addAction(a);
	}


#ifndef APPSTORE_COMPLIANT
	historyMenu = new tipMenu(tr("Recent DataBases") + " ...", this);
	setAutomationId(historyMenu, "menu_history");
	update_history_menu();

	connect(historyMenu, SIGNAL(triggered(QAction*)),
	        this, SLOT(open_database(QAction*)));

	file = setAutomationId(menuBar()->addMenu(tr("&File")), "menu_file");

	a = file->addAction(tr("New DataBase"), this, SLOT(new_database()));
	a->setObjectName("act_file_newDatabase");
	a->setShortcut(QKeySequence::New);
	a->setEnabled(OpenDb::hasSqLite());

	a = file->addAction(tr("Open DataBase"), this, SLOT(load_database()));
	a->setObjectName("act_file_openDatabase");
	a->setShortcut(QKeySequence::Open);
	a->setEnabled(OpenDb::hasSqLite());

	setAutomationId(file->addAction(tr("Open Remote DataBase"),
			this, SLOT(openRemoteSqlDB())),
			"act_file_openRemoteDatabase")->
			setEnabled(OpenDb::hasRemoteDrivers());
	file->addMenu(historyMenu);
	setAutomationId(file->addAction(tr("Set as default DataBase"), this,
				SLOT(default_database())),
			"act_file_setDefaultDatabase");
	a = file->addAction(tr("Close DataBase"), this, SLOT(close_database()));
	a->setObjectName("act_file_closeDatabase");
	a->setShortcut(QKeySequence::Close);
	acList += a;

#endif
	options = new QAction(tr("Options"), this);
	options->setObjectName("act_file_options");
	connect(options, SIGNAL(triggered()), this, SLOT(setOptions()));
	options->setMenuRole(QAction::PreferencesRole);
#ifndef APPSTORE_COMPLIANT
	file->addAction(options);
#endif
	acList += options;

	a = new QAction(tr("Exit"), this);
	a->setObjectName("act_file_exit");
	connect(a, SIGNAL(triggered()),
		qApp, SLOT(quit()), Qt::QueuedConnection);
	a->setMenuRole(QAction::QuitRole);
	a->setShortcut(QKeySequence::Quit);
#ifndef APPSTORE_COMPLIANT
	file->addMenu(languageMenu);
	file->addSeparator();
	file->addAction(a);
#endif

	import = setAutomationId(menuBar()->addMenu(tr("I&mport")),
				"menu_import");
	setAutomationId(import->addAction(tr("Keys"), keyView, SLOT(load()) ),
			"act_import_keys");
	setAutomationId(import->addAction(tr("Requests"), reqView, SLOT(load()) ),
			"act_import_requests");
	setAutomationId(import->addAction(tr("Certificates"), certView, SLOT(load()) ),
			"act_import_certificates");
	setAutomationId(import->addAction(tr("PKCS#12"), certView, SLOT(loadPKCS12()) ),
			"act_import_pkcs12");
	setAutomationId(import->addAction(tr("PKCS#7"), certView, SLOT(loadPKCS7()) ),
			"act_import_pkcs7");
	setAutomationId(import->addAction(tr("Template"), tempView, SLOT(load()) ),
			"act_import_template");
	setAutomationId(import->addAction(tr("Revocation list"), crlView, SLOT(load())),
			"act_import_crl");
	setAutomationId(import->addAction(tr("PEM file"), this, SLOT(loadPem()) ),
			"act_import_pemFile");
	setAutomationId(import->addAction(tr("Paste PEM file"), this, SLOT(pastePem())),
			"act_import_pastePem")->setShortcut(QKeySequence::Paste);

#ifndef APPSTORE_COMPLIANT
	token = setAutomationId(menuBar()->addMenu(tr("Token")), "menu_token");
	setAutomationId(token->addAction(tr("&Manage Security token"), this,
				SLOT(manageToken())), "act_token_manage");
	setAutomationId(token->addAction(tr("&Init Security token"),  this,
				SLOT(initToken())), "act_token_init");
	setAutomationId(token->addAction(tr("&Change PIN"), this,
				SLOT(changePin()) ), "act_token_changePin");
	setAutomationId(token->addAction(tr("Change &SO PIN"), this,
				SLOT(changeSoPin()) ), "act_token_changeSoPin");
	setAutomationId(token->addAction(tr("Init PIN"), this,
				SLOT(initPin()) ), "act_token_initPin");
#endif
	extra = setAutomationId(menuBar()->addMenu(tr("Extra")), "menu_extra");
	acList += setAutomationId(extra->addAction(tr("&Dump DataBase"), this,
				SLOT(dump_database())), "act_extra_dumpDatabase");
	acList += setAutomationId(extra->addAction(tr("&Export Certificate Index"), this,
				SLOT(exportIndex())), "act_extra_exportIndex");
	acList += setAutomationId(extra->addAction(tr("Export Certificate &Index hierarchy"), this,
				SLOT(exportIndexHierarchy())), "act_extra_exportIndexHierarchy");
	acList += setAutomationId(extra->addAction(tr("C&hange DataBase password"), this,
				SLOT(changeDbPass())), "act_extra_changeDbPassword");

	extra->addSeparator();
	acList += setAutomationId(extra->addAction(tr("Change table font"), this,
				SLOT(changeTableFont())), "act_extra_changeTableFont");
	acList += setAutomationId(extra->addAction(tr("Reset table font"), this,
				SLOT(resetTableFont())), "act_extra_resetTableFont");
	extra->addSeparator();

	setAutomationId(extra->addAction(tr("Generate DH parameter"), this,
				 SLOT(generateDHparam())), "act_extra_generateDhParam");
	setAutomationId(extra->addAction(tr("OID Resolver"), resolver, SLOT(show())),
			"act_extra_oidResolver");

#ifdef APPSTORE_COMPLIANT
	extra->addSeparator();
	extra->addMenu(languageMenu);
	extra->addAction(options);
#endif
	help = setAutomationId(menuBar()->addMenu(tr("&Help") ), "menu_help");
	setAutomationId(help->addAction(tr("Content"), helpdlg, SLOT(content())),
			"act_help_content")->setShortcut(QKeySequence::HelpContents);
	a = new QAction(tr("About"), this);
	a->setObjectName("act_help_about");
	connect(a, SIGNAL(triggered()), this, SLOT(about()));
	a->setMenuRole(QAction::AboutRole);
	a->setShortcut(QKeySequence::WhatsThis);
	help->addAction(a);
	wdMenuList += import;
#ifndef APPSTORE_COMPLIANT
	scardList += token;
#endif

	setItemEnabled(Database.isOpen());
}

void MainWindow::update_history_menu()
{
	QStringList hist = history.get();
	if (!historyMenu)
		return;
	historyMenu->clear();
	for (int i = 0, j = 0; i < hist.size(); i++) {
		QAction *a;
		QString txt = hist[i];
		if (!QFile::exists(txt) && !database_model::isRemoteDB(txt))
			continue;
		if (txt.size() > 33)
			txt = QString("...") + txt.mid(txt.size() - 30);
		a = historyMenu->addAction(QString("%1 %2").arg(j).arg(txt));
		a->setObjectName(QString("act_history_%1").arg(j++));
		a->setData(QVariant(hist[i]));
		a->setToolTip(hist[i]);
	}
}

void MainWindow::open_database(QAction* a)
{
	init_database(a->data().toString());
}

void MainWindow::new_database()
{
	load_db l;
	QString selectedFilter;
	QString fname = QFileDialog::getSaveFileName(this, l.caption, homedir,
			l.filter, &selectedFilter, QFileDialog::DontConfirmOverwrite);
	// make sure that, if the 3 letter extension was left selected
	// in Qt's OS X file open dialog,
	// the filename actually ends with that extension.
	// Otherwise usability breaks in jarring ways.
	init_database(getFullFilename(fname, selectedFilter));
}

void MainWindow::load_database()
{
	load_db l;
	QString fname = QFileDialog::getOpenFileName(this, l.caption, homedir,
			l.filter);
	init_database(fname);
}

void MainWindow::setOptions()
{
	if (!QSqlDatabase::database().isOpen())
		return;

	Options *opt = new Options(this);
	if (opt->exec()) {
		reqView->showHideSections();
		certView->showHideSections();
	}
	delete opt;

	pkcs11::libraries.load(Settings["pkcs11path"]);
	enableTokenMenu(pkcs11::libraries.loaded());
}
