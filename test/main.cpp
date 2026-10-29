/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2023 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QTest>
#include <QFile>

#include <openssl/opensslv.h>
#include <openssl/provider.h>

#include "widgets/MainWindow.h"
#include "widgets/AutomationId.h"
#include "ui_MainWindow.h"

#include "lib/debug_info.h"
#include "lib/entropy.h"
#include "lib/pki_evp.h"

#include "main.h"
#include "TestEnv.h"

static TestEnv *testEnv;

/* Called by QTEST_MAIN before the QApplication: testxca and
 * test_automation_ids run at the same time under ctest --parallel and must
 * not share testdb.xdb, testdata/ or the settings (BTD-83) */
void test_main::initMain()
{
	testEnv = new TestEnv(TestEnv::workInHome);
}

void test_main::initTestCase()
{
	OSSL_PROVIDER_try_load(0, "legacy", 1);

	debug_info::init();

	entropy = new Entropy;

	Settings.clear();
	initOIDs();

	AutomationId::install();
	mainwin = new MainWindow();
	mainwin->show();

	pwdialog = new PwDialogMock();
	PwDialogCore::setGui(pwdialog);

	xcaWarning::setGui(new xcaWarningCore());
}

void test_main::cleanupTestCase()
{
	mainwin->close_database();
	delete entropy;
	delete mainwin;
	pki_export::free_elements();
	QFile::remove("testdb.xdb");
	/* While Qt is still up; after main() its globals are gone */
	delete testEnv;
	testEnv = nullptr;
}

void test_main::cleanup()
{
	mainwin->close_database();
	dbstatus();
	QFile::remove("testdb.xdb");
}

void test_main::openDB()
{
	pwdialog->setExpectations(QList<pw_expect*>{
		new pw_expect("testdbpass", pw_ok),
	});
	mainwin->close_database();
	QFile::remove("testdb.xdb");
	Database.open("testdb.xdb");
	Settings["pkcs12_keep_legacy"] = true;
	mainwin->setup_open_database();
	dbstatus();
}

void test_main::dbstatus()
{
	QList<pki_base*> allitems = Store.getAll<pki_base>();
	QStringList out;
	foreach(pki_base *p, allitems)
		out << QString("%1[%2]").arg(p->getIntName()).arg(p->getTypeString());
	qDebug("%s ALL: %ld %s", Database.isOpen() ? "OPEN" : "CLOSED",
		(long)allitems.size(), out.join(", ").toUtf8().constData());
}

QTEST_MAIN(test_main)
