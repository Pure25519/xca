/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2023 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QTest>

#include "widgets/MainWindow.h"
#include "ui_MainWindow.h"
#include "widgets/ImportMulti.h"
#include "ui_ImportMulti.h"

#include "lib/pki_multi.h"
#include "lib/pki_x509.h"

#include <QFileInfo>
#include <QSqlDatabase>
#include <QSqlError>
#include <QSqlQuery>

#include "main.h"

void test_main::importPEM()
{
	try {

	ign_openssl_error();
	openDB();
	dbstatus();
	pki_multi *pem = new pki_multi();

	pem->fromPEMbyteArray(pemdata["Inter CA 1"].toUtf8(), QString());
	pem->fromPEMbyteArray(pemdata["Root CA"].toUtf8(), QString());

	// Enter a wrong password and then abort
	pwdialog->setExpectations(QList<pw_expect*>{
		new pw_expect("wrongPassword", pw_ok),
	});
	QVERIFY_EXCEPTION_THROWN(pem->fromPEMbyteArray(
				pemdata["Inter CA 1 EncKey"].toUtf8(), QString()), errorEx);


	// Enter a wrong password and then the correct one
	pwdialog->setExpectations(QList<pw_expect*>{
		new pw_expect("BadPassword", pw_ok),
		new pw_expect("pass", pw_ok),
	});
	pem->fromPEMbyteArray(pemdata["Inter CA 1 Key"].toUtf8(), QString());

	QCOMPARE(pem->failed_files.count(), 0);
	ImportMulti *dlg = new ImportMulti(mainwin);
	dlg->addItem(pem);

	dlg->show();
	Q_ASSERT(QTest::qWaitForWindowActive(dlg));
	dlg->on_butOk_clicked();

	delete dlg;
	QList<pki_base*> allitems = Store.getAll<pki_base>();
	QCOMPARE(allitems.count() , 3);
	} catch (...) {
		QVERIFY2(false, "Exception thrown");
	}
	dbstatus();
}

/* Rows of the items table, read from the database file by a second
 * connection: only what was committed counts */
static int committedItems(const QString &file)
{
	int count = -1;
	{
		QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE",
							"btd114-count");
		db.setDatabaseName(file);
		if (db.open()) {
			QSqlQuery q("SELECT COUNT(*) FROM items", db);
			if (q.next())
				count = q.value(0).toInt();
		}
		db.close();
	}
	QSqlDatabase::removeDatabase("btd114-count");
	return count;
}

/* The import dialog with the certificates "Root CA", "Inter CA 1" and
 * "Endentity", on a new database */
ImportMulti *test_main::importDialog()
{
	ign_openssl_error();
	openDB();
	ImportMulti *dlg = new ImportMulti(mainwin);
	foreach(const QString &name, QStringList({ "Root CA", "Inter CA 1",
						"Endentity" })) {
		pki_multi *pem = new pki_multi();
		pem->fromPEMbyteArray(pemdata[name].toUtf8(), QString());
		dlg->addItem(pem);
	}
	dlg->show();
	Q_ASSERT(QTest::qWaitForWindowActive(dlg));
	return dlg;
}

/* Another program holds the database: nothing can be stored, and every
 * item stays in the import dialog; once the database is free, the same
 * dialog stores them (BTD-114). Before, the dialog handed the whole
 * selection to one importItems() call, and the failure deleted it. */
void test_main::importLockedKeepsItems()
{
	try {

	ImportMulti *dlg = importDialog();
	QCOMPARE(dlg->entries(), 3);
	QString file = QFileInfo("testdb.xdb").absoluteFilePath();
	QSqlQuery("PRAGMA busy_timeout = 0");
	{
		QSqlDatabase lock = QSqlDatabase::addDatabase("QSQLITE",
							"btd114-lock");
		lock.setDatabaseName(file);
		QVERIFY(lock.open());
		QSqlQuery q(lock);
		QVERIFY2(q.exec("BEGIN EXCLUSIVE"),
			CCHAR(q.lastError().text()));
		dlg->on_butOk_clicked();
		q.exec("ROLLBACK");
		lock.close();
	}
	QSqlDatabase::removeDatabase("btd114-lock");
	QSqlQuery("PRAGMA busy_timeout = 5000");
	QCOMPARE(dlg->entries(), 3);
	QCOMPARE(Store.getAll<pki_x509>().size(), 0);
	QCOMPARE(committedItems(file), 0);

	dlg->on_butOk_clicked();
	QCOMPARE(dlg->entries(), 0);
	QCOMPARE(Store.getAll<pki_x509>().size(), 3);
	QCOMPARE(committedItems(file), 3);
	delete dlg;

	} catch (...) {
		QVERIFY2(false, "Exception thrown");
	}
	dbstatus();
}

/* One item fails while it is written: the others are stored and
 * committed (BTD-114). Before, the failure rolled the whole selection
 * back, and the items stored before it stayed in memory only. The
 * failing item is reported; a SQL error inside the store step deletes
 * it (db_base::insertPKI(), BTD-50), so it leaves the dialog. */
void test_main::importOneFailingItem()
{
	try {

	ImportMulti *dlg = importDialog();
	QString file = QFileInfo("testdb.xdb").absoluteFilePath();
	QSqlQuery trigger;
	QVERIFY2(trigger.exec("CREATE TEMP TRIGGER btd114_refuse BEFORE "
		"INSERT ON items WHEN NEW.name = 'Inter CA 1' BEGIN "
		"SELECT RAISE(ABORT, 'BTD-114 test: insert refused'); END"),
		CCHAR(trigger.lastError().text()));
	dlg->on_butOk_clicked();
	QSqlQuery("DROP TRIGGER temp.btd114_refuse");
	QStringList stored;
	foreach(pki_x509 *cert, Store.getAll<pki_x509>())
		stored << cert->getIntName();
	stored.sort();
	QCOMPARE(stored, QStringList({ "Endentity", "Root CA" }));
	QCOMPARE(committedItems(file), 2);
	delete dlg;

	} catch (...) {
		QVERIFY2(false, "Exception thrown");
	}
	dbstatus();
}
