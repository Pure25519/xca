/* vi: set sw=4 ts=4:
 *
 * A read-only database in the GUI (BTD-214): the status bar says so,
 * the actions that write are disabled and the reading ones stay. The
 * write probe itself is tested by test_cli_readonly_open on a read-only
 * file; here the flag it sets is given directly, since testxca runs as
 * root, for whom no file is read-only.
 */

#include <QAction>
#include <QLabel>
#include <QMenu>
#include <QPushButton>

#include "widgets/MainWindow.h"
#include "lib/database_model.h"

#include "main.h"

static bool enabled(MainWindow *mainwin, const QString &name)
{
	QWidget *w = mainwin->findChild<QWidget *>(name);
	if (w)
		return w->isEnabled();
	QAction *a = mainwin->findChild<QAction *>(name);
	return a && a->isEnabled();
}

void test_main::readOnlyDatabaseActions()
{
	const QStringList writing { "BNnewKey", "BNimportKey", "BNdeleteKey",
		"BNnewCert", "BNimportPKCS12", "BNdeleteCert", "BNnewReq",
		"BNnewCrl", "BNnewTemp", "BNchangeTemp", "menu_import",
		"act_extra_changeDbPassword", "act_file_options" };
	const QStringList reading { "BNexportKey", "BNexportCert",
		"BNdetailsCert", "BNexportCrl", "act_extra_exportIndex" };
	/* a failed QVERIFY returns at once: the flag must not stay set */
	struct resetFlag {
		~resetFlag() { database_model::read_only = false; }
	} reset;
	try {
		openDB();
		QLabel *status = mainwin->findChild<QLabel *>("dlg_main_dbStatus");
		QVERIFY(status);
		for (const QString &n : writing + reading)
			QVERIFY2(enabled(mainwin, n), CCHAR(n));
		QVERIFY(!status->text().contains("read-only"));

		database_model::read_only = true;
		mainwin->setup_open_database();
		for (const QString &n : writing)
			QVERIFY2(!enabled(mainwin, n), CCHAR(n));
		for (const QString &n : reading)
			QVERIFY2(enabled(mainwin, n), CCHAR(n));
		QVERIFY2(status->text().contains("(read-only)"),
			CCHAR(status->text()));

		/* the next writable database has every action again */
		database_model::read_only = false;
		mainwin->setup_open_database();
		for (const QString &n : writing)
			QVERIFY2(enabled(mainwin, n), CCHAR(n));
		QVERIFY(!status->text().contains("read-only"));
	} catch (errorEx &err) {
		QVERIFY2(false, CCHAR(err.getString()));
	}
}
