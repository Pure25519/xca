/* vi: set sw=4 ts=4:
 *
 * The parent of the password dialog (BTD-177): the active window if XCA
 * has one, otherwise the main window. With qApp->activeWindow() alone
 * the dialog had no parent while XCA had no focus (after a slow token
 * call, another application in front, the headless GUI harness): not
 * modal to XCA, not centred on it, possibly behind it.
 */

#include <QApplication>
#include <QDialog>

#include "widgets/MainWindow.h"
#include "ui_PwDialog.h"
#include "widgets/PwDialog.h"
#include "lib/pass_info.h"
#include "lib/XcaWarningCore.h"
#include "lib/func.h"
#include "ui_Help.h"
#include "widgets/Help.h"

#include "main.h"

void test_main::passwordDialogParent()
{
	pass_info pi("Password", "for the dialog parent test");

	/* XCA without focus: no window of it is active (the main window is
	 * hidden for this, as if another application were in front) */
	bool shown = mainwin->isVisible();
	mainwin->hide();
	QTRY_VERIFY_WITH_TIMEOUT(!qApp->activeWindow(), 2000);
	PwDialog unfocused(&pi);
	QWidget *parent = unfocused.parentWidget();
	if (shown)
		mainwin->show();
	QCOMPARE(parent, (QWidget *)mainwin);
	QVERIFY(unfocused.isWindow());

	/* an active window of XCA is the parent */
	QDialog other(mainwin);
	other.show();
	other.activateWindow();
	if (!QTest::qWaitForWindowActive(&other, 2000))
		QSKIP("the platform activates no window");
	PwDialog focused(&pi);
	QCOMPARE(focused.parentWidget(), (QWidget *)&other);
	other.hide();
}

/* BTD-255: a build without the help collection (no sphinx-build in the
 * build image) shows the online manual on Help > Content instead of an
 * empty help window */
class helpInfo : public xcaWarningCore
{
  public:
	QStringList infos{};
	void information(const QString &msg) override
	{
		infos << msg;
	}
};

void test_main::helpWithoutCollection()
{
	if (!getDocDir().isEmpty())
		QSKIP("this build has the help collection");
	helpInfo *w = new helpInfo();
	xcaWarning::setGui(w);
	mainwin->helpdlg->hide();
	mainwin->helpdlg->content();
	QStringList infos = w->infos;
	bool shown = mainwin->helpdlg->isVisible();
	mainwin->helpdlg->hide();
	xcaWarning::setGui(new xcaWarningCore());
	QCOMPARE(infos.size(), 1);
	QVERIFY2(infos[0].contains("hohnstaedt.de/xca"), qPrintable(infos[0]));
	QVERIFY(!shown);
}
