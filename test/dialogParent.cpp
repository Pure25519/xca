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
