/* vi: set sw=4 ts=4:
 *
 * Token handlers of the views with an item they cannot use (BTD-240):
 * db_base::fromIndex<T>() is a dynamic_cast and gives NULL for no
 * current item or another item type. The PIN handlers of the key view
 * with a software key, and "delete from token" of the certificate view
 * without a current item, dereferenced it. Now they warn and stop.
 */

#include "widgets/MainWindow.h"
#include "ui_MainWindow.h"
#include "widgets/KeyTreeView.h"
#include "widgets/CertTreeView.h"
#include "lib/XcaWarningCore.h"
#include "lib/audit.h"
#include "lib/db_key.h"

#include "main.h"

static QStringList nhWarnings;

/* testxca answers like the command line; this one keeps the warnings */
class nullHandlerWarnings : public xcaWarningCore
{
  public:
	void warning(const QString &msg) override
	{
		nhWarnings << msg;
	}
	void error(const QString &msg) override
	{
		nhWarnings << msg;
	}
};

void test_main::tokenHandlersWithoutToken()
{
	try {
		openDB();
		pki_key *soft = Database.model<db_key>()->newKey(
				keyjob("EC:prime256v1"), "software key");
		QVERIFY(soft);
		db_key *keys = Database.model<db_key>();
		/* the view's proxy follows after its throttle timer */
		QTRY_VERIFY_WITH_TIMEOUT(mainwin->keyView->getProxyIndex(
				keys->index(soft)).isValid(), 2000);
		mainwin->keyView->setCurrentIndex(
			mainwin->keyView->getProxyIndex(keys->index(soft)));
		/* XcaTreeView::currentIndex() is the source index */
		QCOMPARE(mainwin->keyView->currentIndex(), keys->index(soft));
		mainwin->certView->setCurrentIndex(QModelIndex());
		int entries = AuditLog::entries().size();

		xcaWarning::setGui(new nullHandlerWarnings());
		nhWarnings.clear();
		mainwin->keyView->changePin();
		mainwin->keyView->initPin();
		mainwin->keyView->changeSoPin();
		mainwin->certView->deleteFromToken();
		xcaWarning::setGui(new xcaWarningCore());

		QCOMPARE(nhWarnings.size(), 4);
		for (int i = 0; i < 3; i++)
			QVERIFY2(nhWarnings[i].contains("not a token"),
				CCHAR(nhWarnings[i]));
		QVERIFY2(nhWarnings[3].contains("No certificate"),
			CCHAR(nhWarnings[3]));
		QCOMPARE(AuditLog::entries().size(), entries);
	} catch (errorEx &err) {
		QVERIFY2(false, CCHAR(err.getString()));
	}
}
