/* vi: set sw=4 ts=4:
 *
 * Store on Security token of the key view with a real token (BTD-217 AC5,
 * BTD-126): KeyTreeView::toToken() writes the software key to a SoftHSM
 * token and replaces it by the token key, all or nothing
 * (db_key::replaceWithToken()). On success the database holds the token
 * key and no software key; when the store of the token key fails, the
 * software key stays, the copy on the token remains and the error says
 * so. Without SOFTHSM2_MODULE both tests skip with the reason.
 */

#include <QSqlQuery>

#include "widgets/MainWindow.h"
#include "ui_MainWindow.h"
#include "widgets/KeyTreeView.h"
#include "lib/XcaWarningCore.h"
#include "lib/db_key.h"
#include "lib/pkcs11.h"
#include "lib/pki_scard.h"

#include "PwDialogMock.h"
#include "SoftHsmToken.h"
#include "main.h"

static QStringList storeErrors;

/* testxca answers like the command line; this one keeps the errors */
class storeWarnings : public xcaWarningCore
{
  public:
	void error(const QString &msg) override
	{
		storeErrors << msg;
	}
};

/* A software key, current in the key view, and the token loaded */
static pki_key *currentSoftwareKey(SoftHsmToken &token, const QString &name)
{
	if (!token.load())
		return nullptr;
	db_key *keys = Database.model<db_key>();
	pki_key *soft = keys->newKey(keyjob("EC:prime256v1"), name);
	if (!soft)
		return nullptr;
	/* the view's proxy follows after its throttle timer */
	if (!QTest::qWaitFor([&]() {
		return mainwin->keyView->getProxyIndex(
			keys->index(soft)).isValid(); }, 2000))
		return nullptr;
	mainwin->keyView->setCurrentIndex(
		mainwin->keyView->getProxyIndex(keys->index(soft)));
	return soft;
}

/* Runs Store on Security token with the PIN from its source, the test
 * token chosen (SoftHSM offers a free slot next to it) and the question
 * token.replace_key answered yes */
static void storeOnToken(PwDialogMock *pwdialog)
{
	pwdialog->tokenPrefix = SoftHsmToken::label;
	xcaWarning::setGui(new storeWarnings());
	xcaWarningCore::setConfirmations(false, { "token.replace_key" });
	storeErrors.clear();
	{
		TokenPinScope pin;
		mainwin->keyView->toToken();
	}
	xcaWarningCore::setConfirmations(false, {});
	xcaWarning::setGui(new xcaWarningCore());
	pwdialog->tokenPrefix.clear();
}

void test_main::storeOnTokenReplacesKey()
{
	SoftHsmToken token;
	SoftHsmToken::watchMessages();
	QString why = token.setUp();
	if (!why.isEmpty())
		QSKIP(CCHAR(why));
	try {
		openDB();
		pki_key *soft = currentSoftwareKey(token, "BTD-217 store");
		QVERIFY(soft);

		storeOnToken(pwdialog);
		QVERIFY2(storeErrors.isEmpty(), CCHAR(storeErrors.join("; ")));

		/* the software key is gone, the token key is in its place */
		QVERIFY(!Database.model<db_key>()->isStored(soft));
		QList<pki_key *> keys = Store.getAll<pki_key>();
		QCOMPARE(keys.size(), 1);
		QVERIFY(keys[0]->isToken());
		QCOMPARE(keys[0]->getIntName(), QString("BTD-217 store"));
		QVERIFY(token.labels(CKO_PRIVATE_KEY).contains("BTD-217 store"));
		QStringList leaks = token.messagesWithPin();
		QVERIFY2(leaks.isEmpty(), CCHAR(leaks.join("; ")));
	} catch (...) {
		QFAIL("Exception thrown");
	}
}

void test_main::storeOnTokenFailureKeepsKey()
{
	SoftHsmToken token;
	SoftHsmToken::watchMessages();
	QString why = token.setUp();
	if (!why.isEmpty())
		QSKIP(CCHAR(why));
	try {
		openDB();
		pki_key *soft = currentSoftwareKey(token, "BTD-217 kept");
		QVERIFY(soft);

		/* the store of the token key fails (BTD-217 AC1) */
		QSqlQuery q;
		QVERIFY(q.exec("CREATE TEMP TRIGGER btd217_gui_refuse BEFORE "
			"INSERT ON tokens BEGIN SELECT RAISE(ABORT, "
			"'BTD-217 GUI test: token key refused'); END"));
		storeOnToken(pwdialog);
		QSqlQuery("DROP TRIGGER IF EXISTS temp.btd217_gui_refuse");

		/* the error says the key is unchanged and the copy remains */
		QCOMPARE(storeErrors.size(), 1);
		QVERIFY2(storeErrors[0].contains("is unchanged in the database; "
			"the copy on the token remains"), CCHAR(storeErrors[0]));
		/* the software key stays, no token key in the database */
		QVERIFY(Database.model<db_key>()->isStored(soft));
		QList<pki_key *> keys = Store.getAll<pki_key>();
		QCOMPARE(keys.size(), 1);
		QVERIFY(!keys[0]->isToken());
		QVERIFY(token.labels(CKO_PRIVATE_KEY).contains("BTD-217 kept"));
		QStringList leaks = token.messagesWithPin();
		QVERIFY2(leaks.isEmpty(), CCHAR(leaks.join("; ")));
	} catch (...) {
		QFAIL("Exception thrown");
	}
}
