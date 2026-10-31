/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2023 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __MAIN_H
#define __MAIN_H

#include "lib/entropy.h"
#include "lib/pki_evp.h"

#include "PwDialogMock.h"

#include <QTest>
#include <QTimer>
#include <QApplication>
#include <functional>
#include <QtGlobal>

class test_main: public QObject
{
	Q_OBJECT

	Entropy *entropy {};
	PwDialogMock *pwdialog{};

	void openDB();
	void dbstatus();
	class ImportMulti *importDialog();
	static const QMap<QString, QString> pemdata;

  public:
	static void initMain();

  private slots:
	void initTestCase();
	void cleanupTestCase();
	void cleanup();
	void newKey();
	void keyDetailFixed();
	void digestLessSigner();
	void importPEM();
	void importLockedKeepsItems();
	void importOneFailingItem();
	void importAuditFailureKeepsItem();
	void tokenDialogClosedDatabase();
	void exportFormat();
	void exportMlDsaEncoding();
	void exportPkcs12Mac();
	void revoke();
	void renewalSigningFails();
	void issueRefusedByPolicy();
	void testValidity();
	void proposalUnderUnlimitedCa();
	void issueBelowExpiredCa();
	void issueMidnightBelowTodaysCa();
	void issueRefusedInsideDialog();
	void automationIds();
	void issuanceExtensions();
	void optionsStoreChangedOnly();
	void lineExtensionTyping();
	void templateMergeRoundTrip();
	void crlRefusedWithoutCrlSign();
	void keyUsageByKeyType_data();
	void keyUsageByKeyType();
	void issueInAccept_data();
	void issueInAccept();
	void ekuRows_data();
	void ekuRows();
	void ekuOwnOidAndReplace();
	void ekuBuiltInList();
	void dnUpperBounds();

  public:
	template <class T> static T *findWindow(const QString &name)
	{
		T *ret = nullptr;
		for (int i=0; i < 200; i++) {
			foreach (QWidget *w, QApplication::allWidgets()) {
				T *dest = dynamic_cast<T*>(w);
				if (dest && name == dest->objectName() && dest->isVisible()) {
					qDebug() << "Widget found:" << name << dest << i << dest->isVisible();
					ret = dest;
				}
			}
			if (ret) {
				if (!QTest::qWaitForWindowActive(ret))
					return nullptr;
				return ret;
			}
			QThread::msleep(50);
		}
		qWarning() << "Widget not found:" << name;
		return nullptr;
	}
};

/* BTD-180: dialogs are driven from the GUI thread only. A worker thread
 * that clicks in a dialog races with the GUI thread (Qt widgets are not
 * thread-safe) and crashed testxca now and then (test_main::revoke).
 * whenShown() runs action in the event loop of the modal dialog that
 * opens next: a timer looks every 10 ms for a visible widget of type T
 * with that object name, for at most ten seconds. test_main::cleanup()
 * ends the timers of a test, so none acts on a later test's dialog. */
extern int dialogDriverRun;
/* extkeyuse_nid as initOIDs() left it, without eku.txt (BTD-215) */
extern QList<int> ekuListAtStart;

template <class T> static T *visibleWidget(const QString &name)
{
	for (QWidget *w : QApplication::allWidgets()) {
		T *t = dynamic_cast<T *>(w);
		if (t && t->objectName() == name && t->isVisible())
			return t;
	}
	return nullptr;
}

template <class T> static void whenShown(const QString &name,
				std::function<void(T *)> action,
				int tries = 1000)
{
	int run = dialogDriverRun;
	QTimer::singleShot(10, [name, action, tries, run]() {
		if (run != dialogDriverRun)
			return;
		T *w = visibleWidget<T>(name);
		if (w)
			action(w);
		else if (tries > 0)
			whenShown<T>(name, action, tries - 1);
		else
			qWarning() << "Widget not shown:" << name;
	});
}


#endif
