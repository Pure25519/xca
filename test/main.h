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
	void lineExtensionTyping();
	void templateMergeRoundTrip();
	void crlRefusedWithoutCrlSign();
	void keyUsageByKeyType_data();
	void keyUsageByKeyType();
	void issueInAccept_data();
	void issueInAccept();
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

#endif
