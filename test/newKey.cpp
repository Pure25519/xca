/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2023 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QRegularExpression>
#include <QTest>

#include "widgets/MainWindow.h"
#include "ui_MainWindow.h"
#include "widgets/NewKey.h"
#include "ui_NewKey.h"
#include "widgets/KeyDetail.h"
#include "ui_KeyDetail.h"
#include "lib/audit.h"
#include "lib/db_key.h"
#include "main.h"

#include <openssl/core_names.h>

void test_main::newKey()
{
	/* RSA 3012 bit key - Remember as default */
	NewKey *dlg = new NewKey(mainwin, "Alfons");
	dlg->show();
	Q_ASSERT(QTest::qWaitForWindowActive(dlg));
	dlg->keyLength->setEditText("3012 bit");
	QCOMPARE(dlg->rememberDefault->isChecked(), false);
	dlg->rememberDefault->setChecked(true);
	dlg->accept();
	keyjob job = dlg->getKeyJob();
	QCOMPARE(job.ktype.name, "RSA");
	QCOMPARE(job.size, 3012);
	delete dlg;

	/* Remembered RSA:3012 key. Change to EC:secp521r1 */
	dlg = new NewKey(mainwin, "Erwin");
	dlg->show();
	Q_ASSERT(QTest::qWaitForWindowActive(dlg));
	QCOMPARE(dlg->rememberDefault->isChecked(), false);
	QCOMPARE(job.toString(), dlg->getKeyJob().toString());
#ifndef OPENSSL_NO_EC
	/* Curve box visible after selecting EC Key */
	QCOMPARE(dlg->curveBox->isVisible(),false);
	QCOMPARE(dlg->curveLabel->isVisible(),false);
	dlg->keyType->setCurrentIndex(2);
	QCOMPARE(dlg->curveBox->isVisible(),true);
	QCOMPARE(dlg->curveLabel->isVisible(),true);
	dlg->curveBox->setCurrentIndex(2);
	QCOMPARE(dlg->getKeyJob().toString(), "EC:secp521r1");
#ifdef EVP_PKEY_ED25519
	/* Select Edwards Curve */
	dlg->keyType->setCurrentIndex(3);
	QCOMPARE(dlg->getKeyJob().toString(), "ED25519");
	/* Neither key size nor curve is visible */
	QCOMPARE(dlg->curveBox->isVisible(),false);
	QCOMPARE(dlg->curveLabel->isVisible(),false);
	QCOMPARE(dlg->keyLength->isVisible(),false);
	QCOMPARE(dlg->keySizeLabel->isVisible(),false);
#endif
	/* Ed448, ML-DSA and SLH-DSA: offered, neither size nor curve (BTD-16).
	 * The hidden size field of a type with size is not theirs: an
	 * edited RSA size did make "takes no size" of an ML-DSA job */
	dlg->keyType->setCurrentIndex(0);
	dlg->keyLength->setEditText("no size");
	foreach (const keytype t, keytype::types()) {
		if (!t.fixed())
			continue;
		int idx = dlg->keyType->findText(t.name);
		QVERIFY2(idx != -1, CCHAR(t.name));
		dlg->keyType->setCurrentIndex(idx);
		QCOMPARE(dlg->getKeyJob().toString(), t.name);
		QVERIFY(dlg->getKeyJob().isValid());
		QCOMPARE(dlg->curveBox->isVisible(),false);
		QCOMPARE(dlg->keyLength->isVisible(),false);
	}
	QVERIFY(dlg->keyType->findText("ML-DSA-65") != -1);
	QVERIFY(dlg->keyType->findText("SLH-DSA-SHAKE-256f") != -1);
	/* Back to EC and previously set curve is set */
	dlg->keyType->setCurrentIndex(2);
	QCOMPARE(dlg->getKeyJob().toString(), "EC:secp521r1");
#endif
	dlg->accept();
	delete dlg;

	/* Open dialog again and RSA:3012 is remembered */
	dlg = new NewKey(mainwin, "Otto");
	dlg->show();
	Q_ASSERT(QTest::qWaitForWindowActive(dlg));
	QCOMPARE(dlg->rememberDefault->isChecked(), false);
	QCOMPARE(job.toString(), dlg->getKeyJob().toString());
	QCOMPARE(dlg->curveBox->isVisible(),false);
	QCOMPARE(dlg->curveLabel->isVisible(),false);
#ifndef OPENSSL_NO_EC
	/* Select EC and remember as default */
	dlg->keyType->setCurrentIndex(2);
	dlg->curveBox->setCurrentIndex(2);

	QCOMPARE(dlg->curveBox->isVisible(),true);
	QCOMPARE(dlg->curveLabel->isVisible(),true);
	QCOMPARE(dlg->getKeyJob().toString(), "EC:secp521r1");
	dlg->rememberDefault->setChecked(true);
	dlg->accept();
	delete dlg;

	/* Now "EC:secp521r1" is remembered as default */
	dlg = new NewKey(mainwin, "Heini");
	dlg->show();
	Q_ASSERT(QTest::qWaitForWindowActive(dlg));
	QCOMPARE(dlg->getKeyJob().toString(), "EC:secp521r1");
	QCOMPARE(dlg->rememberDefault->isChecked(), false);
#endif
	dlg->accept();
	delete dlg;
}

/* The key details of the types without size or curve show the algorithm
 * and the raw public key instead of "Unknown key" (BTD-16) */
void test_main::keyDetailFixed()
{
	openDB();
	ServiceContext ctx(ServiceContext::gui, "os:gui-test");
	db_key *keys = Database.model<db_key>();
	QVERIFY(keys);

	for (const char *name : { "ED448", "ML-DSA-65", "SLH-DSA-SHA2-128s" }) {
		pki_key *key = keys->newKey(ctx, keyjob(name), name);
		QVERIFY(key);
		KeyDetail *dlg = new KeyDetail(mainwin);
		dlg->setKey(key, false);
		QCOMPARE(dlg->tlHeader->text(),
			QString("Details of the %1 key").arg(name));
		QCOMPARE(dlg->tlPubEx->text(), QString("Algorithm"));
		QCOMPARE(dlg->keyPubEx->text(), QString(name));
		/* the raw public key, hex digits compared */
		static const QRegularExpression noHex("[^0-9A-Fa-f]");
		QString shown = dlg->keyModulus->toPlainText().remove(noHex);
		QString pub = key->QByteArrayParam(OSSL_PKEY_PARAM_PUB_KEY)
					.toHex();
		QVERIFY(!pub.isEmpty());
		QCOMPARE(shown.toLower(), pub);
		delete dlg;
	}
}
