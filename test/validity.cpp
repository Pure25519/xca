/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2023 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QTest>

#include "lib/audit.h"
#include "lib/db_key.h"
#include "lib/db_x509.h"
#include "lib/issuance.h"
#include "lib/pki_x509.h"
#include "widgets/MainWindow.h"
#include "widgets/NewX509.h"
#include "widgets/validity.h"

#include "main.h"

void test_main::testValidity()
{
	try {

		Validity *start = new Validity(mainwin);
		Validity *end = new Validity(mainwin);

		QCOMPARE(start->displayFormat(), "yyyy-MM-dd hh:mm 'GMT'");
		QCOMPARE(end->displayFormat(), "yyyy-MM-dd hh:mm 'GMT'");
		end->setEndDate(true);
		start->hideTime(true);
		end->hideTime(true);
		QCOMPARE(start->displayFormat(), "yyyy-MM-dd 00:00 'GMT'");
		QCOMPARE(end->displayFormat(), "yyyy-MM-dd 23:59 'GMT'");

		start->setDate(a1time("20130921094317Z"));
		end->setDiff(start, 7, 0);
		QCOMPARE(start->getDate().toPlain(), "20130921000000Z");
		QCOMPARE(end->getDate().toPlain(), "20130927235959Z");
		start->hideTime(false);
		end->hideTime(false);
		QCOMPARE(start->getDate().toPlain(), "20130921094300Z");
		QCOMPARE(end->getDate().toPlain(), "20130928094300Z");
		start->hideTime(false);
		QCOMPARE(start->getDate().toPlain(), "20130921094300Z");
		start->hideTime(true);
		end->hideTime(true);
		QCOMPARE(start->getDate().toPlain(), "20130921000000Z");
		QCOMPARE(end->getDate().toPlain(), "20130927235959Z");

		end->setDiff(start, 2, 1);
		QCOMPARE(end->getDate().toPlain(), "20131120235959Z");
		end->hideTime(true);
		QCOMPARE(end->getDate().toPlain(), "20131120235959Z");
		end->hideTime(false);
		QCOMPARE(end->getDate().toPlain(), "20131121094300Z");

	} catch (...) {
		QVERIFY2(false, "Exception thrown");
	}
}

/* BTD-51: below a CA with an undefined notAfter (99991231235959Z, which
 * a1time keeps as the epoch) the New Certificate dialog proposed an end
 * date in 1970, because it capped the proposal at the signer's notAfter
 * with a plain comparison. */
void test_main::proposalUnderUnlimitedCa()
{
	try {
		openDB();
		ServiceContext ctx(ServiceContext::cli, "os:test");
		pki_key *key = Database.model<db_key>()->newKey(
				keyjob("EC:prime256v1"), "Unlimited CA");
		QVERIFY(key);
		x509name n;
		n.addEntryByNid(NID_commonName, "Unlimited CA");
		IssuanceSpec spec;
		spec.name = "Unlimited CA";
		spec.subject = n;
		spec.key = key;
		spec.notBefore = a1time();
		spec.notAfter.setUndefined();
		spec.hashAlgo = digest(NID_sha256);
		spec.extensions.basicCA = ExtensionSpec::bc_ca;
		spec.extensions.keyUsage << "keyCertSign" << "cRLSign";
		pki_x509 *ca = Database.model<db_x509>()->newCert(ctx, spec);
		QVERIFY(ca);
		QVERIFY(ca->getNotAfter().isUndefined());

		NewX509 *dlg = new NewX509(mainwin);
		dlg->setCert();
		dlg->defineSigner(ca, false);
		QVERIFY(dlg->foreignSignRB->isChecked());
		dlg->on_certList_currentIndexChanged(0);

		/* the dialog's default: one year from now (the last day of
		 * it with the time hidden) */
		QDate start = dlg->notBefore->getDate().date();
		a1time end = dlg->notAfter->getDate();
		QString shown = QDateTime(end).toString(Qt::ISODate);
		QVERIFY2(!end.isUndefined() && end.isValid(), CCHAR(shown));
		QVERIFY2(end.date() >= start.addYears(1).addDays(-1) &&
			end.date() <= start.addYears(1), CCHAR(shown));

		/* an explicit later date stays, the CA does not end */
		dlg->notAfter->setDate(a1time("20500101000000Z"));
		dlg->on_certList_currentIndexChanged(0);
		QCOMPARE(dlg->notAfter->getDate().date(), QDate(2050, 1, 1));
		delete dlg;
	} catch (errorEx &err) {
		QVERIFY2(false, CCHAR(err.getString()));
	}
}
