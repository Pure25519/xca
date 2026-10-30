/* vi: set sw=4 ts=4:
 *
 * RFC 5280 upper bounds in the New Certificate dialog (BTD-202):
 * C=DEU shows the error naming countryName and its limit, the dialog
 * stays open with the input, and nothing is issued. The old warning
 * ("Continue rollout") is gone; the service refuses such a value.
 */

#include <QAbstractButton>
#include <QLineEdit>
#include <QMessageBox>
#include <QThread>

#include "widgets/MainWindow.h"
#include "widgets/NewX509.h"
#include "widgets/XcaWarning.h"
#include "lib/audit.h"
#include "lib/db_key.h"
#include "lib/db_x509.h"
#include "lib/issuance.h"
#include "lib/pki_x509.h"

#include "main.h"

static QString dnBoxText;
static bool dnHadContinue;

/* Answers the error box of the dialog with Ok and notes its text */
static void answerDnBox()
{
	xcaWarningBox *box = test_main::findWindow<xcaWarningBox>("dlg_warning");
	if (!box)
		return;
	dnBoxText = box->text();
	dnHadContinue = box->button(QMessageBox::Apply) != nullptr;
	box->button(QMessageBox::Ok)->click();
}

void test_main::dnUpperBounds()
{
	try {
		openDB();
		ServiceContext ctx(ServiceContext::cli, "os:test");
		db_key *keys = Database.model<db_key>();
		IssuanceSpec spec;
		spec.name = "DN CA";
		spec.subject.addEntryByNid(NID_commonName, spec.name);
		spec.key = keys->newKey(keyjob("EC:prime256v1"), "DN CA key");
		spec.notBefore = a1time(QDateTime::currentDateTimeUtc().addDays(-1));
		spec.notAfter = a1time(QDateTime::currentDateTimeUtc().addYears(2));
		spec.hashAlgo = digest(NID_sha256);
		spec.extensions.basicCA = ExtensionSpec::bc_ca;
		spec.extensions.keyUsage << "keyCertSign" << "cRLSign";
		pki_x509 *ca = Database.model<db_x509>()->newCert(ctx, spec);
		QVERIFY(ca);
		pki_key *key = keys->newKey(keyjob("EC:prime256v1"), "ee key");
		int certs = Store.getAll<pki_x509>().size();

		NewX509 *dlg = new NewX509(mainwin);
		dlg->setCert();
		dlg->defineSigner(ca, false);
		dlg->keyList->setCurrentPkiItem(key);
		QLineEdit *c = dlg->findChild<QLineEdit *>("dlg_newX509_dn_C");
		QLineEdit *cn = dlg->findChild<QLineEdit *>("dlg_newX509_dn_CN");
		QVERIFY(c && cn);
		c->setText("DEU");
		cn->setText("dn.example");
		dlg->description->setText("dn bounds");
		dlg->basicCA->setCurrentIndex(2);
		dlg->notBefore->setDate(a1time());
		dlg->notAfter->setDate(a1time(
			QDateTime::currentDateTimeUtc().addYears(1)));

		dnBoxText.clear();
		dnHadContinue = false;
		QThread *job = QThread::create(answerDnBox);
		job->start();
		dlg->accept();
		job->wait();
		delete job;
		QVERIFY2(dnBoxText.contains("countryName") &&
			 dnBoxText.contains("exactly 2"), CCHAR(dnBoxText));
		QVERIFY(!dnHadContinue);
		QVERIFY(dlg->result() != QDialog::Accepted);
		QCOMPARE(c->text(), QString("DEU"));
		QCOMPARE(Store.getAll<pki_x509>().size(), certs);

		/* corrected, the same dialog issues */
		c->setText("DE");
		dlg->accept();
		QCOMPARE(dlg->result(), (int)QDialog::Accepted);
		pki_x509 *cert = Database.model<db_x509>()->newCert(
			ServiceContext::localUser(ServiceContext::gui),
			dlg->getIssuanceSpec());
		QVERIFY(cert);
		QCOMPARE(cert->getSubject().getEntryByNid(NID_countryName),
			QString("DE"));
		delete dlg;
	} catch (errorEx &err) {
		QVERIFY2(false, CCHAR(err.getString()));
	}
}
