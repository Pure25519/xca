/* vi: set sw=4 ts=4:
 *
 * The name policy of a CA in the GUI (BTD-167): the New Certificate
 * dialog issues through the same service function, so a name outside
 * the policy assigned to the CA is refused with the error naming rule
 * and value, and no certificate is stored.
 */

#include <QPointer>
#include <QThread>

#include "widgets/MainWindow.h"
#include "widgets/NewX509.h"
#include "widgets/XcaWarning.h"
#include "widgets/CertTreeView.h"
#include "lib/XcaWarningCore.h"
#include "lib/audit.h"
#include "lib/db_key.h"
#include "lib/db_x509.h"
#include "lib/issuance.h"
#include "lib/pki_x509.h"
#include "lib/profile_store.h"

#include "main.h"

static QString policyBoxText;
static bool policyStillOpen;
static pki_x509 *policyCa;
static pki_key *policyKey;

/* Fills the dialog on the GUI thread, presses OK and reads the refusal,
 * which since BTD-212 shows in the open dialog; then aborts */
static void issueOtherOrganisation()
{
	QPointer<NewX509> dlg = test_main::findWindow<NewX509>("NewX509");
	if (!dlg)
		return;
	QMetaObject::invokeMethod(qApp, [dlg]() {
		dlg->defineSigner(policyCa, false);
		dlg->keyList->setCurrentPkiItem(policyKey);
		x509name n;
		n.addEntryByNid(NID_organizationName, "Other");
		n.addEntryByNid(NID_commonName, "plc10");
		dlg->setX509name(n);
		dlg->description->setText("outside the policy");
		dlg->basicCA->setCurrentIndex(2);
		dlg->notBefore->setDate(a1time());
		dlg->notAfter->setDate(a1time(
			QDateTime::currentDateTimeUtc().addYears(1)));
	}, Qt::BlockingQueuedConnection);
	QMetaObject::invokeMethod(qApp, [dlg]() {
		if (dlg)
			dlg->accept();
	}, Qt::QueuedConnection);
	xcaWarningBox *box = test_main::findWindow<xcaWarningBox>("dlg_warning");
	if (box) {
		policyBoxText = box->text();
		box->button(QMessageBox::Ok)->click();
	}
	QMetaObject::invokeMethod(qApp, [dlg]() {
		policyStillOpen = dlg && dlg->isVisible();
		if (policyStillOpen)
			dlg->reject();
	}, Qt::BlockingQueuedConnection);
}

void test_main::issueRefusedByPolicy()
{
	try {
		openDB();
		ServiceContext ctx(ServiceContext::cli, "os:test");
		db_key *keys = Database.model<db_key>();
		pki_key *caKey = keys->newKey(keyjob("EC:prime256v1"), "Policy CA");
		policyKey = keys->newKey(keyjob("EC:prime256v1"), "EE");
		x509name n;
		n.addEntryByNid(NID_commonName, "Policy CA");
		IssuanceSpec spec;
		spec.name = "Policy CA";
		spec.subject = n;
		spec.key = caKey;
		spec.notBefore = a1time(QDateTime::currentDateTimeUtc().addDays(-1));
		spec.notAfter = a1time(QDateTime::currentDateTimeUtc().addYears(2));
		spec.hashAlgo = digest(NID_sha256);
		spec.extensions.basicCA = ExtensionSpec::bc_ca;
		spec.extensions.keyUsage << "keyCertSign" << "cRLSign";
		policyCa = Database.model<db_x509>()->newCert(ctx, spec);
		QVERIFY(policyCa);
		ProfileStore::importFile(ctx, "policy",
			QString(XCA_SOURCE_DIR "/test/service/data/policies/ot-lab-names.json"));
		ProfileStore::assign(ctx, policyCa, "policy", "ot-lab-names");
		int certs = Store.getAll<pki_x509>().size();

		policyBoxText.clear();
		policyStillOpen = false;
		QThread *job = QThread::create(issueOtherOrganisation);
		job->start();
		mainwin->certView->newItem();
		while (!job->isFinished())
			QTest::qWait(20);
		delete job;

		QVERIFY2(policyBoxText.contains("ot-lab-names") &&
			 policyBoxText.contains("Other"), CCHAR(policyBoxText));
		QVERIFY(policyStillOpen);
		QCOMPARE(Store.getAll<pki_x509>().size(), certs);
	} catch (errorEx &err) {
		QVERIFY2(false, CCHAR(err.getString()));
	}
}
