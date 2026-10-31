/* vi: set sw=4 ts=4:
 *
 * The New Certificate dialog issues in accept() (BTD-212): on all four
 * entry points of the certificate view (new, from a request, from a
 * template, from a certificate) a refusal of the service keeps the
 * dialog open with every input and shows the typed error; corrected, the
 * same dialog issues. The refusal writes one failure audit entry and no
 * certificate. Before, the dialog closed first and the input was lost.
 * The refusal used here is a wildcard over a top-level domain in the SAN
 * (invalid_dns_name), which no check of the dialog itself catches.
 */

#include <QApplication>
#include <QPointer>
#include <QTimer>

#include "widgets/MainWindow.h"
#include "widgets/NewX509.h"
#include "widgets/CertTreeView.h"
#include "widgets/XcaWarning.h"
#include "lib/audit.h"
#include "lib/db_key.h"
#include "lib/db_x509.h"
#include "lib/db_x509req.h"
#include "lib/issuance.h"
#include "lib/load_obj.h"
#include "lib/pki_temp.h"
#include "lib/pki_x509.h"
#include "lib/pki_x509req.h"
#include "lib/request.h"

#include "main.h"

static pki_x509 *iaSigner;
static pki_key *iaKey;
static QString iaBoxText, iaSanKept;
static bool iaStillOpen;

/* the visible widget of that type and name, or nullptr */
/* Answers the refusal box with "Edit"; runs in the box's event loop */
static void answerRefusal()
{
	xcaWarningBox *box = visibleWidget<xcaWarningBox>("dlg_warning");
	if (!box)
		return;
	iaBoxText = box->text();
	box->button(QMessageBox::Ok)->click();
}

/* Drives the dialog on the GUI thread, in its own event loop (BTD-180:
 * no worker thread): a refused OK, then the corrected one */
static void driveDialog()
{
	QPointer<NewX509> dlg = visibleWidget<NewX509>("NewX509");
	if (!dlg)
		return;
	dlg->defineSigner(iaSigner, false);
	if (dlg->keyList->isEnabled())
		dlg->keyList->setCurrentPkiItem(iaKey);
	if (!dlg->fromReqCB->isChecked()) {
		x509name n;
		n.addEntryByNid(NID_commonName, "host.example");
		dlg->setX509name(n);
		dlg->description->setText("in accept");
	}
	dlg->notBefore->setDate(a1time());
	dlg->notAfter->setDate(a1time(
		QDateTime::currentDateTimeUtc().addYears(1)));
	dlg->subAltName->setText("DNS:*.com");
	/* the refusal box runs its own event loop inside accept(); a
	 * local timer, so no answer is left over for a later test */
	QTimer answer;
	answer.setSingleShot(true);
	QObject::connect(&answer, &QTimer::timeout, answerRefusal);
	answer.start(0);
	dlg->accept();
	answer.stop();
	iaStillOpen = dlg && dlg->isVisible();
	if (!iaStillOpen)
		return;
	iaSanKept = dlg->subAltName->text();
	dlg->subAltName->setText("DNS:host.example");
	dlg->accept();
	/* a second refusal must not leave the dialog waiting */
	if (dlg && dlg->isVisible())
		dlg->reject();
}

void test_main::issueInAccept_data()
{
	QTest::addColumn<QString>("entry");
	for (const char *e : { "new", "request", "template", "certificate" })
		QTest::newRow(e) << QString(e);
}

void test_main::issueInAccept()
{
	QFETCH(QString, entry);
	try {
		openDB();
		ServiceContext ctx(ServiceContext::cli, "os:test");
		db_key *keys = Database.model<db_key>();
		db_x509 *certs = Database.model<db_x509>();
		IssuanceSpec spec;
		spec.name = "Accept CA";
		spec.subject.addEntryByNid(NID_commonName, spec.name);
		spec.key = keys->newKey(keyjob("EC:prime256v1"), "Accept CA key");
		spec.notBefore = a1time(QDateTime::currentDateTimeUtc().addDays(-1));
		spec.notAfter = a1time(QDateTime::currentDateTimeUtc().addYears(2));
		spec.hashAlgo = digest(NID_sha256);
		spec.extensions.basicCA = ExtensionSpec::bc_ca;
		spec.extensions.keyUsage << "keyCertSign" << "cRLSign";
		iaSigner = certs->newCert(ctx, spec);
		QVERIFY(iaSigner);
		iaKey = keys->newKey(keyjob("EC:prime256v1"), "subject key");

		pki_x509req *req = nullptr;
		pki_temp *temp = nullptr;
		pki_x509 *model = nullptr;
		if (entry == "request") {
			RequestSpec r;
			r.name = "accept request";
			r.subject.addEntryByNid(NID_commonName, "host.example");
			r.key = iaKey;
			r.hashAlgo = digest(NID_sha256);
			req = Database.model<db_x509req>()->newRequest(ctx, r);
			QVERIFY(req);
		} else if (entry == "template") {
			load_temp l;
			temp = dynamic_cast<pki_temp *>(l.loadItem(
				XCA_SOURCE_DIR "/misc/TLS_server_EC.xca"));
			QVERIFY(temp);
		} else if (entry == "certificate") {
			IssuanceSpec m;
			m.name = "model";
			m.subject.addEntryByNid(NID_commonName, "model.example");
			m.key = keys->newKey(keyjob("EC:prime256v1"), "model key");
			m.signer = iaSigner;
			m.notBefore = spec.notBefore;
			m.notAfter = a1time(QDateTime::currentDateTimeUtc().addYears(1));
			m.hashAlgo = digest(NID_sha256);
			m.extensions.basicCA = ExtensionSpec::bc_not_ca;
			m.extensions.keyUsage << "digitalSignature";
			model = certs->newCert(ctx, m);
			QVERIFY(model);
		}
		int nCerts = Store.getAll<pki_x509>().size();
		int nEntries = AuditLog::entries().size();

		iaBoxText.clear();
		iaSanKept.clear();
		iaStillOpen = false;
		/* the dialog's event loop runs the driver */
		QTimer::singleShot(0, driveDialog);
		if (entry == "new")
			mainwin->certView->newItem();
		else if (entry == "request")
			mainwin->certView->newCert(req);
		else if (entry == "template")
			mainwin->certView->newCert(temp);
		else
			mainwin->certView->newCert(model);
		delete temp;

		QVERIFY2(iaBoxText.contains("*.com"), CCHAR(iaBoxText));
		QVERIFY2(iaStillOpen, "the refusal closed the dialog");
		QCOMPARE(iaSanKept, QString("DNS:*.com"));
		QCOMPARE(Store.getAll<pki_x509>().size(), nCerts + 1);
		QList<AuditEntry> added = AuditLog::entries().mid(nEntries);
		int failures = 0, successes = 0;
		for (const AuditEntry &e : added) {
			if (e.action != "certificate.issue")
				continue;
			if (e.result == "failure") {
				failures++;
				QCOMPARE(e.errorCode, QString("invalid_dns_name"));
				QVERIFY(!e.params.contains("serial"));
			} else {
				successes++;
				QCOMPARE(e.channel, QString("gui"));
			}
		}
		QCOMPARE(failures, 1);
		QCOMPARE(successes, 1);
	} catch (errorEx &err) {
		QVERIFY2(false, CCHAR(err.getString()));
	}
}
