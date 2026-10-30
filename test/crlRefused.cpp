/* vi: set sw=4 ts=4:
 *
 * The CRL dialog shows the typed error of the issuer checks (BTD-188):
 * a CA whose key usage lacks cRLSign signs no CRL.
 */

#include <QThread>

#include "widgets/MainWindow.h"
#include "ui_NewCrl.h"
#include "widgets/NewCrl.h"
#include <QDialog>
#include "lib/XcaWarningCore.h"
#include "lib/audit.h"
#include "lib/db_crl.h"
#include "lib/db_key.h"
#include "lib/db_x509.h"
#include "lib/issuance.h"
#include "lib/pki_crl.h"
#include "lib/pki_x509.h"

#include "main.h"

static QStringList crlErrors;

/* testxca answers like the command line; this one keeps the errors */
class crlWarnings : public xcaWarningCore
{
  public:
	void error(const QString &msg) override
	{
		crlErrors << msg;
	}
};

static void acceptCrlDialog()
{
	QDialog *dlg = test_main::findWindow<QDialog>("XcaDialog");
	if (!dlg)
		return;
	QMetaObject::invokeMethod(dlg, [dlg]() { dlg->accept(); },
			Qt::BlockingQueuedConnection);
}

void test_main::crlRefusedWithoutCrlSign()
{
	try {
		openDB();
		ServiceContext ctx(ServiceContext::cli, "os:test");
		x509name n;
		n.addEntryByNid(NID_commonName, "No cRLSign CA");
		IssuanceSpec spec;
		spec.name = "No cRLSign CA";
		spec.subject = n;
		spec.key = Database.model<db_key>()->newKey(keyjob("EC:prime256v1"),
				"No cRLSign key");
		spec.notBefore = a1time(QDateTime::currentDateTimeUtc().addDays(-1));
		spec.notAfter = a1time(QDateTime::currentDateTimeUtc().addYears(2));
		spec.hashAlgo = digest(NID_sha256);
		spec.extensions.basicCA = ExtensionSpec::bc_ca;
		spec.extensions.keyUsage << "keyCertSign";
		pki_x509 *ca = Database.model<db_x509>()->newCert(ctx, spec);
		QVERIFY(ca);
		int crls = Store.getAll<pki_crl>().size();

		crlErrors.clear();
		xcaWarning::setGui(new crlWarnings());
		QThread *job = QThread::create(acceptCrlDialog);
		job->start();
		NewCrl::newCrl(mainwin, ca);
		job->wait();
		delete job;
		xcaWarning::setGui(new xcaWarningCore());

		QCOMPARE(crlErrors.size(), 1);
		QVERIFY2(crlErrors[0].contains("cRLSign"), CCHAR(crlErrors[0]));
		QCOMPARE(Store.getAll<pki_crl>().size(), crls);
	} catch (errorEx &err) {
		QVERIFY2(false, CCHAR(err.getString()));
	}
}
