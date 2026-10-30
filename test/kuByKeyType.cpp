/* vi: set sw=4 ts=4:
 *
 * Key usage by key type in the GUI (BTD-195): a template with
 * keyEncipherment issues for an RSA key, but refuses an EC key with an
 * error that names the bit; no certificate is stored.
 */

#include <QThread>

#include "widgets/MainWindow.h"
#include "widgets/NewX509.h"
#include "widgets/CertTreeView.h"
#include "lib/XcaWarningCore.h"
#include "lib/audit.h"
#include "lib/db_key.h"
#include "lib/db_x509.h"
#include "lib/issuance.h"
#include "lib/pki_temp.h"
#include "lib/pki_x509.h"
#include "lib/template.h"

#include "main.h"

static QStringList kuErrors;
static pki_x509 *kuCa;
static pki_key *kuKey;
static pki_temp *kuTemplate;

class kuWarnings : public xcaWarningCore
{
  public:
	void error(const QString &msg) override
	{
		kuErrors << msg;
	}
};

static void issueFromTemplate()
{
	NewX509 *dlg = test_main::findWindow<NewX509>("NewX509");
	if (!dlg)
		return;
	QMetaObject::invokeMethod(dlg, [dlg]() {
		dlg->defineTemplate(kuTemplate);
		dlg->defineSigner(kuCa, false);
		dlg->keyList->setCurrentPkiItem(kuKey);
		x509name n;
		n.addEntryByNid(NID_commonName, "web.example");
		dlg->setX509name(n);
		dlg->description->setText("from template");
		dlg->notBefore->setDate(a1time());
		dlg->notAfter->setDate(a1time(
			QDateTime::currentDateTimeUtc().addYears(1)));
		dlg->accept();
	}, Qt::BlockingQueuedConnection);
}

void test_main::keyUsageByKeyType()
{
	try {
		openDB();
		ServiceContext ctx(ServiceContext::cli, "os:test");
		db_key *keys = Database.model<db_key>();
		IssuanceSpec spec;
		spec.name = "KU CA";
		spec.subject.addEntryByNid(NID_commonName, spec.name);
		spec.key = keys->newKey(keyjob("RSA:2048"), "KU CA key");
		spec.notBefore = a1time(QDateTime::currentDateTimeUtc().addDays(-1));
		spec.notAfter = a1time(QDateTime::currentDateTimeUtc().addYears(2));
		spec.hashAlgo = digest(NID_sha256);
		spec.extensions.basicCA = ExtensionSpec::bc_ca;
		spec.extensions.keyUsage << "keyCertSign" << "cRLSign";
		kuCa = Database.model<db_x509>()->newCert(ctx, spec);
		QVERIFY(kuCa);

		kuTemplate = new pki_temp("web server");
		TemplateSpec t = TemplateSpec::fromTemplate(kuTemplate);
		t.extensions.basicCA = ExtensionSpec::bc_not_ca;
		t.extensions.keyUsage << "digitalSignature" << "keyEncipherment";
		t.extensions.extKeyUsage << "serverAuth";
		t.toTemplate(kuTemplate);

		for (const char *job : { "EC:prime256v1", "RSA:2048" }) {
			kuKey = keys->newKey(keyjob(job), QString("key ") + job);
			int certs = Store.getAll<pki_x509>().size();
			kuErrors.clear();
			xcaWarning::setGui(new kuWarnings());
			QThread *thread = QThread::create(issueFromTemplate);
			thread->start();
			mainwin->certView->newItem();
			thread->wait();
			delete thread;
			xcaWarning::setGui(new xcaWarningCore());
			if (QString(job).startsWith("EC")) {
				QCOMPARE(kuErrors.size(), 1);
				QVERIFY2(kuErrors[0].contains("keyEncipherment"),
					CCHAR(kuErrors[0]));
				QCOMPARE(Store.getAll<pki_x509>().size(), certs);
			} else {
				QVERIFY2(kuErrors.isEmpty(), CCHAR(kuErrors.join("; ")));
				QCOMPARE(Store.getAll<pki_x509>().size(), certs + 1);
			}
		}
		delete kuTemplate;
	} catch (errorEx &err) {
		QVERIFY2(false, CCHAR(err.getString()));
	}
}
