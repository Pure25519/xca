/* vi: set sw=4 ts=4:
 *
 * Key usage by key type in the GUI (BTD-195, BTD-203): the default
 * templates of misc/ issue TLS server certificates for RSA (TLS_server)
 * and EC keys (TLS_server_EC) without a question. An EC key with the RSA
 * template is never issued with keyEncipherment: the dialog shows the
 * error with the action "Remove unfitting key usage bits"; with "Edit" it
 * stays open and nothing is stored, after the action the certificate
 * lacks the bit and the audit entry names it (ku_removed).
 */

#include <QAbstractButton>
#include <QMessageBox>
#include <QThread>

#include "widgets/MainWindow.h"
#include "widgets/NewX509.h"
#include "widgets/CertTreeView.h"
#include "widgets/XcaWarning.h"
#include "lib/XcaWarningCore.h"
#include "lib/audit.h"
#include "lib/db_key.h"
#include "lib/db_temp.h"
#include "lib/db_x509.h"
#include "lib/issuance.h"
#include "lib/pki_temp.h"
#include "lib/pki_x509.h"
#include "lib/template.h"

#include "main.h"

static QString kuBoxText;
static bool kuHadAction;

/* Answers the warning box of the dialog: Apply ("Remove unfitting key
 * usage bits") or Ok ("Edit") */
static void answerBox(xcaWarningBox *box,
			QMessageBox::StandardButton answer)
{
	kuBoxText = box->text() + "\n" + box->informativeText();
	QAbstractButton *remove = box->button(QMessageBox::Apply);
	kuHadAction = remove &&
		remove->text() == "Remove unfitting key usage bits";
	box->button(answer)->click();
}

static bool hasKeyEncipherment(pki_x509 *cert)
{
	ASN1_BIT_STRING *ku = (ASN1_BIT_STRING *)X509_get_ext_d2i(
			cert->getCert(), NID_key_usage, nullptr, nullptr);
	bool set = ku && ASN1_BIT_STRING_get_bit(ku, 2);
	ASN1_BIT_STRING_free(ku);
	return set;
}

void test_main::keyUsageByKeyType_data()
{
	QTest::addColumn<QString>("file");
	QTest::addColumn<QString>("job");
	/* 0: no question, Ok: "Edit", Apply: "Remove unfitting ..." */
	QTest::addColumn<int>("answer");
	QTest::newRow("TLS_server RSA") << "TLS_server" << "RSA:2048" << 0;
	QTest::newRow("TLS_server_EC EC") << "TLS_server_EC" << "EC:prime256v1"
		<< 0;
	QTest::newRow("TLS_server EC, edit") << "TLS_server" << "EC:prime256v1"
		<< (int)QMessageBox::Ok;
	QTest::newRow("TLS_server EC, remove") << "TLS_server" << "EC:prime256v1"
		<< (int)QMessageBox::Apply;
}

void test_main::keyUsageByKeyType()
{
	QFETCH(QString, file);
	QFETCH(QString, job);
	QFETCH(int, answer);
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
		pki_x509 *ca = Database.model<db_x509>()->newCert(ctx, spec);
		QVERIFY(ca);

		/* the template as shipped, imported as a user would, so the
		 * dialog's template list holds it */
		pki_temp *shipped = new pki_temp("shipped");
		shipped->fload(QString(XCA_SOURCE_DIR "/misc/%1.xca").arg(file));
		QCOMPARE(shipped->getIntName(), file);
		pki_temp *temp = dynamic_cast<pki_temp *>(
			Database.model<db_temp>()->insert(shipped));
		QVERIFY(temp);
		pki_key *key = keys->newKey(keyjob(job), QString("key ") + job);
		int certs = Store.getAll<pki_x509>().size();

		NewX509 *dlg = new NewX509(mainwin);
		dlg->setCert();
		dlg->defineTemplate(temp);
		dlg->defineSigner(ca, false);
		dlg->keyList->setCurrentPkiItem(key);
		x509name n;
		n.addEntryByNid(NID_commonName, "web.example");
		dlg->setX509name(n);
		dlg->description->setText("from template");
		dlg->notBefore->setDate(a1time());
		dlg->notAfter->setDate(a1time(
			QDateTime::currentDateTimeUtc().addYears(1)));

		/* an unexpected box is answered with "Edit", so the test
		 * fails instead of waiting for it */
		kuBoxText.clear();
		kuHadAction = false;
		QMessageBox::StandardButton button = answer ?
			(QMessageBox::StandardButton)answer : QMessageBox::Ok;
		/* in the box's event loop (whenShown(), BTD-180) */
		whenShown<xcaWarningBox>("dlg_warning",
			[button](xcaWarningBox *box) {
				answerBox(box, button);
			});
		dlg->accept();
		if (answer) {
			QVERIFY2(kuBoxText.contains("keyEncipherment") &&
				kuBoxText.contains("template 'TLS_server'"),
				CCHAR(kuBoxText));
			QVERIFY(kuHadAction);
		} else {
			QVERIFY2(kuBoxText.isEmpty(), CCHAR(kuBoxText));
		}
		bool accepted = dlg->result() == QDialog::Accepted;
		QCOMPARE(accepted, answer != QMessageBox::Ok);
		if (accepted) {
			pki_x509 *cert = Database.model<db_x509>()->newCert(
				ServiceContext::localUser(ServiceContext::gui),
				dlg->getIssuanceSpec());
			QVERIFY(cert);
			QVERIFY(!hasKeyEncipherment(cert) || job.startsWith("RSA"));
			AuditEntry e = AuditLog::entries().last();
			QCOMPARE(e.action, QString("certificate.issue"));
			QCOMPARE(e.result, QString("success"));
			QCOMPARE(e.params.value("template").toString(), file);
			QCOMPARE(e.params.value("ku_removed").toString(),
				answer == QMessageBox::Apply ? QString("keyEncipherment")
							     : QString());
		}
		QCOMPARE(Store.getAll<pki_x509>().size(), certs + (accepted ? 1 : 0));
		delete dlg;
	} catch (errorEx &err) {
		QVERIFY2(false, CCHAR(err.getString()));
	}
}
