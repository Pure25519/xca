/* vi: set sw=4 ts=4:
 *
 * The PKCS#12 MAC and iteration count in the export dialog (BTD-175): the
 * combo pkcs12Mac and the spin box pkcs12Iterations are shown only for
 * PKCS#12 formats with a non-legacy algorithm, and their choice reaches
 * the export service as ExportSpec::pkcs12Mac and pkcs12Iterations. The
 * default choice sends nothing, so the service takes its defaults. The
 * dialog is only built, never run with exec() (BTD-180).
 */

#include <QComboBox>
#include <QSpinBox>
#include <QTemporaryDir>

#include <openssl/x509.h>

/* AUTOUIC of testxca makes only the ui headers a test includes itself */
#include "ui_ExportDialog.h"
#include "widgets/ExportDialog.h"
#include "widgets/MainWindow.h"
#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/db_key.h"
#include "lib/db_x509.h"
#include "lib/importexport.h"
#include "lib/issuance.h"
#include "lib/pki_export.h"
#include "lib/pki_pkcs12.h"
#include "lib/pki_x509.h"
#include "lib/settings.h"

#include "main.h"

/* Format ids of pki_export::init_elements() */
enum { certPem = 1, certPkcs12 = 15 };

static ExportDialog *p12DialogFor(pki_x509 *cert)
{
	db_base *db = Database.modelForPki(cert);
	QModelIndexList idx { db->index(cert) };
	return new ExportDialog(mainwin, "BTD-175", QString(), idx, QPixmap(),
		pki_export::select(x509, db->exportFlags({ cert })));
}

/* Highlights the format; true if both controls are shown for it */
static bool p12Shown(ExportDialog *dlg, int format)
{
	QComboBox *mac = dlg->findChild<QComboBox *>("pkcs12Mac");
	QSpinBox *iter = dlg->findChild<QSpinBox *>("pkcs12Iterations");
	if (!mac || !iter)
		return false;
	int row = dlg->exportFormat->findData(format);
	if (row < 0)
		return false;
	dlg->exportFormat->setCurrentIndex(row);
	dlg->on_exportFormat_highlighted(row);
	return !mac->isHidden() && !iter->isHidden();
}

void test_main::exportPkcs12Mac()
{
	try {
		openDB();
		ServiceContext ctx(ServiceContext::cli, "os:test");
		IssuanceSpec is;
		is.name = "p12 mac cert";
		is.subject.addEntryByNid(NID_commonName, is.name);
		is.key = Database.model<db_key>()->newKey(keyjob("EC:prime256v1"),
							"p12 mac key");
		QVERIFY(is.key);
		is.notBefore = a1time(QDateTime::currentDateTimeUtc().addDays(-1));
		is.notAfter = a1time(QDateTime::currentDateTimeUtc().addYears(1));
		is.extensions.basicCA = ExtensionSpec::bc_ca;
		is.extensions.keyUsage << "keyCertSign" << "cRLSign";
		pki_x509 *cert = Database.model<db_x509>()->newCert(ctx, is);
		QVERIFY(cert);

		ExportDialog *dlg = p12DialogFor(cert);
		QComboBox *mac = dlg->findChild<QComboBox *>("pkcs12Mac");
		QSpinBox *iter = dlg->findChild<QSpinBox *>("pkcs12Iterations");
		QVERIFY2(mac && iter, "no pkcs12Mac or pkcs12Iterations in the "
			"export dialog");
		QVERIFY(p12Shown(dlg, certPkcs12));
		QVERIFY(!p12Shown(dlg, certPem));

		/* the defaults send nothing; the spin box shows the setting */
		QVERIFY(p12Shown(dlg, certPkcs12));
		QCOMPARE(iter->value(), pki_pkcs12::minIterations);
		QCOMPARE(iter->minimum(), pki_pkcs12::minIterations);
		QCOMPARE(iter->maximum(), pki_pkcs12::maxIterations);
		ExportSpec spec = dlg->exportSpec({ cert });
		QVERIFY(spec.pkcs12Mac.isEmpty());
		QCOMPARE(spec.pkcs12Iterations, 0);

		/* PBMAC1 with 4096: the spec, the help and the audit entry */
		mac->setCurrentIndex(mac->findData("pbmac1"));
		iter->setValue(4096);
		QVERIFY2(dlg->infoBox->text().contains("PBMAC1"),
			CCHAR(dlg->infoBox->text()));
		spec = dlg->exportSpec({ cert });
		QCOMPARE(spec.pkcs12Mac, QString("pbmac1"));
		QCOMPARE(spec.pkcs12Iterations, 4096);
		QTemporaryDir dir;
		spec.fileName = dir.filePath("pbmac1.p12");
		spec.passwordSource = "pass:BTD-175-gui";
		Database.model<db_x509>()->exportItems(ctx, spec);
		QList<AuditEntry> all = AuditLog::entries();
		QVERIFY(!all.isEmpty());
		QCOMPARE(all.last().params.value("pkcs12_mac").toString(),
			QString("pbmac1"));
		QCOMPARE(all.last().params.value("pkcs12_iterations").toLongLong(),
			4096LL);

		/* another format sends neither */
		QVERIFY(!p12Shown(dlg, certPem));
		spec = dlg->exportSpec({ cert });
		QVERIFY(spec.pkcs12Mac.isEmpty());
		QCOMPARE(spec.pkcs12Iterations, 0);
		delete dlg;

		/* a legacy algorithm in the settings: hidden, nothing sent */
		Settings["pkcs12_enc_algo"] = QString("PBE-SHA1-3DES");
		dlg = p12DialogFor(cert);
		QVERIFY(!p12Shown(dlg, certPkcs12));
		spec = dlg->exportSpec({ cert });
		QVERIFY(spec.pkcs12Mac.isEmpty());
		QCOMPARE(spec.pkcs12Iterations, 0);
		delete dlg;
		Settings["pkcs12_enc_algo"] = QString("AES-256-CBC");
	} catch (errorEx &err) {
		QVERIFY2(false, CCHAR(err.getString()));
	}
}
