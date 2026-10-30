/* vi: set sw=4 ts=4:
 *
 * The ML-DSA private key encoding in the export dialog (BTD-190): the
 * combo mlDsaFormat is shown only where the export writes an ML-DSA
 * private key, and its choice reaches the export service as
 * ExportSpec::privateKeyFormat. The dialog is only built, never run
 * with exec(): no second thread drives it (BTD-180).
 */

#include <QComboBox>
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
#include "lib/pki_x509.h"

#include "main.h"

/* Format ids of pki_export::init_elements() */
enum {
	certPem = 1, certPemKey = 6, certPkcs12 = 15,
	keyPemPublic = 19, keyPemPrivate = 20, keyDerPublic = 24,
	keyDerPrivate = 25, keyPkcs8Encrypted = 28, keyPkcs8 = 29,
};

static ExportDialog *dialogFor(pki_base *pki)
{
	db_base *db = Database.modelForPki(pki);
	QModelIndexList idx { db->index(pki) };
	QList<pki_base *> items { pki };
	enum pki_type type = dynamic_cast<pki_x509 *>(pki) ? x509 : asym_key;
	return new ExportDialog(mainwin, "BTD-190", QString(), idx, QPixmap(),
		pki_export::select(type, db->exportFlags(items)));
}

/* Highlights the format; true if the combo is shown for it */
static bool comboShown(ExportDialog *dlg, int format)
{
	QComboBox *combo = dlg->findChild<QComboBox *>("mlDsaFormat");
	if (!combo)
		return false;
	int row = dlg->exportFormat->findData(format);
	if (row < 0)
		return false;
	dlg->exportFormat->setCurrentIndex(row);
	dlg->on_exportFormat_highlighted(row);
	return !combo->isHidden();
}

/* The RFC 9881 privateKey CHOICE of a DER PKCS#8 file: 0x80 seed,
 * 0x04 expanded key, 0x30 both */
static int privateKeyTag(const QString &name)
{
	QFile f(name);
	if (!f.open(QIODevice::ReadOnly))
		return -1;
	QByteArray der = f.readAll();
	const unsigned char *p = (const unsigned char *)der.constData();
	PKCS8_PRIV_KEY_INFO *p8 = d2i_PKCS8_PRIV_KEY_INFO(nullptr, &p, der.size());
	if (!p8)
		return -1;
	const unsigned char *pk = nullptr;
	int len = 0;
	PKCS8_pkey_get0(nullptr, &pk, &len, nullptr, p8);
	int tag = len > 0 ? pk[0] : -1;
	PKCS8_PRIV_KEY_INFO_free(p8);
	return tag;
}

void test_main::exportMlDsaEncoding()
{
	try {
		openDB();
		ServiceContext ctx(ServiceContext::cli, "os:test");
		db_key *keys = Database.model<db_key>();
		pki_key *ml = keys->newKey(keyjob("ML-DSA-44"), "ml-dsa key");
		QVERIFY(ml);

		/* visible only where an ML-DSA private key is written */
		ExportDialog *dlg = dialogFor(ml);
		QVERIFY2(dlg->findChild<QComboBox *>("mlDsaFormat"),
			"no combo mlDsaFormat in the export dialog");
		for (int f : { keyPemPrivate, keyDerPrivate, keyPkcs8,
				keyPkcs8Encrypted })
			QVERIFY2(comboShown(dlg, f), qPrintable(QString::number(f)));
		for (int f : { keyPemPublic, keyDerPublic })
			QVERIFY2(!comboShown(dlg, f), qPrintable(QString::number(f)));

		/* each value: the PKCS#8 structure and the audit entry */
		QComboBox *combo = dlg->findChild<QComboBox *>("mlDsaFormat");
		QTemporaryDir dir;
		const QList<QPair<QString, int> > encodings {
			{ "both", 0x30 }, { "seed", 0x80 }, { "expanded", 0x04 } };
		for (const auto &e : encodings) {
			QVERIFY(comboShown(dlg, keyDerPrivate));
			int row = combo->findData(e.first);
			QVERIFY2(row >= 0, qPrintable(e.first));
			combo->setCurrentIndex(row);
			ExportSpec spec = dlg->exportSpec({ ml });
			QCOMPARE(spec.privateKeyFormat, e.first);
			spec.fileName = dir.filePath(e.first + ".der");
			keys->exportItems(ctx, spec);
			QCOMPARE(privateKeyTag(spec.fileName), e.second);
			QList<AuditEntry> all = AuditLog::entries();
			QVERIFY(!all.isEmpty());
			QCOMPARE(all.last().action, QString("key.export_private"));
			QCOMPARE(all.last().params.value("ml_dsa_encoding").toString(),
				e.first);
		}
		/* the default leaves the service default */
		combo->setCurrentIndex(combo->findData(QString()));
		QVERIFY(dlg->exportSpec({ ml }).privateKeyFormat.isEmpty());
		delete dlg;

		/* hidden for the other key types */
		for (const char *job : { "RSA:2048", "EC:prime256v1", "ED25519",
					"SLH-DSA-SHA2-128f" }) {
			pki_key *other = keys->newKey(keyjob(job), job);
			QVERIFY(other);
			dlg = dialogFor(other);
			QVERIFY2(!comboShown(dlg, keyPemPrivate), job);
			delete dlg;
		}

		/* a certificate with an ML-DSA key: PKCS#12 and PEM + key */
		IssuanceSpec spec;
		spec.name = "ml-dsa cert";
		spec.subject.addEntryByNid(NID_commonName, spec.name);
		spec.key = ml;
		spec.notBefore = a1time(QDateTime::currentDateTimeUtc().addDays(-1));
		spec.notAfter = a1time(QDateTime::currentDateTimeUtc().addYears(1));
		spec.extensions.basicCA = ExtensionSpec::bc_ca;
		spec.extensions.keyUsage << "keyCertSign" << "cRLSign";
		pki_x509 *cert = Database.model<db_x509>()->newCert(ctx, spec);
		QVERIFY(cert);
		dlg = dialogFor(cert);
		QVERIFY(comboShown(dlg, certPkcs12));
		QVERIFY(comboShown(dlg, certPemKey));
		QVERIFY(!comboShown(dlg, certPem));
		delete dlg;
	} catch (errorEx &err) {
		QVERIFY2(false, CCHAR(err.getString()));
	}
}
