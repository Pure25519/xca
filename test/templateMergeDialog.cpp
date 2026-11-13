/* vi: set sw=4 ts=4:
 *
 * The template dialog shows and saves the request merge settings of
 * BTD-54 (BTD-185): one mode per extension (SAN, key usage, EKU), the
 * EKU allow-list and the EKU default. A template without them opens as
 * legacy and stays legacy; an EKU default outside the allow-list keeps
 * the dialog open with the service error.
 */

#include <QComboBox>
#include <QLineEdit>

#include "widgets/MainWindow.h"
#include "widgets/NewX509.h"
#include "widgets/XcaWarning.h"
#include "lib/audit.h"
#include "lib/db_key.h"
#include "lib/db_x509req.h"
#include "lib/pki_temp.h"
#include "lib/pki_x509req.h"
#include "lib/request.h"
#include "lib/template.h"

#include "main.h"

static QComboBox *mergeBox(NewX509 *dlg, const char *name)
{
	return dlg->findChild<QComboBox *>(name);
}

static QLineEdit *ekuEdit(NewX509 *dlg, const char *name)
{
	return dlg->findChild<QLineEdit *>(name);
}

static int mode(QComboBox *box)
{
	return box ? box->currentData().toInt() : -1;
}

static void setMode(QComboBox *box, ExtensionSpec::requestMerge m)
{
	box->setCurrentIndex(box->findData((int)m));
}

void test_main::templateMergeShownAndSaved()
{
	pki_temp *temp = new pki_temp("merge dialog template");
	TemplateSpec t = TemplateSpec::fromTemplate(temp);
	t.extensions.sanMerge = ExtensionSpec::merge_union;
	t.extensions.kuMerge = ExtensionSpec::merge_template;
	t.extensions.ekuMerge = ExtensionSpec::merge_request;
	t.extensions.ekuAllowed << "serverAuth" << "clientAuth";
	t.extensions.ekuDefault << "clientAuth";
	t.toTemplate(temp);

	NewX509 *dlg = new NewX509(mainwin);
	dlg->setTemp(temp, true);
	QComboBox *san = mergeBox(dlg, "reqSanMerge"),
		  *ku = mergeBox(dlg, "reqKuMerge"),
		  *eku = mergeBox(dlg, "reqEkuMerge");
	QLineEdit *allowed = ekuEdit(dlg, "ekuAllowed"),
		  *def = ekuEdit(dlg, "ekuDefault");
	QVERIFY(san && ku && eku && allowed && def);
	QCOMPARE(san->count(), 4);
	QCOMPARE(mode(san), (int)ExtensionSpec::merge_union);
	QCOMPARE(mode(ku), (int)ExtensionSpec::merge_template);
	QCOMPARE(mode(eku), (int)ExtensionSpec::merge_request);
	QCOMPARE(allowed->text(), QString("serverAuth, clientAuth"));
	QCOMPARE(def->text(), QString("clientAuth"));

	setMode(san, ExtensionSpec::merge_template);
	setMode(ku, ExtensionSpec::merge_union);
	setMode(eku, ExtensionSpec::merge_legacy);
	allowed->setText("TLS Web Server Authentication, 1.3.6.1.4.1.99999.1");
	def->setText("");
	dlg->toTemplate(temp);
	delete dlg;

	TemplateSpec back = TemplateSpec::fromTemplate(temp);
	QCOMPARE(back.extensions.sanMerge, ExtensionSpec::merge_template);
	QCOMPARE(back.extensions.kuMerge, ExtensionSpec::merge_union);
	QCOMPARE(back.extensions.ekuMerge, ExtensionSpec::merge_legacy);
	QCOMPARE(back.extensions.ekuAllowed, QStringList({
		"TLS Web Server Authentication", "1.3.6.1.4.1.99999.1" }));
	QVERIFY(back.extensions.ekuDefault.isEmpty());
	delete temp;
}

/* A template from before BTD-54 opens as legacy and is saved unchanged */
void test_main::templateMergeLegacyKept()
{
	pki_temp *temp = new pki_temp("old template");
	QStringList keys { "reqSan", "reqKu", "reqEku", "ekuAllowed",
			   "ekuDefault" };
	QStringList before;
	for (const QString &k : keys)
		before << temp->getSetting(k);

	NewX509 *dlg = new NewX509(mainwin);
	dlg->setTemp(temp, true);
	for (const char *name : { "reqSanMerge", "reqKuMerge", "reqEkuMerge" }) {
		QComboBox *box = mergeBox(dlg, name);
		QVERIFY2(box, name);
		QCOMPARE(mode(box), (int)ExtensionSpec::merge_legacy);
	}
	QVERIFY(ekuEdit(dlg, "ekuAllowed"));
	QVERIFY(ekuEdit(dlg, "ekuAllowed")->text().isEmpty());
	QVERIFY(ekuEdit(dlg, "ekuDefault")->text().isEmpty());
	dlg->toTemplate(temp);
	delete dlg;

	QStringList after;
	for (const QString &k : keys)
		after << temp->getSetting(k);
	QCOMPARE(after, before);
	delete temp;
}

static QString mergeBoxText;

/* An EKU default outside the allow-list: the dialog shows the service
 * error and stays open */
void test_main::templateMergeDefaultRefused()
{
	pki_temp *temp = new pki_temp("refused template");
	NewX509 *dlg = new NewX509(mainwin);
	dlg->setTemp(temp, true);
	QLineEdit *allowed = ekuEdit(dlg, "ekuAllowed"),
		  *def = ekuEdit(dlg, "ekuDefault");
	QVERIFY(allowed && def);
	allowed->setText("serverAuth");
	def->setText("clientAuth");

	mergeBoxText.clear();
	whenShown<xcaWarningBox>("dlg_warning", [](xcaWarningBox *box) {
		mergeBoxText = box->text();
		box->button(QMessageBox::Ok)->click();
	});
	dlg->accept();
	QVERIFY2(mergeBoxText.contains("clientAuth") &&
		 mergeBoxText.contains("ekuAllowed"), CCHAR(mergeBoxText));
	QVERIFY(dlg->result() != QDialog::Accepted);
	delete dlg;
	delete temp;
}

void test_main::templateEkuUnknownRefused_data()
{
	QTest::addColumn<QString>("allowed");
	QTest::addColumn<QString>("def");
	/* the field and entry the warning names; empty: accepted */
	QTest::addColumn<QString>("field");
	QTest::addColumn<QString>("entry");
	QTest::newRow("unknown in ekuAllowed") << "serverAuth, serverAuthh"
		<< "" << "ekuAllowed" << "serverAuthh";
	QTest::newRow("unknown in ekuDefault") << "" << "clientAuthh"
		<< "ekuDefault" << "clientAuthh";
	QTest::newRow("long name and OID accepted")
		<< "TLS Web Client Authentication, 1.3.6.1.5.5.7.3.1"
		<< "clientAuth" << "" << "";
}

/* An EKU name OpenSSL does not know (BTD-192 AC2, GUI part): the dialog
 * shows the template_eku_unknown error of the service check, naming the
 * field and the entry, stays open and changes nothing; short names, long
 * names and dotted OIDs are accepted */
void test_main::templateEkuUnknownRefused()
{
	QFETCH(QString, allowed);
	QFETCH(QString, def);
	QFETCH(QString, field);
	QFETCH(QString, entry);

	pki_temp *temp = new pki_temp("eku names template");
	QString beforeAllowed = temp->getSetting("ekuAllowed"),
		beforeDefault = temp->getSetting("ekuDefault");
	NewX509 *dlg = new NewX509(mainwin);
	dlg->setTemp(temp, true);
	QLineEdit *allowedEdit = ekuEdit(dlg, "ekuAllowed"),
		  *defEdit = ekuEdit(dlg, "ekuDefault");
	QVERIFY(allowedEdit && defEdit);
	allowedEdit->setText(allowed);
	defEdit->setText(def);

	mergeBoxText.clear();
	if (!field.isEmpty()) {
		whenShown<xcaWarningBox>("dlg_warning", [](xcaWarningBox *box) {
			mergeBoxText = box->text();
			box->button(QMessageBox::Ok)->click();
		});
	}
	dlg->accept();
	if (field.isEmpty()) {
		QVERIFY2(mergeBoxText.isEmpty(), CCHAR(mergeBoxText));
		QCOMPARE(dlg->result(), (int)QDialog::Accepted);
	} else {
		/* the text of template_eku_unknown (ExtensionSpec::checkEkuNames) */
		QVERIFY2(mergeBoxText.contains(QString("%1: '%2' is no known "
			"extended key usage").arg(field, entry)),
			CCHAR(mergeBoxText));
		QVERIFY(dlg->result() != QDialog::Accepted);
		QCOMPARE(temp->getSetting("ekuAllowed"), beforeAllowed);
		QCOMPARE(temp->getSetting("ekuDefault"), beforeDefault);
	}
	delete dlg;
	delete temp;
}

/* Signing a request with a template whose SAN mode merges: the dialog's
 * check does not count the request's SAN as a duplicate, the issuance
 * merges both into one (found by the GUI case gui.template.request_merge).
 * With legacy, a copied SAN next to the template's stays a duplicate. */
void test_main::templateMergeNoDuplicate()
{
	try {
		openDB();
		ServiceContext ctx(ServiceContext::cli, "os:test");
		RequestSpec r;
		r.name = "merge request";
		r.subject.addEntryByNid(NID_commonName, "req.example");
		r.key = Database.model<db_key>()->newKey(keyjob("EC:prime256v1"),
				"merge request key");
		r.hashAlgo = digest(NID_sha256);
		r.extensions.subjectAltName = "DNS:req.example";
		pki_x509req *req = Database.model<db_x509req>()->newRequest(ctx, r);
		QVERIFY(req);

		for (ExtensionSpec::requestMerge m : { ExtensionSpec::merge_union,
					ExtensionSpec::merge_legacy }) {
			pki_temp *temp = new pki_temp("merge SAN template");
			TemplateSpec t = TemplateSpec::fromTemplate(temp);
			t.extensions.subjectAltName = "DNS:tmpl.example";
			t.extensions.sanMerge = m;
			t.toTemplate(temp);

			NewX509 *dlg = new NewX509(mainwin);
			dlg->setCert();
			dlg->defineRequest(req);
			dlg->defineTemplate(temp);
			dlg->copyReqExtCB->setChecked(true);
			QString result;
			int ee = dlg->validateExtensions(result);
			delete dlg;
			delete temp;
			if (m == ExtensionSpec::merge_union)
				QVERIFY2(ee == 0, CCHAR(result));
			else
				QVERIFY2(ee != 0, CCHAR(result));
		}
	} catch (errorEx &err) {
		QVERIFY2(false, CCHAR(err.getString()));
	}
}
