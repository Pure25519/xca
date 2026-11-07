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
#include "lib/pki_temp.h"
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
