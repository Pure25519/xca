/* vi: set sw=4 ts=4:
 *
 * Editing a template in the dialog keeps what the dialog does not show
 * (mr-processor review of xca#47, blocker 2): the merge modes of SAN, key
 * usage and EKU and the EKU limits survive an edit (BTD-54; the dialog
 * shows them with BTD-185).
 */

#include "widgets/MainWindow.h"
#include "widgets/NewX509.h"
#include "lib/pki_temp.h"
#include "lib/template.h"

#include "main.h"

void test_main::templateMergeRoundTrip()
{
	pki_temp *temp = new pki_temp("merge template");
	TemplateSpec t = TemplateSpec::fromTemplate(temp);
	t.extensions.basicCA = ExtensionSpec::bc_not_ca;
	t.extensions.keyUsage << "digitalSignature";
	t.extensions.extKeyUsage << "serverAuth";
	t.extensions.sanMerge = ExtensionSpec::merge_union;
	t.extensions.kuMerge = ExtensionSpec::merge_template;
	t.extensions.ekuMerge = ExtensionSpec::merge_request;
	t.extensions.ekuAllowed << "serverAuth" << "clientAuth";
	t.extensions.ekuDefault << "clientAuth";
	t.toTemplate(temp);

	NewX509 *dlg = new NewX509(mainwin);
	dlg->setTemp(temp, true);
	dlg->description->setText("merge template renamed");
	dlg->toTemplate(temp);
	delete dlg;

	TemplateSpec back = TemplateSpec::fromTemplate(temp);
	QCOMPARE(back.name, QString("merge template renamed"));
	QCOMPARE(back.extensions.sanMerge, ExtensionSpec::merge_union);
	QCOMPARE(back.extensions.kuMerge, ExtensionSpec::merge_template);
	QCOMPARE(back.extensions.ekuMerge, ExtensionSpec::merge_request);
	QCOMPARE(back.extensions.ekuAllowed,
		QStringList({ "serverAuth", "clientAuth" }));
	QCOMPARE(back.extensions.ekuDefault, QStringList{ "clientAuth" });

	/* the certificate dialog issues with them, too */
	dlg = new NewX509(mainwin);
	dlg->setCert();
	dlg->defineTemplate(temp);
	ExtensionSpec e = dlg->getExtensionSpec();
	delete dlg;
	QCOMPARE(e.ekuMerge, ExtensionSpec::merge_request);
	QCOMPARE(e.ekuAllowed, QStringList({ "serverAuth", "clientAuth" }));
	delete temp;
}
