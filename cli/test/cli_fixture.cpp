/* vi: set sw=4 ts=4:
 *
 * Test helper for the bxc-pki CLI tests (BTD-41): prepares what part 1
 * of the command line cannot create itself, through the service layer.
 *
 * cli_fixture <database> <password source> template <name> <eku,...> [<ku,...>]
 *     a template (db_temp::newTemplate) with CA:FALSE, the given extended
 *     key usages (short names or dotted OIDs) and key usages, period 1 year
 *
 * Exit code 1 and the message on stderr on any error.
 */

#include <QCoreApplication>
#include <QTextStream>

#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/db_temp.h"
#include "lib/entropy.h"
#include "lib/oid.h"
#include "lib/PwDialogCore.h"
#include "lib/settings.h"
#include "lib/template.h"
#include "lib/XcaWarningCore.h"

int main(int argc, char *argv[])
{
	QCoreApplication app(argc, argv);
	app.setApplicationName("de.hohnstaedt.xca");
	app.setOrganizationDomain("hohnstaedt.de");
	QStringList args = app.arguments().mid(1);
	QTextStream err(stderr);

	if (args.size() < 5 || args[2] != "template") {
		err << "usage: cli_fixture <db> <password source> template "
			"<name> <eku,...> [<ku,...>]\n";
		return 1;
	}
	xcaWarning::setGui(new xcaWarningCore());
	Entropy entropy;
	Settings.clear();
	try {
		initOIDs();
		PwDialogHeadless *h = PwDialogCore::headless();
		h->setSource(pass_info::DatabasePassword, args[1]);
		h->setSource(pass_info::KeyPassword, args[1]);
		ServiceContext::processChannel = ServiceContext::cli;
		Database.open(args[0]);

		TemplateSpec t;
		t.name = args[3];
		t.extensions.basicCA = ExtensionSpec::bc_not_ca;
		t.extensions.basicCritical = true;
		t.extensions.subjectKeyId = true;
		t.extensions.authorityKeyId = true;
		t.extensions.extKeyUsage = args[4].split(',');
		if (args.size() > 5)
			t.extensions.keyUsage = args[5].split(',');
		t.validity = 1;
		t.unit = TemplateSpec::years;
		Database.model<db_temp>()->newTemplate(
			ServiceContext::localUser(ServiceContext::cli), t);
		Database.close();
	} catch (errorEx &e) {
		err << e.getString() << "\n";
		return 1;
	} catch (...) {
		err << "failed\n";
		return 1;
	}
	return 0;
}
