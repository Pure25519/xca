/* vi: set sw=4 ts=4:
 *
 * Test helper for the bxc-pki CLI tests (BTD-41, BTD-42): prepares what
 * the command line cannot create itself, through the service layer.
 *
 * cli_fixture <database> <password source> template <name> <eku,...> [<ku,...>]
 *     a template (db_temp::newTemplate) with CA:FALSE, the given extended
 *     key usages (short names or dotted OIDs) and key usages, period 1 year
 *
 * cli_fixture <database> <password source> ownpass <key> [<key password source>]
 *     gives the key a password of its own (pki_key::ptPrivate): the one of
 *     the key password source, by default the database password
 *     (BTD-42: a password-protected CA key)
 *
 * cli_fixture <database> <password source> revocations <ca> <count>
 *     adds count revocations of serials without a certificate
 *     (db_x509::setRevocations), e.g. for a CRL above a size budget
 *
 * cli_fixture <database> <password source> guicrl <ca>
 *     issues a CRL the way the GUI does (NewCrl::newCrl(), xca --crlgen:
 *     crljob(ca) with the CA's crlDays, db_crl::newCrl() on the gui
 *     channel) and prints "<thisUpdate> <nextUpdate> <seconds between>"
 *     (BTD-211)
 *
 * Exit code 1 and the message on stderr on any error.
 */

#include <QCoreApplication>
#include <QTextStream>

#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/db_crl.h"
#include "lib/db_temp.h"
#include "lib/db_x509.h"
#include "lib/entropy.h"
#include "lib/oid.h"
#include "lib/pki_crl.h"
#include "lib/pki_evp.h"
#include "lib/pki_x509.h"
#include "lib/PwDialogCore.h"
#include "lib/settings.h"
#include "lib/template.h"
#include "lib/x509rev.h"
#include "lib/XcaWarningCore.h"

static int usage(QTextStream &err)
{
	err << "usage: cli_fixture <db> <password source> template <name> "
		"<eku,...> [<ku,...>] | ownpass <key> [<key password source>] "
		"| revocations <ca> <count> | guicrl <ca>\n";
	return 1;
}

int main(int argc, char *argv[])
{
	QCoreApplication app(argc, argv);
	app.setApplicationName("de.hohnstaedt.xca");
	app.setOrganizationDomain("hohnstaedt.de");
	QStringList args = app.arguments().mid(1);
	QTextStream err(stderr);
	QString cmd = args.value(2);

	if ((cmd == "template" && args.size() < 5) ||
	    (cmd == "ownpass" && (args.size() < 4 || args.size() > 5)) ||
	    (cmd == "revocations" && args.size() != 5) ||
	    (cmd == "guicrl" && args.size() != 4) ||
	    !QStringList({ "template", "ownpass", "revocations", "guicrl" })
			.contains(cmd))
		return usage(err);
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
		ServiceContext ctx = ServiceContext::localUser(
					ServiceContext::cli);

		if (cmd == "ownpass") {
			pki_evp *key = nullptr;
			for (pki_evp *k : Store.getAll<pki_evp>())
				if (k->getIntName() == args[3])
					key = k;
			if (!key)
				throw errorEx("no key " + args[3]);
			if (args.size() > 4)
				h->setSource(pass_info::KeyPassword, args[4]);
			key->setOwnPass(pki_key::ptPrivate);
			if (key->getOwnPass() != pki_key::ptPrivate ||
			    !key->sqlUpdatePrivateKey())
				throw errorEx("key not updated");
		} else if (cmd == "guicrl") {
			pki_x509 *ca = nullptr;
			for (pki_x509 *c : Store.getAll<pki_x509>())
				if (c->getIntName() == args[3])
					ca = c;
			if (!ca)
				throw errorEx("no CA " + args[3]);
			pki_crl *crl = Database.model<db_crl>()->newCrl(
				ServiceContext::localUser(ServiceContext::gui),
				crljob(ca));
			QDateTime t = crl->getLastUpdate(),
				n = crl->getNextUpdate();
			QTextStream(stdout) << t.toString(Qt::ISODate) << " "
				<< n.toString(Qt::ISODate) << " "
				<< t.secsTo(n) << "\n";
		} else if (cmd == "revocations") {
			pki_x509 *ca = nullptr;
			for (pki_x509 *c : Store.getAll<pki_x509>())
				if (c->getIntName() == args[3])
					ca = c;
			if (!ca)
				throw errorEx("no CA " + args[3]);
			x509revList list = ca->getRevList();
			for (int i = 0; i < args[4].toInt(); i++) {
				x509rev r;
				r.setSerial(db_x509::randomSerial());
				r.setDate(a1time());
				r.setReason("Key Compromise");
				list << r;
			}
			Database.model<db_x509>()->setRevocations(ctx, ca, list);
		} else {
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
			Database.model<db_temp>()->newTemplate(ctx, t);
		}
		Database.close();
	} catch (errorEx &e) {
		err << e.getString() << "\n";
		/* before QCoreApplication goes away */
		Database.close();
		return 1;
	} catch (...) {
		err << "failed\n";
		Database.close();
		return 1;
	}
	return 0;
}
