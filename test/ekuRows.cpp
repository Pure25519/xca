/* vi: set sw=4 ts=4:
 *
 * Extended key usages in the New Certificate dialog (BTD-215, BTD-127).
 * The EKU list came from eku.txt only: an EKU of a template without a
 * row was dropped without a word, so with a missing or old eku.txt a
 * TLS_server certificate came out without serverAuth, and an own OID
 * was lost. Now such an EKU gets a row marked as coming from the
 * template, is shown and kept; without eku.txt a built-in list is used.
 * Applying a second template replaces the EKUs of the first instead of
 * adding to them, as the service path (TemplateSpec::applyTo) does.
 */

#include <QListWidget>

#include "widgets/MainWindow.h"
#include "widgets/NewX509.h"
#include "lib/audit.h"
#include "lib/db_key.h"
#include "lib/db_x509.h"
#include "lib/issuance.h"
#include "lib/load_obj.h"
#include "lib/oid.h"
#include "lib/pki_temp.h"
#include "lib/pki_x509.h"
#include "lib/template.h"

#include "main.h"

/* the EKUs of a certificate as OpenSSL prints them (openssl x509 -text) */
static QString ekuText(pki_x509 *cert)
{
	X509 *x = cert->getCert();
	int at = X509_get_ext_by_NID(x, NID_ext_key_usage, -1);
	if (at < 0)
		return QString();
	BioByteArray b;
	X509V3_EXT_print(b, X509_get_ext(x, at), X509V3_EXT_DUMP_UNKNOWN, 0);
	return b.qstring();
}

/* the shown texts of the selected EKU rows */
static QStringList selectedEkus(NewX509 *dlg)
{
	QStringList s;
	for (QListWidgetItem *it : dlg->ekeyUsage->selectedItems())
		s << it->text();
	return s;
}

static pki_temp *ekuTemplate(const QString &name, const QStringList &ekus)
{
	pki_temp *temp = new pki_temp(name);
	TemplateSpec t = TemplateSpec::fromTemplate(temp);
	t.extensions.basicCA = ExtensionSpec::bc_not_ca;
	t.extensions.keyUsage << "digitalSignature";
	t.extensions.extKeyUsage = ekus;
	t.toTemplate(temp);
	return temp;
}

/* issues what the dialog shows, as accept() of the certificate view does */
static pki_x509 *issue(NewX509 *dlg, pki_x509 *ca, pki_key *key,
			const QString &name)
{
	dlg->defineSigner(ca, false);
	dlg->keyList->setCurrentPkiItem(key);
	x509name n;
	n.addEntryByNid(NID_commonName, "host.example");
	dlg->setX509name(n);
	dlg->description->setText(name);
	dlg->notBefore->setDate(a1time());
	dlg->notAfter->setDate(a1time(QDateTime::currentDateTimeUtc().addYears(1)));
	return Database.model<db_x509>()->newCert(
		ServiceContext::localUser(ServiceContext::gui),
		dlg->getIssuanceSpec());
}

void test_main::ekuRows_data()
{
	QTest::addColumn<QString>("list");
	QTest::newRow("eku.txt hidden") << "none";
	QTest::newRow("eku.txt without serverAuth") << "clientAuth";
}

/* the shipped TLS_server template with an empty or reduced EKU list */
void test_main::ekuRows()
{
	QFETCH(QString, list);
	NIDlist saved = extkeyuse_nid;
	try {
		openDB();
		ServiceContext ctx(ServiceContext::cli, "os:test");
		db_key *keys = Database.model<db_key>();
		IssuanceSpec spec;
		spec.name = "EKU CA";
		spec.subject.addEntryByNid(NID_commonName, spec.name);
		spec.key = keys->newKey(keyjob("RSA:2048"), "EKU CA key");
		spec.notBefore = a1time(QDateTime::currentDateTimeUtc().addDays(-1));
		spec.notAfter = a1time(QDateTime::currentDateTimeUtc().addYears(2));
		spec.hashAlgo = digest(NID_sha256);
		spec.extensions.basicCA = ExtensionSpec::bc_ca;
		spec.extensions.keyUsage << "keyCertSign" << "cRLSign";
		pki_x509 *ca = Database.model<db_x509>()->newCert(ctx, spec);
		QVERIFY(ca);
		pki_key *key = keys->newKey(keyjob("RSA:2048"), "server key");

		extkeyuse_nid = list == "none" ? NIDlist() :
				NIDlist() << NID_client_auth;
		load_temp l;
		pki_temp *temp = dynamic_cast<pki_temp *>(l.loadItem(
			XCA_SOURCE_DIR "/misc/TLS_server.xca"));
		QVERIFY(temp);
		NewX509 *dlg = new NewX509(mainwin);
		dlg->setCert();
		dlg->defineTemplate(temp);
		delete temp;
		QStringList shown = selectedEkus(dlg);
		QVERIFY2(shown.join(",").contains("TLS Web Server Authentication"),
			CCHAR(shown.join(",")));
		pki_x509 *cert = issue(dlg, ca, key, "tls server");
		QVERIFY(cert);
		QCOMPARE(ekuText(cert), QString("TLS Web Server Authentication"));
		delete dlg;
	} catch (errorEx &err) {
		extkeyuse_nid = saved;
		QVERIFY2(false, CCHAR(err.getString()));
	}
	extkeyuse_nid = saved;
}

/* an own EKU OID of a template is kept and shown; a second template
 * replaces the EKUs of the first (BTD-127), as the service path does */
void test_main::ekuOwnOidAndReplace()
{
	NIDlist saved = extkeyuse_nid;
	try {
		openDB();
		ServiceContext ctx(ServiceContext::cli, "os:test");
		db_key *keys = Database.model<db_key>();
		IssuanceSpec spec;
		spec.name = "EKU CA";
		spec.subject.addEntryByNid(NID_commonName, spec.name);
		spec.key = keys->newKey(keyjob("RSA:2048"), "EKU CA key");
		spec.notBefore = a1time(QDateTime::currentDateTimeUtc().addDays(-1));
		spec.notAfter = a1time(QDateTime::currentDateTimeUtc().addYears(2));
		spec.hashAlgo = digest(NID_sha256);
		spec.extensions.basicCA = ExtensionSpec::bc_ca;
		spec.extensions.keyUsage << "keyCertSign" << "cRLSign";
		pki_x509 *ca = Database.model<db_x509>()->newCert(ctx, spec);
		QVERIFY(ca);
		pki_key *key = keys->newKey(keyjob("RSA:2048"), "ee key");
		extkeyuse_nid = NIDlist() << NID_server_auth << NID_client_auth;

		/* an own OID */
		pki_temp *own = ekuTemplate("own", { "serverAuth",
					"1.3.6.1.4.1.99999.3" });
		NewX509 *dlg = new NewX509(mainwin);
		dlg->setCert();
		dlg->defineTemplate(own);
		QStringList shown = selectedEkus(dlg);
		QVERIFY2(shown.join(",").contains("1.3.6.1.4.1.99999.3 (from the template)"),
			CCHAR(shown.join(",")));
		pki_x509 *cert = issue(dlg, ca, key, "own oid");
		QVERIFY(cert);
		QCOMPARE(ekuText(cert), QString(
			"TLS Web Server Authentication, 1.3.6.1.4.1.99999.3"));
		delete dlg;

		/* template A, then template B in the same dialog */
		pki_temp *a = ekuTemplate("A", { "serverAuth" });
		pki_temp *b = ekuTemplate("B", { "clientAuth" });
		dlg = new NewX509(mainwin);
		dlg->setCert();
		dlg->defineTemplate(own);
		dlg->defineTemplate(a);
		dlg->defineTemplate(b);
		QCOMPARE(selectedEkus(dlg), QStringList("TLS Web Client Authentication"));
		/* the row of the own OID went with its template */
		QCOMPARE(dlg->ekeyUsage->count(), 2);
		pki_x509 *byDialog = issue(dlg, ca, keys->newKey(keyjob("RSA:2048"),
					"key b"), "by dialog");
		QVERIFY(byDialog);
		QCOMPARE(ekuText(byDialog), QString("TLS Web Client Authentication"));
		delete dlg;

		/* the service path with template B gives the same EKU */
		IssuanceSpec s;
		TemplateSpec::fromTemplate(b).applyTo(s, a1time());
		s.name = "by service";
		s.subject.addEntryByNid(NID_commonName, "host.example");
		s.key = key;
		s.signer = ca;
		s.hashAlgo = digest(NID_sha256);
		pki_x509 *byService = Database.model<db_x509>()->newCert(ctx, s);
		QVERIFY(byService);
		QCOMPARE(ekuText(byService), ekuText(byDialog));
		delete own;
		delete a;
		delete b;
	} catch (errorEx &err) {
		extkeyuse_nid = saved;
		QVERIFY2(false, CCHAR(err.getString()));
	}
	extkeyuse_nid = saved;
}

/* without eku.txt: the built-in list, and the dialog says so */
void test_main::ekuBuiltInList()
{
	for (int nid : { NID_server_auth, NID_client_auth, NID_code_sign,
			NID_email_protect, NID_time_stamp, NID_OCSP_sign })
		QVERIFY2(ekuListAtStart.contains(nid), OBJ_nid2sn(nid));
	NIDlist saved = extkeyuse_nid;
	extkeyuse_nid = ekuListAtStart;
	openDB();
	NewX509 *dlg = new NewX509(mainwin);
	QCOMPARE(dlg->ekeyUsage->count(), (int)ekuListAtStart.size());
	QVERIFY2(dlg->ekeyUsage->toolTip().contains("eku.txt"),
		CCHAR(dlg->ekeyUsage->toolTip()));
	delete dlg;
	extkeyuse_nid = saved;
}
