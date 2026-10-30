/* vi: set sw=4 ts=4:
 *
 * The extensions the New Certificate dialog builds (BTD-31): every
 * extension tab filled in, built into a certificate with getAllExt().
 * The expected text was produced by the code before BTD-31 moved the
 * extension building into lib/issuance.cpp; it must not change.
 */

#include <QTest>
#include <QRegularExpression>

#include <openssl/evp.h>
#include <openssl/x509v3.h>

#include "lib/oid.h"
#include "lib/pki_evp.h"
#include "lib/pki_x509.h"
#include "lib/settings.h"
#include "lib/x509name.h"
#include "widgets/MainWindow.h"
#include "widgets/NewX509.h"

#include "main.h"

static QString extensionDump(X509 *x)
{
	QStringList out;
	for (int i = 0; i < X509_get_ext_count(x); i++) {
		const X509_EXTENSION *ext = X509_get_ext(x, i);
		char oid[80];
		OBJ_obj2txt(oid, sizeof oid, X509_EXTENSION_get_object(ext), 1);
		BIO *b = BIO_new(BIO_s_mem());
		X509V3_EXT_print(b, ext, X509V3_EXT_DUMP_UNKNOWN, 0);
		char *data;
		long len = BIO_get_mem_data(b, &data);
		QString val = QString::fromUtf8(data, len).trimmed();
		BIO_free(b);
		/* key identifiers depend on the generated keys */
		val.replace(QRegularExpression("([0-9A-F]{2}:){4,}[0-9A-F]{2}"),
				"<keyid>");
		out << QString("%1%2: %3").arg(oid)
			.arg(X509_EXTENSION_get_critical(ext) ? " critical" : "")
			.arg(val);
	}
	return out.join("\n");
}

static pki_key *ecKey()
{
	return new pki_evp(EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256"));
}

static bool selectRows(QListWidget *l, QList<int> rows)
{
	for (int r : rows) {
		if (r >= l->count()) {
			qWarning() << l->objectName() << "has" << l->count() << "rows";
			return false;
		}
		l->item(r)->setSelected(true);
	}
	return true;
}

void test_main::issuanceExtensions()
{
	try {
		openDB();
		Settings["disable_netscape"] = false;
		pki_key *caKey = ecKey(), *eeKey = ecKey();

		x509name n;
		n.addEntryByNid(NID_commonName, "Ext CA");
		pki_x509 *ca = new pki_x509();
		ca->setSubject(n);
		ca->setIssuer(n);
		ca->setPubKey(caKey);
		X509V3_CTX c{};
		X509V3_set_ctx_nodb(&c);
		X509V3_set_ctx(&c, ca->getCert(), ca->getCert(), NULL, NULL, 0);
		x509v3ext(NID_subject_key_identifier, "hash", &c);

		/* eku.txt is not installed for the tests */
		NIDlist ekuSaved = extkeyuse_nid;
		extkeyuse_nid = NIDlist() << NID_server_auth << NID_client_auth;
		NewX509 *dlg = new NewX509(mainwin);
		dlg->setCert();
		dlg->basicCA->setCurrentIndex(1);
		dlg->bcCritical->setChecked(true);
		dlg->basicPath->setText("2");
		dlg->subKey->setChecked(true);
		dlg->authKey->setEnabled(true);
		dlg->authKey->setChecked(true);
		QVERIFY(selectRows(dlg->keyUsage, { 0, 2, 5, 6 }));
		dlg->kuCritical->setChecked(true);
		QVERIFY(selectRows(dlg->ekeyUsage, { 0, 1 }));
		dlg->ekuCritical->setChecked(false);
		dlg->nameCons->setText("permitted;DNS:.example.com");
		dlg->subAltName->setText("DNS:a.example.com, IP:10.1.2.3, "
			"email:a@example.com, URI:urn:bxc:a, "
			"URI:tag:example.com,2026:a");
		dlg->issAltName->setText("DNS:ca.example.com");
		dlg->crlDist->setText("URI:http://crl.example.com/ca.crl");
		dlg->authInfAcc->setText("OCSP;URI:http://ocsp.example.com, "
			"caIssuers;URI:http://ca.example.com/ca.crt");
		dlg->OCSPstaple->setChecked(true);
		dlg->nconf_data->setPlainText(
			"certificatePolicies = 1.3.6.1.4.1.99999.1.2\n"
			"1.3.6.1.4.1.99999.7 = ASN1:UTF8String:bxc\n");
		QVERIFY(selectRows(dlg->nsCertType, { 0, 1 }));
		dlg->nsComment->setText("ns comment");
		dlg->nsBaseUrl->setText("http://ns.example.com/");

		/* Signed by the CA: only now, the check icons of the line
		 * edits above would look for a selected signer */
		dlg->foreignSignRB->setChecked(true);

		x509name en;
		en.addEntryByNid(NID_commonName, "a.example.com");
		pki_x509 *cert = new pki_x509();
		cert->setSubject(en);
		cert->setPubKey(eeKey);
		dlg->initCtx(cert, ca, nullptr);
		cert->setIssuer(ca->getSubject());
		dlg->getAllExt();

		QString dump = extensionDump(cert->getCert());
		qInfo().noquote() << "EXTENSIONS\n" << dump;
		QCOMPARE(dump, QString(
"2.5.29.19 critical: CA:TRUE, pathlen:2\n"
"2.5.29.14: <keyid>\n"
"2.5.29.35: <keyid>\n"
"2.5.29.15 critical: Digital Signature, Key Encipherment, Certificate Sign, CRL Sign\n"
"2.5.29.37: TLS Web Server Authentication, TLS Web Client Authentication\n"
"2.5.29.30: Permitted:\n  DNS:.example.com\n"
"2.5.29.17: DNS:a.example.com, IP Address:10.1.2.3, email:a@example.com, URI:urn:bxc:a, URI:tag:example.com,2026:a\n"
"2.5.29.18: DNS:ca.example.com\n"
"2.5.29.31: Full Name:\n  URI:http://crl.example.com/ca.crl\n"
"1.3.6.1.5.5.7.1.1: OCSP - URI:http://ocsp.example.com\nCA Issuers - URI:http://ca.example.com/ca.crt\n"
"1.3.6.1.5.5.7.1.24: status_request\n"
"2.5.29.32: Policy: 1.3.6.1.4.1.99999.1.2\n"
"1.3.6.1.4.1.99999.7: 0000 - 0c 03 62 78 63                                    ..bxc\n"
"2.16.840.1.113730.1.1: SSL Client, SSL Server\n"
"2.16.840.1.113730.1.2: http://ns.example.com/\n"
"2.16.840.1.113730.1.13: ns comment"));

		delete dlg;
		extkeyuse_nid = ekuSaved;
		delete cert;
		delete ca;
		delete caKey;
		delete eeKey;
	} catch (errorEx &err) {
		QVERIFY2(false, CCHAR(err.getString()));
	}
}

/* The extension line edits are checked on every key (BTD-197): a prefix
 * that OpenSSL cannot encode shows the warning icon. Since BTD-197 the
 * build throws for such input; uncaught in the textChanged slot it was an
 * error box on the first key typed. The icon state is its accessible
 * name, "valid" or "invalid". */
void test_main::lineExtensionTyping()
{
	try {
		openDB();
		NewX509 *dlg = new NewX509(mainwin);
		dlg->setCert();
		struct {
			QLineEdit *edit;
			QLabel *icon;
			QString text;
			bool valid;
		} typed[] = {
			{ dlg->subAltName, dlg->subAltIco, "DNS:plc10", true },
			{ dlg->subAltName, dlg->subAltIco, "IP:300.1.1.1", false },
			{ dlg->issAltName, dlg->issAltIco, "DNS:ca.plc10", true },
			{ dlg->nameCons, dlg->nameConsIco, "permitted;DNS:.plc", true },
			{ dlg->crlDist, dlg->crlDistIco,
				"URI:http://crl.plc/ca.crl", true },
			{ dlg->authInfAcc, dlg->authInfAccIco,
				"OCSP;URI:http://ocsp.plc", true },
		};
		for (const auto &t : typed) {
			t.edit->clear();
			QCOMPARE(t.icon->accessibleName(), QString());
			QStringList states;
			/* one textChanged per key, as typed */
			for (int i = 1; i <= t.text.size(); i++) {
				t.edit->setText(t.text.left(i));
				states << t.icon->accessibleName();
			}
			QVERIFY2(states.first() == "invalid",
				CCHAR(t.text + ": " + states.join(",")));
			QCOMPARE(states.last(),
				QString(t.valid ? "valid" : "invalid"));
		}
		delete dlg;
	} catch (errorEx &err) {
		QVERIFY2(false, CCHAR(err.getString()));
	}
}
