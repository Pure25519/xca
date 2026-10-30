/* vi: set sw=4 ts=4:
 *
 * The default templates of misc/ against every key type (BTD-203): each
 * shipped template issues for the key types its key usage fits and is
 * refused with key_usage_not_for_key_type, naming the template, for the
 * others (BTD-195). Every *.xca in misc/ must be listed here, so a new
 * default template cannot ship untested. Before BTD-203 TLS_server and
 * TLS_client (keyEncipherment and keyAgreement together) fitted no key
 * type at all; the BTD-195 tests used their own templates only.
 */

#include <QDir>

#include "lib/audit.h"
#include "lib/db_key.h"
#include "lib/db_x509.h"
#include "lib/exception.h"
#include "lib/issuance_checks.h"
#include "lib/load_obj.h"
#include "lib/pki_temp.h"
#include "lib/pki_x509.h"
#include "lib/template.h"

#include "ServiceTestCase.h"

class test_service_default_templates : public ServiceTestCase
{
	Q_OBJECT

	ServiceContext ctx{ ServiceContext::cli, "os:service-test" };

	/* template -> the key jobs it must issue for */
	static const QMap<QString, QStringList> &fits()
	{
		static const QStringList all { "RSA:2048", "EC:prime256v1",
				"ED25519", "ML-DSA-65" };
		static const QMap<QString, QStringList> f {
			{ "CA", all },
			{ "TLS_server", { "RSA:2048" } },
			{ "TLS_client", { "RSA:2048" } },
			{ "TLS_server_EC", all },
			{ "TLS_client_EC", all },
		};
		return f;
	}

  private slots:
	void everyTemplateListed();
	void issueByKeyType_data();
	void issueByKeyType();
};

void test_service_default_templates::everyTemplateListed()
{
	QStringList shipped;
	for (const QFileInfo &f : QDir(XCA_SOURCE_DIR "/misc").entryInfoList(
			QStringList("*.xca"), QDir::Files))
		shipped << f.completeBaseName();
	shipped.sort();
	QStringList listed = fits().keys();
	listed.sort();
	QCOMPARE(shipped, listed);
}

void test_service_default_templates::issueByKeyType_data()
{
	QTest::addColumn<QString>("file");
	QTest::addColumn<QString>("job");
	QTest::addColumn<bool>("fits");
	for (const QString &file : fits().keys()) {
		for (const char *job : { "RSA:2048", "EC:prime256v1", "ED25519",
					"ML-DSA-65" }) {
			QTest::newRow(CCHAR(file + " " + job)) << file
				<< QString(job) << fits()[file].contains(job);
		}
	}
}

void test_service_default_templates::issueByKeyType()
{
	QFETCH(QString, file);
	QFETCH(QString, job);
	QFETCH(bool, fits);

	db_key *keys = Database.model<db_key>();
	IssuanceSpec c;
	c.name = "Template CA";
	c.subject.addEntryByNid(NID_commonName, c.name);
	c.key = keys->newKey(keyjob("RSA:3072"), c.name);
	c.notBefore = a1time(QDateTime::currentDateTimeUtc().addDays(-1));
	c.notAfter = a1time(QDateTime::currentDateTimeUtc().addYears(10));
	c.hashAlgo = digest(NID_sha256);
	c.extensions.basicCA = ExtensionSpec::bc_ca;
	c.extensions.keyUsage << "keyCertSign" << "cRLSign";
	pki_x509 *ca = Database.model<db_x509>()->newCert(ctx, c);
	QVERIFY(ca);

	load_temp l;
	pki_temp *temp = dynamic_cast<pki_temp *>(l.loadItem(
			QString(XCA_SOURCE_DIR "/misc/%1.xca").arg(file)));
	QVERIFY(temp);
	QCOMPARE(temp->getIntName(), file);
	TemplateSpec t = TemplateSpec::fromTemplate(temp);
	delete temp;

	IssuanceSpec s;
	t.applyTo(s, a1time());
	s.name = "by " + file;
	s.subject = x509name();
	s.subject.addEntryByNid(NID_commonName, "host.example");
	s.key = keys->newKey(keyjob(job), "key " + job);
	QVERIFY(s.key);
	s.signer = ca;
	s.hashAlgo = digest(NID_sha256);
	QString code, detail;
	pki_x509 *cert = nullptr;
	try {
		cert = Database.model<db_x509>()->newCert(ctx, s);
	} catch (serviceError &e) {
		code = e.code;
		detail = e.getString();
	}
	if (!fits) {
		QCOMPARE(code, QString("key_usage_not_for_key_type"));
		QVERIFY2(detail.contains("template '" + file + "'"), CCHAR(detail));
		QVERIFY(!cert);
		return;
	}
	QVERIFY2(code.isEmpty(), CCHAR(code + ": " + detail));
	QVERIFY(cert);
	/* only bits the key can use, and exactly the template's */
	ASN1_BIT_STRING *ku = (ASN1_BIT_STRING *)X509_get_ext_d2i(
			cert->getCert(), NID_key_usage, nullptr, nullptr);
	QVERIFY(ku);
	QStringList bits;
	for (int b = 0; b < TemplateSpec::keyUsageNames.size(); b++) {
		if (ASN1_BIT_STRING_get_bit(ku, b))
			bits << TemplateSpec::keyUsageNames[b];
	}
	ASN1_BIT_STRING_free(ku);
	QCOMPARE(bits, t.extensions.keyUsage);
	QCOMPARE(IssuanceChecks::keyUsageUnfit(X509_get0_pubkey(cert->getCert()),
			bits), QStringList());
}

XCA_SERVICE_TEST_MAIN(test_service_default_templates)
#include "test_service_default_templates.moc"
