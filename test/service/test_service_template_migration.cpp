/* vi: set sw=4 ts=4:
 *
 * XCA templates as profiles (BTD-167): each default template of misc/
 * (CA, TLS_server, TLS_client) migrates to a generic profile, and the
 * same CSR issued with the template and with the migrated profile gives
 * identical extensions, compared in the text of openssl x509 -text.
 * Netscape extensions are not migrated (profile.h), so the comparison
 * runs with the setting disable_netscape. A template value a profile
 * cannot hold is refused with the field named, never dropped silently.
 */

#include <QProcess>
#include <QRegularExpression>
#include <QTemporaryDir>

#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/db_key.h"
#include "lib/db_x509.h"
#include "lib/db_x509req.h"
#include "lib/exception.h"
#include "lib/load_obj.h"
#include "lib/pki_temp.h"
#include "lib/pki_x509.h"
#include "lib/pki_x509req.h"
#include "lib/profile.h"
#include "lib/profile_store.h"
#include "lib/template.h"

#include "ServiceTestCase.h"

class test_service_template_migration : public ServiceTestCase
{
	Q_OBJECT

	ServiceContext ctx{ ServiceContext::cli, "os:service-test" };
	QTemporaryDir dir{};

	static pki_temp *defaultTemplate(const QString &file)
	{
		load_temp l;
		return dynamic_cast<pki_temp *>(l.loadItem(
			QString(XCA_SOURCE_DIR "/misc/%1.xca").arg(file)));
	}
	pki_x509 *ca();
	pki_x509req *csr(const QString &type, const QString &cn);
	QString extensionsText(pki_x509 *cert);

  private slots:
	void identicalExtensions_data();
	void identicalExtensions();
	void notMigratable_data();
	void notMigratable();
	void migrateIntoStore();
};

pki_x509 *test_service_template_migration::ca()
{
	IssuanceSpec s;
	s.name = "Migration CA";
	x509name n;
	n.addEntryByNid(NID_commonName, s.name);
	s.subject = n;
	s.key = Database.model<db_key>()->newKey(keyjob("EC:prime256v1"), s.name);
	s.notBefore = a1time(QDateTime::currentDateTimeUtc().addDays(-1));
	s.notAfter = a1time(QDateTime::currentDateTimeUtc().addYears(20));
	s.hashAlgo = digest(NID_sha256);
	s.extensions.basicCA = ExtensionSpec::bc_ca;
	s.extensions.basicCritical = true;
	s.extensions.subjectKeyId = true;
	s.extensions.keyUsage << "keyCertSign" << "cRLSign";
	return Database.model<db_x509>()->newCert(ctx, s);
}

pki_x509req *test_service_template_migration::csr(const QString &type,
			const QString &cn)
{
#ifndef OPENSSL_PROGRAM
	Q_UNUSED(type); Q_UNUSED(cn);
	return nullptr;
#else
	static int n = 0;
	QString out = dir.filePath(QString("tm-%1.csr").arg(++n));
	bool ec = type.startsWith("ec");
	QProcess proc;
	proc.start(OPENSSL_PROGRAM, { "req", "-new", "-newkey", ec ? "ec" : "rsa:2048",
		"-pkeyopt", ec ? "ec_paramgen_curve:P-256" : "rsa_keygen_bits:2048",
		"-nodes", "-keyout", out + ".key", "-out", out, "-subj", "/CN=" + cn });
	if (!proc.waitForFinished(30000) || proc.exitCode() != 0)
		return nullptr;
	pki_x509req *req = new pki_x509req(cn + QString::number(n));
	req->fload(out);
	return dynamic_cast<pki_x509req *>(
			Database.model<db_x509req>()->insert(req));
#endif
}

/* The "X509v3 extensions:" part of openssl x509 -text */
QString test_service_template_migration::extensionsText(pki_x509 *cert)
{
#ifndef OPENSSL_PROGRAM
	Q_UNUSED(cert);
	return QString();
#else
	QString pem = dir.filePath(cert->getIntName() + ".pem");
	XFile f(pem);
	f.open_write();
	cert->writeCert(f, true);
	f.close();
	QProcess proc;
	proc.start(OPENSSL_PROGRAM, { "x509", "-noout", "-text", "-in", pem });
	proc.waitForFinished(30000);
	QString text = QString::fromUtf8(proc.readAllStandardOutput());
	int from = text.indexOf("X509v3 extensions:");
	int to = text.indexOf("Signature Algorithm:", from);
	return from < 0 ? QString() : text.mid(from, to - from);
#endif
}

void test_service_template_migration::identicalExtensions_data()
{
	QTest::addColumn<QString>("file");
	QTest::addColumn<QString>("id");
	QTest::addColumn<QString>("type");
	QTest::addColumn<QString>("refused");
	/* TLS_server and TLS_client carry keyEncipherment and keyAgreement,
	 * which fit no key type together (BTD-195): the template and the
	 * migrated profile refuse every key alike */
	for (QString t : { "rsa-2048", "ec-p256" }) {
		QTest::newRow(CCHAR("CA " + t)) << "CA" << "xca-ca" << t
			<< QString();
		QTest::newRow(CCHAR("TLS_server " + t)) << "TLS_server"
			<< "xca-tls-server" << t
			<< QString("key_usage_not_for_key_type");
		QTest::newRow(CCHAR("TLS_client " + t)) << "TLS_client"
			<< "xca-tls-client" << t
			<< QString("key_usage_not_for_key_type");
	}
}

void test_service_template_migration::identicalExtensions()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	QFETCH(QString, file);
	QFETCH(QString, id);
	QFETCH(QString, type);
	QFETCH(QString, refused);
	Settings["disable_netscape"] = true;
	pki_temp *temp = defaultTemplate(file);
	QVERIFY(temp);
	TemplateSpec t = TemplateSpec::fromTemplate(temp);
	delete temp;
	QJsonObject doc = Profile::fromTemplate(t);
	QCOMPARE(doc["id"].toString(), id);
	Profile p = Profile::fromJson(doc);
	QCOMPARE(p.family, QString("generic"));

	pki_x509 *issuer = ca();
	pki_x509req *req = csr(type, "host.example");
	QVERIFY(issuer && req);

	/* the template, as the New Certificate dialog signs a request */
	IssuanceSpec ts;
	t.applyTo(ts, a1time());
	ts.name = "by template";
	ts.subject = req->getSubject();
	ts.request = req;
	ts.signer = issuer;
	ts.hashAlgo = digest(NID_sha256);
	if (!refused.isEmpty()) {
		QString a, b;
		try {
			Database.model<db_x509>()->newCert(ctx, ts);
		} catch (serviceError &e) {
			a = e.code;
		}
		try {
			p.apply(req, nullptr, Registration(), issuer);
		} catch (serviceError &e) {
			b = e.code;
		}
		QCOMPARE(a, refused);
		QCOMPARE(b, refused);
		return;
	}
	pki_x509 *byTemplate = Database.model<db_x509>()->newCert(ctx, ts);

	IssuanceSpec ps = p.apply(req, nullptr, Registration(), issuer);
	ps.name = "by profile";
	pki_x509 *byProfile = Database.model<db_x509>()->newCert(ctx, ps);
	QVERIFY(byTemplate && byProfile);

	QString a = extensionsText(byTemplate), b = extensionsText(byProfile);
	QVERIFY2(!a.isEmpty(), "no extensions");
	QCOMPARE(b, a);
#endif
}

/* Values a profile cannot hold */
void test_service_template_migration::notMigratable_data()
{
	QTest::addColumn<QString>("field");
	QTest::newRow("fixed SAN") << "subjectAltName";
	QTest::newRow("name constraints") << "nameConstraints";
	QTest::newRow("CRL distribution points") << "crlDistPoints";
	QTest::newRow("advanced") << "advanced";
	QTest::newRow("subject") << "subject";
	QTest::newRow("no key usage") << "keyUsage";
	QTest::newRow("midnight") << "midnight";
	QTest::newRow("SAN merge mode") << "reqSan";
	QTest::newRow("EKU merge mode") << "reqEku";
	QTest::newRow("pathLen not a number") << "pathLen";
}

void test_service_template_migration::notMigratable()
{
	QFETCH(QString, field);
	pki_temp *temp = defaultTemplate("TLS_server");
	QVERIFY(temp);
	TemplateSpec t = TemplateSpec::fromTemplate(temp);
	delete temp;
	if (field == "subjectAltName")
		t.extensions.subjectAltName = "DNS:copycn, DNS:fixed.example";
	else if (field == "nameConstraints")
		t.extensions.nameConstraints = "permitted;DNS:example";
	else if (field == "crlDistPoints")
		t.extensions.crlDistPoints = "URI:http://crl.example/ca.crl";
	else if (field == "advanced")
		t.extensions.advanced = "1.2.3.4=ASN1:NULL";
	else if (field == "subject")
		t.subject.addEntryByNid(NID_organizationName, "Fixed");
	else if (field == "keyUsage")
		t.extensions.keyUsage.clear();
	else if (field == "midnight")
		t.midnight = true;
	else if (field == "reqSan")
		t.extensions.sanMerge = ExtensionSpec::merge_union;
	else if (field == "reqEku")
		t.extensions.ekuMerge = ExtensionSpec::merge_request;
	else if (field == "pathLen") {
		t.extensions.basicCA = ExtensionSpec::bc_ca;
		t.extensions.pathLen = "two";
	}
	try {
		Profile::fromTemplate(t);
		QFAIL("migrated");
	} catch (serviceError &err) {
		QCOMPARE(err.code, QString("template_not_migratable"));
		QVERIFY2(err.getString().contains(field), CCHAR(err.getString()));
	}
}

/* The explicit migration into the store; the template stays */
void test_service_template_migration::migrateIntoStore()
{
	pki_temp *temp = defaultTemplate("TLS_client");
	QVERIFY(temp);
	ProfileStore::Document d = ProfileStore::migrateTemplate(ctx,
				TemplateSpec::fromTemplate(temp));
	delete temp;
	QCOMPARE(d.name, QString("xca-tls-client"));
	QCOMPARE(d.version, 1);
	AuditEntry e = AuditLog::entries().last();
	QCOMPARE(e.action, QString("profile.migrate"));
	QCOMPARE(e.params.value("template").toString(), QString("TLS_client"));
	/* the Netscape extensions of the template are named, never dropped
	 * silently (review of bxc-pki#46) */
	QCOMPARE(d.dropped, QStringList({ "nsCertType", "nsComment" }));
	QCOMPARE(e.params.value("dropped_extensions").toString(),
		QString("nsCertType,nsComment"));
	QCOMPARE(ProfileStore::show("profile", "xca-tls-client").document,
		d.document);
}

XCA_SERVICE_TEST_MAIN(test_service_template_migration)
#include "test_service_template_migration.moc"
