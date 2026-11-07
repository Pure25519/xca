/* vi: set sw=4 ts=4:
 *
 * EKU names of a template and the request merge (BTD-192): an ekuAllowed
 * or ekuDefault entry OpenSSL does not know is refused with
 * template_eku_unknown when a template is created, changed or imported,
 * and at issuance for a spec that bypassed that check, instead of being
 * dropped (an empty EKU SEQUENCE, RFC 5280 4.2.1.12). A merged extension
 * that cannot be encoded is a typed error, not a certificate without it.
 */

#include <QProcess>
#include <QSqlQuery>
#include <QTemporaryDir>

#include <openssl/x509v3.h>

#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/db_key.h"
#include "lib/db_temp.h"
#include "lib/db_x509.h"
#include "lib/db_x509req.h"
#include "lib/exception.h"
#include "lib/importexport.h"
#include "lib/issuance.h"
#include "lib/pki_temp.h"
#include "lib/pki_x509.h"
#include "lib/pki_x509req.h"
#include "lib/template.h"

#include "ServiceTestCase.h"

class test_service_eku_names : public ServiceTestCase
{
	Q_OBJECT

	ServiceContext ctx{ ServiceContext::cli, "os:service-test" };
	QTemporaryDir dir{};

	pki_x509 *ca();
	pki_x509req *csr(const QStringList &addext);
	IssuanceSpec spec(pki_x509req *req, pki_x509 *signer);
	static int certRows();
	static int ekuIndex(pki_x509 *cert);
	/* the code and message of the issuance, "" when it issued */
	QString issue(const IssuanceSpec &s, QString *message = nullptr);

  private slots:
	void cleanup();
	void unknownEkuDefaultAtIssuance();
	void unknownEkuAllowedAtIssuance();
	void templateWithUnknownEku_data();
	void templateWithUnknownEku();
	void knownEkuNamesAccepted();
	void failedEncodingIssuesNothing();
	void mergedExtensionKeepsPosition();
};

void test_service_eku_names::cleanup()
{
	db_x509::encodeExtension = X509V3_EXT_i2d;
	ServiceTestCase::cleanup();
}

pki_x509 *test_service_eku_names::ca()
{
	IssuanceSpec s;
	s.name = "EKU CA";
	x509name n;
	n.addEntryByNid(NID_commonName, s.name);
	s.subject = n;
	s.key = Database.model<db_key>()->newKey(keyjob("EC:prime256v1"), "ca");
	s.notBefore = a1time();
	s.notAfter = a1time(QDateTime::currentDateTimeUtc().addDays(365));
	s.hashAlgo = digest(NID_sha256);
	s.extensions.basicCA = ExtensionSpec::bc_ca;
	s.extensions.subjectKeyId = true;
	s.extensions.keyUsage << "keyCertSign" << "cRLSign";
	return Database.model<db_x509>()->newCert(ctx, s);
}

/* A device CSR with the given -addext values */
pki_x509req *test_service_eku_names::csr(const QStringList &addext)
{
#ifdef OPENSSL_PROGRAM
	static int n;
	QString out = dir.filePath(QString("req%1.pem").arg(++n));
	QStringList args{ "req", "-new", "-newkey", "ec", "-pkeyopt",
		"ec_paramgen_curve:P-256", "-nodes",
		"-keyout", dir.filePath("req.key"), "-out", out,
		"-subj", "/CN=device.example" };
	for (const QString &a : addext)
		args << "-addext" << a;
	QProcess p;
	p.setProcessChannelMode(QProcess::MergedChannels);
	p.start(OPENSSL_PROGRAM, args);
	if (!p.waitForFinished(30000) || p.exitCode() != 0) {
		qWarning() << "openssl" << args << p.readAll();
		return nullptr;
	}
	pki_x509req *req = new pki_x509req(QString("req%1").arg(n));
	req->fload(out);
	return dynamic_cast<pki_x509req *>(
			Database.model<db_x509req>()->insert(req));
#else
	Q_UNUSED(addext);
	return nullptr;
#endif
}

IssuanceSpec test_service_eku_names::spec(pki_x509req *req, pki_x509 *signer)
{
	IssuanceSpec s;
	s.request = req;
	s.subject = req->getSubject();
	s.signer = signer;
	s.notBefore = a1time();
	s.notAfter = a1time(QDateTime::currentDateTimeUtc().addDays(30));
	s.hashAlgo = digest(NID_sha256);
	s.extensions.basicCA = ExtensionSpec::bc_not_ca;
	s.copyRequestExtensions = true;
	return s;
}

int test_service_eku_names::certRows()
{
	QSqlQuery q(QSqlDatabase::database());
	return q.exec("SELECT COUNT(*) FROM certs") && q.first() ?
		q.value(0).toInt() : -1;
}

int test_service_eku_names::ekuIndex(pki_x509 *cert)
{
	return X509_get_ext_by_NID(cert->getCert(), NID_ext_key_usage, -1);
}

QString test_service_eku_names::issue(const IssuanceSpec &s, QString *message)
{
	try {
		Database.model<db_x509>()->newCert(ctx, s);
		return QString();
	} catch (serviceError &err) {
		if (message)
			*message = err.getString();
		return err.code;
	}
}

/* Only unknown names in ekuDefault: before BTD-192 the certificate got
 * an EKU extension with an empty SEQUENCE */
void test_service_eku_names::unknownEkuDefaultAtIssuance()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	pki_x509 *signer = ca();
	pki_x509req *req = csr({});
	QVERIFY(signer && req);
	IssuanceSpec s = spec(req, signer);
	s.extensions.ekuMerge = ExtensionSpec::merge_request;
	s.extensions.ekuDefault = QStringList{ "clientAuht" };
	int rows = certRows();

	QString message;
	QCOMPARE(issue(s, &message), QString("template_eku_unknown"));
	QVERIFY2(message.contains("clientAuht"), CCHAR(message));
	QCOMPARE(certRows(), rows);
	AuditEntry e = AuditLog::entries().last();
	QCOMPARE(e.result, QString("failure"));
	QCOMPARE(e.errorCode, QString("template_eku_unknown"));
#endif
}

/* An unknown name in ekuAllowed: before BTD-192 it was dropped and the
 * certificate was issued from the rest of the list */
void test_service_eku_names::unknownEkuAllowedAtIssuance()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	pki_x509 *signer = ca();
	pki_x509req *req = csr({ "extendedKeyUsage=serverAuth" });
	QVERIFY(signer && req);
	IssuanceSpec s = spec(req, signer);
	s.extensions.ekuMerge = ExtensionSpec::merge_request;
	s.extensions.ekuAllowed = QStringList{ "serverAuth", "sevrerAuth" };
	int rows = certRows();

	QString message;
	QCOMPARE(issue(s, &message), QString("template_eku_unknown"));
	QVERIFY2(message.contains("sevrerAuth"), CCHAR(message));
	QCOMPARE(certRows(), rows);
#endif
}

void test_service_eku_names::templateWithUnknownEku_data()
{
	QTest::addColumn<QString>("path");
	QTest::addColumn<QString>("field");
	for (const char *path : { "create", "update", "import" }) {
		for (const char *field : { "ekuAllowed", "ekuDefault" }) {
			QTest::newRow(CCHAR(QString("%1 %2").arg(path, field)))
				<< QString(path) << QString(field);
		}
	}
}

/* Created, changed or imported: refused, the entry named, nothing stored
 * or changed, one failure entry */
void test_service_eku_names::templateWithUnknownEku()
{
	QFETCH(QString, path);
	QFETCH(QString, field);
	db_temp *temps = Database.model<db_temp>();

	TemplateSpec good;
	good.name = "EKU template";
	good.extensions.ekuMerge = ExtensionSpec::merge_request;
	good.extensions.ekuAllowed = QStringList{ "serverAuth" };
	good.extensions.ekuDefault = QStringList{ "serverAuth" };
	pki_temp *stored = path == "update" ?
		temps->newTemplate(ctx, good) : nullptr;

	TemplateSpec bad = good;
	bad.name = "EKU template bad";
	(field == "ekuAllowed" ? bad.extensions.ekuAllowed :
		bad.extensions.ekuDefault) << "TLS Web Srever Authentication";
	int templates = Store.getAll<pki_temp>().size();
	int entries = AuditLog::entries().size();

	QString code, message;
	try {
		if (path == "create") {
			temps->newTemplate(ctx, bad);
		} else if (path == "update") {
			temps->updateTemplate(ctx, stored, bad);
		} else {
			pki_temp *t = new pki_temp(bad.name);
			bad.toTemplate(t);
			ImportSpec spec;
			spec.items << t;
			Database.importItems(ctx, spec);
		}
	} catch (serviceError &err) {
		code = err.code;
		message = err.getString();
	}
	QCOMPARE(code, QString("template_eku_unknown"));
	QVERIFY2(message.contains("TLS Web Srever Authentication") &&
		 message.contains(field), CCHAR(message));
	QCOMPARE(Store.getAll<pki_temp>().size(), templates);
	if (stored) {
		TemplateSpec now = TemplateSpec::fromTemplate(stored);
		QCOMPARE(now.name, good.name);
		QCOMPARE(now.extensions.ekuAllowed, good.extensions.ekuAllowed);
		QCOMPARE(now.extensions.ekuDefault, good.extensions.ekuDefault);
	}
	QCOMPARE(AuditLog::entries().size(), entries + 1);
	AuditEntry e = AuditLog::entries().last();
	QCOMPARE(e.result, QString("failure"));
	QCOMPARE(e.errorCode, QString("template_eku_unknown"));
	AuditVerifyResult v = AuditLog::verify();
	QVERIFY2(v.ok(), v.toJson().constData());
}

/* Short names, long names and dotted OIDs are known */
void test_service_eku_names::knownEkuNamesAccepted()
{
	TemplateSpec t;
	t.name = "Known EKU names";
	t.extensions.ekuMerge = ExtensionSpec::merge_request;
	t.extensions.ekuAllowed = QStringList{ "serverAuth",
		"TLS Web Client Authentication", "1.3.6.1.4.1.99999.1" };
	t.extensions.ekuDefault = QStringList{ "clientAuth" };
	pki_temp *temp = Database.model<db_temp>()->newTemplate(ctx, t);
	QVERIFY(temp);
	QCOMPARE(TemplateSpec::fromTemplate(temp).extensions.ekuAllowed,
		t.extensions.ekuAllowed);
}

static X509_EXTENSION *failEku(int nid, int crit, void *value)
{
	if (nid == NID_ext_key_usage)
		return nullptr;
	return X509V3_EXT_i2d(nid, crit, value);
}

/* The merged EKU cannot be encoded: before BTD-192 the template's EKU was
 * deleted first and the certificate was issued without any EKU */
void test_service_eku_names::failedEncodingIssuesNothing()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	pki_x509 *signer = ca();
	pki_x509req *req = csr({ "extendedKeyUsage=clientAuth" });
	QVERIFY(signer && req);
	IssuanceSpec s = spec(req, signer);
	s.extensions.extKeyUsage << "serverAuth";
	s.extensions.ekuMerge = ExtensionSpec::merge_union;
	int rows = certRows();
	int certs = Store.getAll<pki_x509>().size();

	db_x509::encodeExtension = failEku;
	QCOMPARE(issue(s), QString("invalid_extension"));
	db_x509::encodeExtension = X509V3_EXT_i2d;
	QCOMPARE(certRows(), rows);
	QCOMPARE(Store.getAll<pki_x509>().size(), certs);
	AuditEntry e = AuditLog::entries().last();
	QCOMPARE(e.result, QString("failure"));
	QCOMPARE(e.errorCode, QString("invalid_extension"));
	AuditVerifyResult v = AuditLog::verify();
	QVERIFY2(v.ok(), v.toJson().constData());
#endif
}

/* The merged EKU stays where the template put it */
void test_service_eku_names::mergedExtensionKeepsPosition()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	pki_x509 *signer = ca();
	pki_x509req *plain = csr({});
	pki_x509req *withEku = csr({ "extendedKeyUsage=clientAuth" });
	QVERIFY(signer && plain && withEku);
	IssuanceSpec s = spec(plain, signer);
	s.extensions.subjectKeyId = true;
	s.extensions.keyUsage << "digitalSignature";
	s.extensions.extKeyUsage << "serverAuth";
	s.extensions.ekuMerge = ExtensionSpec::merge_union;
	pki_x509 *templOnly = Database.model<db_x509>()->newCert(ctx, s);
	QVERIFY(templOnly);
	s.request = withEku;
	s.subject = withEku->getSubject();
	pki_x509 *merged = Database.model<db_x509>()->newCert(ctx, s);
	QVERIFY(merged);
	QVERIFY(ekuIndex(templOnly) >= 0);
	QCOMPARE(ekuIndex(merged), ekuIndex(templOnly));
#endif
}

XCA_SERVICE_TEST_MAIN(test_service_eku_names)
#include "test_service_eku_names.moc"
