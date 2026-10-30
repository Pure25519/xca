/* vi: set sw=4 ts=4:
 *
 * What a CSR adds to SAN, key usage and EKU (BTD-54): each merge mode
 * with the extension in the CSR, in the template or in both; one
 * instance of each extension; EKU from the CSR limited to an allowed set
 * with a default; templates without the new settings behave as XCA
 * always did.
 */

#include <QFile>
#include <QProcess>
#include <QTemporaryDir>

#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/db_key.h"
#include "lib/db_temp.h"
#include "lib/db_x509.h"
#include "lib/db_x509req.h"
#include "lib/exception.h"
#include "lib/issuance.h"
#include "lib/pki_temp.h"
#include "lib/pki_x509.h"
#include "lib/pki_x509req.h"
#include "lib/template.h"

#include "ServiceTestCase.h"

Q_DECLARE_METATYPE(ExtensionSpec::requestMerge)

class test_service_merge : public ServiceTestCase
{
	Q_OBJECT

	ServiceContext ctx{ ServiceContext::cli, "os:service-test" };
	QTemporaryDir dir{};

	pki_x509 *ca();
	pki_x509req *csr(const QStringList &addext);
	IssuanceSpec spec(pki_x509req *req, pki_x509 *signer);
	QString openssl(const QStringList &args);
	static QString extText(pki_x509 *cert, int nid);

  private slots:
	void modes_data();
	void modes();
	void ekuDefaultAndAllowed();
	void legacyTemplates();
	void caBitsNeverIntoLeaf_data();
	void caBitsNeverIntoLeaf();
	void criticalityFromTemplate_data();
	void criticalityFromTemplate();
	void mergeDecisionAudited();
};

/* the code of the issuance, "" when it issued */
static QString code(const ServiceContext &ctx, const IssuanceSpec &s)
{
	try {
		Database.model<db_x509>()->newCert(ctx, s);
		return QString();
	} catch (serviceError &err) {
		return err.code;
	}
}

pki_x509 *test_service_merge::ca()
{
	IssuanceSpec s;
	s.name = "Merge CA";
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

QString test_service_merge::openssl(const QStringList &args)
{
#ifdef OPENSSL_PROGRAM
	QProcess p;
	p.setProcessChannelMode(QProcess::MergedChannels);
	p.setWorkingDirectory(dir.path());
	p.start(OPENSSL_PROGRAM, args);
	if (!p.waitForFinished(30000) || p.exitCode() != 0) {
		qWarning() << "openssl" << args << p.readAll();
		return QString();
	}
	return QString::fromUtf8(p.readAll()) + " ";
#else
	Q_UNUSED(args);
	return QString();
#endif
}

/* A device CSR with the given -addext values */
pki_x509req *test_service_merge::csr(const QStringList &addext)
{
	static int n;
	QString out = dir.filePath(QString("req%1.pem").arg(++n));
	QStringList args{ "req", "-new", "-newkey", "ec", "-pkeyopt",
		"ec_paramgen_curve:P-256", "-nodes",
		"-keyout", dir.filePath("req.key"), "-out", out,
		"-subj", "/CN=device.example" };
	for (const QString &a : addext)
		args << "-addext" << a;
	if (openssl(args).isEmpty())
		return nullptr;
	pki_x509req *req = new pki_x509req(QString("req%1").arg(n));
	req->fload(out);
	return dynamic_cast<pki_x509req *>(
			Database.model<db_x509req>()->insert(req));
}

IssuanceSpec test_service_merge::spec(pki_x509req *req, pki_x509 *signer)
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

QString test_service_merge::extText(pki_x509 *c, int nid)
{
	X509 *x = c->getCert();
	int i = X509_get_ext_by_NID(x, nid, -1);
	if (i < 0)
		return QString();
	BIO *b = BIO_new(BIO_s_mem());
	X509V3_EXT_print(b, X509_get_ext(x, i), 0, 0);
	char *data;
	long len = BIO_get_mem_data(b, &data);
	QString s = QString::fromUtf8(data, len);
	BIO_free(b);
	return s;
}

void test_service_merge::modes_data()
{
	QTest::addColumn<int>("nid");
	QTest::addColumn<ExtensionSpec::requestMerge>("mode");
	QTest::addColumn<QString>("in");        // csr, template, both
	QTest::addColumn<QString>("expected");

	struct ext {
		int nid;
		const char *name, *csrText, *tmplText, *both;
	};
	const ext exts[] = {
		{ NID_subject_alt_name, "SAN", "DNS:csr.example",
		  "DNS:tmpl.example", "DNS:csr.example, DNS:tmpl.example" },
		{ NID_key_usage, "KU", "Digital Signature", "Key Agreement",
		  "Digital Signature, Key Agreement" },
		{ NID_ext_key_usage, "EKU", "TLS Web Client Authentication",
		  "TLS Web Server Authentication",
		  "TLS Web Client Authentication, TLS Web Server Authentication" },
	};
	const struct {
		ExtensionSpec::requestMerge mode;
		const char *name;
	} modes[] = {
		{ ExtensionSpec::merge_legacy, "legacy" },
		{ ExtensionSpec::merge_template, "template" },
		{ ExtensionSpec::merge_request, "request" },
		{ ExtensionSpec::merge_union, "merge" },
	};
	for (const auto &e : exts) {
		for (const auto &m : modes) {
			QString csrOnly = m.mode == ExtensionSpec::merge_template ?
						QString() : e.csrText;
			QString both = m.mode == ExtensionSpec::merge_request ?
				e.csrText : m.mode == ExtensionSpec::merge_union ?
				e.both : e.tmplText;
			QTest::newRow(CCHAR(QString("%1 %2 csr").arg(e.name, m.name)))
				<< e.nid << m.mode << "csr" << csrOnly;
			QTest::newRow(CCHAR(QString("%1 %2 template").arg(e.name, m.name)))
				<< e.nid << m.mode << "template" << QString(e.tmplText);
			QTest::newRow(CCHAR(QString("%1 %2 both").arg(e.name, m.name)))
				<< e.nid << m.mode << "both" << both;
		}
	}
}

/* AC 1: each mode with the extension in the CSR, the template or both */
void test_service_merge::modes()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	QFETCH(int, nid);
	QFETCH(ExtensionSpec::requestMerge, mode);
	QFETCH(QString, in);
	QFETCH(QString, expected);

	pki_x509 *signer = ca();
	QVERIFY(signer);
	QStringList addext;
	bool fromCsr = in != "template", fromTmpl = in != "csr";
	if (fromCsr) {
		addext << (nid == NID_subject_alt_name ? "subjectAltName=DNS:csr.example" :
			nid == NID_key_usage ? "keyUsage=digitalSignature" :
			"extendedKeyUsage=clientAuth");
	}
	pki_x509req *req = csr(addext);
	QVERIFY(req);
	IssuanceSpec s = spec(req, signer);
	ExtensionSpec &e = s.extensions;
	if (fromTmpl) {
		if (nid == NID_subject_alt_name)
			e.subjectAltName = "DNS:tmpl.example";
		else if (nid == NID_key_usage)
			e.keyUsage << "keyAgreement";
		else
			e.extKeyUsage << "serverAuth";
	}
	(nid == NID_subject_alt_name ? e.sanMerge : nid == NID_key_usage ?
		e.kuMerge : e.ekuMerge) = mode;
	pki_x509 *cert = Database.model<db_x509>()->newCert(ctx, s);
	QVERIFY(cert);
	QCOMPARE(extText(cert, nid), expected);

	/* openssl sees each extension once */
	QString pem = dir.filePath("merged.pem");
	BIO *b = BIO_new_file(QFile::encodeName(pem).constData(), "w");
	PEM_write_bio_X509(b, cert->getCert());
	BIO_free(b);
	QString text = openssl({ "x509", "-in", pem, "-noout", "-text" });
	for (const char *h : { "X509v3 Subject Alternative Name",
			"X509v3 Key Usage", "X509v3 Extended Key Usage",
			"X509v3 Basic Constraints" })
		QVERIFY2(text.count(h) <= 1, CCHAR(text));
#endif
}

/* AC 2: a CSR without EKU gets the default (clientAuth, Nexus style); an
 * EKU outside the allowed set is a typed error; own OIDs are allowed */
void test_service_merge::ekuDefaultAndAllowed()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	pki_x509 *signer = ca();
	QVERIFY(signer);

	pki_x509req *none = csr({});
	QVERIFY(none);
	IssuanceSpec s = spec(none, signer);
	s.extensions.ekuMerge = ExtensionSpec::merge_request;
	s.extensions.ekuDefault = QStringList{ "clientAuth" };
	s.extensions.ekuAllowed = QStringList{ "serverAuth", "clientAuth",
						"1.3.6.1.4.1.99999.1" };
	pki_x509 *cert = Database.model<db_x509>()->newCert(ctx, s);
	QVERIFY(cert);
	QCOMPARE(extText(cert, NID_ext_key_usage),
		QString("TLS Web Client Authentication"));

	pki_x509req *code = csr({ "extendedKeyUsage=codeSigning" });
	QVERIFY(code);
	s.request = code;
	QString got;
	try {
		Database.model<db_x509>()->newCert(ctx, s);
		got = "<issued>";
	} catch (serviceError &err) {
		got = err.code;
	}
	QCOMPARE(got, QString("csr_eku_not_allowed"));

	pki_x509req *own = csr({ "extendedKeyUsage=1.3.6.1.4.1.99999.1" });
	QVERIFY(own);
	s.request = own;
	cert = Database.model<db_x509>()->newCert(ctx, s);
	QVERIFY(cert);
	QCOMPARE(extText(cert, NID_ext_key_usage),
		QString("1.3.6.1.4.1.99999.1"));
#endif
}

/* AC 3: a template stored before BTD-54 has none of the new settings and
 * keeps XCA's behaviour; the new settings survive a store and a read */
void test_service_merge::legacyTemplates()
{
	pki_temp old("old-template");
	TemplateSpec t = TemplateSpec::fromTemplate(&old);
	QCOMPARE(t.extensions.sanMerge, ExtensionSpec::merge_legacy);
	QCOMPARE(t.extensions.kuMerge, ExtensionSpec::merge_legacy);
	QCOMPARE(t.extensions.ekuMerge, ExtensionSpec::merge_legacy);
	QVERIFY(t.extensions.ekuAllowed.isEmpty());
	QVERIFY(t.extensions.ekuDefault.isEmpty());

	t.extensions.sanMerge = ExtensionSpec::merge_union;
	t.extensions.kuMerge = ExtensionSpec::merge_template;
	t.extensions.ekuMerge = ExtensionSpec::merge_request;
	t.extensions.ekuAllowed = QStringList{ "serverAuth", "clientAuth" };
	t.extensions.ekuDefault = QStringList{ "clientAuth" };
	pki_temp stored("new-template");
	t.toTemplate(&stored);
	QCOMPARE(stored.getSetting("reqSan"), QString("merge"));
	QCOMPARE(stored.getSetting("reqKu"), QString("template"));
	QCOMPARE(stored.getSetting("reqEku"), QString("request"));
	TemplateSpec back = TemplateSpec::fromTemplate(&stored);
	QCOMPARE(back.extensions.sanMerge, ExtensionSpec::merge_union);
	QCOMPARE(back.extensions.kuMerge, ExtensionSpec::merge_template);
	QCOMPARE(back.extensions.ekuMerge, ExtensionSpec::merge_request);
	QCOMPARE(back.extensions.ekuAllowed,
		QStringList({ "serverAuth", "clientAuth" }));
	QCOMPARE(back.extensions.ekuDefault, QStringList{ "clientAuth" });

	/* the legacy default writes empty values, as an old template has */
	TemplateSpec plain;
	pki_temp p("plain");
	plain.toTemplate(&p);
	QCOMPARE(p.getSetting("reqSan"), QString());
	QCOMPARE(p.getSetting("ekuAllowed"), QString());
}

XCA_SERVICE_TEST_MAIN(test_service_merge)
/* mr-processor review of xca#47, blocker 1: keyCertSign and cRLSign of
 * a CSR never reach an end entity, in any mode that takes its key usage,
 * with or without "copy extensions"; anyExtendedKeyUsage, OCSPSigning
 * and codeSigning only when ekuAllowed names them. A CA may take them. */
void test_service_merge::caBitsNeverIntoLeaf_data()
{
	QTest::addColumn<QString>("addext");
	QTest::addColumn<ExtensionSpec::requestMerge>("mode");
	QTest::addColumn<bool>("copy");
	QTest::addColumn<QString>("allowed");
	QTest::addColumn<bool>("ca");
	QTest::addColumn<QString>("code");

	const QString kcs = "keyUsage=digitalSignature,keyCertSign";
	const QString crl = "keyUsage=digitalSignature,cRLSign";
	for (auto mode : { ExtensionSpec::merge_union, ExtensionSpec::merge_request }) {
		QString m = mode == ExtensionSpec::merge_union ? "union" : "request";
		for (bool copy : { false, true }) {
			QString c = copy ? " copy" : "";
			QTest::newRow(CCHAR(m + c + " keyCertSign")) << kcs << mode
				<< copy << "" << false << "csr_keycertsign_not_ca";
			QTest::newRow(CCHAR(m + c + " cRLSign")) << crl << mode
				<< copy << "" << false << "csr_keycertsign_not_ca";
			for (QString p : { "anyExtendedKeyUsage", "OCSPSigning", "codeSigning" })
				QTest::newRow(CCHAR(m + c + " " + p))
					<< "extendedKeyUsage=" + p << mode << copy
					<< "" << false << "csr_eku_not_allowed";
		}
		QTest::newRow(CCHAR(m + " anyEKU allowed"))
			<< "extendedKeyUsage=anyExtendedKeyUsage" << mode << false
			<< "anyExtendedKeyUsage" << false << "";
		QTest::newRow(CCHAR(m + " keyCertSign for a CA")) << kcs << mode
			<< false << "" << true << "";
	}
	QTest::newRow("legacy copy keyCertSign") << kcs
		<< ExtensionSpec::merge_legacy << true << "" << false
		<< "csr_keycertsign_not_ca";
	QTest::newRow("legacy without copy") << kcs
		<< ExtensionSpec::merge_legacy << false << "" << false << "";
}

void test_service_merge::caBitsNeverIntoLeaf()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	QFETCH(QString, addext);
	QFETCH(ExtensionSpec::requestMerge, mode);
	QFETCH(bool, copy);
	QFETCH(QString, allowed);
	QFETCH(bool, ca);
	QFETCH(QString, code);
	pki_x509 *signer = this->ca();
	pki_x509req *req = csr({ addext });
	QVERIFY(signer && req);
	IssuanceSpec s = spec(req, signer);
	s.copyRequestExtensions = copy;
	s.extensions.kuMerge = mode;
	s.extensions.ekuMerge = mode;
	if (!allowed.isEmpty())
		s.extensions.ekuAllowed << allowed;
	if (ca)
		s.extensions.basicCA = ExtensionSpec::bc_ca;
	QCOMPARE(::code(ctx, s), code);
#endif
}

/* MINOR 4: the template's criticality wins; union may only add it */
void test_service_merge::criticalityFromTemplate_data()
{
	QTest::addColumn<ExtensionSpec::requestMerge>("mode");
	QTest::addColumn<bool>("templateCritical");
	QTest::addColumn<bool>("csrCritical");
	QTest::addColumn<bool>("expected");
	QTest::newRow("request, template critical") << ExtensionSpec::merge_request
		<< true << false << true;
	QTest::newRow("request, CSR critical") << ExtensionSpec::merge_request
		<< false << true << false;
	QTest::newRow("union, CSR critical") << ExtensionSpec::merge_union
		<< false << true << true;
	QTest::newRow("union, none") << ExtensionSpec::merge_union
		<< false << false << false;
}

void test_service_merge::criticalityFromTemplate()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	QFETCH(ExtensionSpec::requestMerge, mode);
	QFETCH(bool, templateCritical);
	QFETCH(bool, csrCritical);
	QFETCH(bool, expected);
	pki_x509 *signer = ca();
	pki_x509req *req = csr({ QString("keyUsage=%1digitalSignature")
			.arg(csrCritical ? "critical," : "") });
	QVERIFY(signer && req);
	IssuanceSpec s = spec(req, signer);
	s.copyRequestExtensions = false;
	s.extensions.kuMerge = mode;
	s.extensions.keyUsage << "keyAgreement";
	s.extensions.keyUsageCritical = templateCritical;
	pki_x509 *cert = Database.model<db_x509>()->newCert(ctx, s);
	QVERIFY(cert);
	X509 *x = cert->getCert();
	QCOMPARE((bool)X509_EXTENSION_get_critical(X509_get_ext(x,
		X509_get_ext_by_NID(x, NID_key_usage, -1))), expected);
#endif
}

/* MINOR 10: the audit entry says per extension which mode decided and
 * whether the CSR or ekuDefault gave the value */
void test_service_merge::mergeDecisionAudited()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	pki_x509 *signer = ca();
	pki_x509req *req = csr({ "keyUsage=digitalSignature",
				"subjectAltName=DNS:device.example" });
	QVERIFY(signer && req);
	IssuanceSpec s = spec(req, signer);
	s.copyRequestExtensions = false;
	s.extensions.sanMerge = ExtensionSpec::merge_template;
	s.extensions.kuMerge = ExtensionSpec::merge_union;
	s.extensions.keyUsage << "keyAgreement";
	s.extensions.ekuMerge = ExtensionSpec::merge_request;
	s.extensions.ekuDefault << "clientAuth";
	QVERIFY(Database.model<db_x509>()->newCert(ctx, s));
	QCOMPARE(AuditLog::entries().last().params.value("merge").toString(),
		QString("san=template,ku=union+csr,eku=request+default"));
#endif
}

#include "test_service_merge.moc"
