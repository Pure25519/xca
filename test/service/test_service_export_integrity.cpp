/* vi: set sw=4 ts=4:
 *
 * Export integrity (BTD-199): an export whose OpenSSL encoder fails ends
 * in the typed error export_failed with the format, the object and the
 * OpenSSL reason. No file is written, no success audit entry, but a
 * failure entry. i2d_bytearray() throws encoding_failed instead of
 * returning empty DER, so no fingerprint of empty bytes and no empty DER
 * reaches the database or the audit log. Before, the writers ignored
 * their encoders: an export reported success with an empty file.
 *
 * The failures are real OpenSSL failures from the test hooks of
 * lib/func_base.h (encodeFault): BioByteArray::bio() hands out a
 * read-only BIO, i2d_bytearray() sees an encoder that returns -1.
 */

#include <QFile>
#include <QTemporaryDir>

#include <openssl/evp.h>

#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/db_crl.h"
#include "lib/db_key.h"
#include "lib/db_temp.h"
#include "lib/db_x509.h"
#include "lib/db_x509req.h"
#include "lib/digest.h"
#include "lib/exception.h"
#include "lib/func.h"
#include "lib/func_base.h"
#include "lib/importexport.h"
#include "lib/issuance.h"
#include "lib/pki_crl.h"
#include "lib/pki_export.h"
#include "lib/pki_temp.h"
#include "lib/pki_x509.h"
#include "lib/pki_x509req.h"
#include "lib/request.h"
#include "lib/template.h"

#include "ServiceTestCase.h"

static const char passVar[] = "BTD199_EXPORT_PASS";

/* Sets a hook of encodeFault for its lifetime */
class Fault
{
	bool &flag;
  public:
	Fault(bool &f) : flag(f) { flag = true; }
	~Fault() { flag = false; }
};

class test_service_export_integrity : public ServiceTestCase
{
	Q_OBJECT

	ServiceContext ctx{ ServiceContext::cli, "os:service-test" };
	QTemporaryDir dir{};

	pki_x509 *ca{};
	pki_x509 *leaf{};
	pki_key *rsaKey{};
	pki_key *edKey{};
	pki_x509req *req{};
	pki_crl *crl{};
	pki_temp *temp{};

	void objects();
	pki_base *object(const QString &kind);
	/* The audit entries after seq, by action and result */
	static QStringList entriesAfter(qint64 seq);
	static qint64 lastSeq();
	/* exportItems() with the hook encodeFault::bioWrites; the error
	 * code or "" */
	QString failingExport(pki_base *pki, int format, bool clipboard,
			const QString &name);

  private slots:
	void initTestCase();
	void init();
	void pkcs12WriterFails();
	void pemCertificateWriterFails();
	void i2dFailureNoEmptyFingerprint();
	void everyFormatFails_data();
	void everyFormatFails();
	void i2dFailureStoresNothing();
};

void test_service_export_integrity::initTestCase()
{
	ServiceTestCase::initTestCase();
	qputenv(passVar, "Export-Secret-199");
}

/* A CA, a certificate with its key, an RSA and an Ed25519 key, a
 * request, a CRL and a template, made anew for every test function */
void test_service_export_integrity::init()
{
	ServiceTestCase::init();
	objects();
}

void test_service_export_integrity::objects()
{
	db_key *keys = Database.model<db_key>();
	QDateTime now = QDateTime::currentDateTimeUtc();

	IssuanceSpec spec;
	spec.name = "BTD-199 CA";
	spec.subject.addEntryByNid(NID_commonName, spec.name);
	spec.key = keys->newKey(ctx, keyjob("EC:prime256v1"), "BTD-199 CA key");
	spec.notBefore = a1time(now.addDays(-1));
	spec.notAfter = a1time(now.addYears(2));
	spec.hashAlgo = digest(NID_sha256);
	spec.extensions.basicCA = ExtensionSpec::bc_ca;
	spec.extensions.keyUsage << "keyCertSign" << "cRLSign";
	ca = Database.model<db_x509>()->newCert(ctx, spec);

	IssuanceSpec ee;
	ee.name = "BTD-199 leaf";
	ee.subject.addEntryByNid(NID_commonName, ee.name);
	ee.key = keys->newKey(ctx, keyjob("EC:prime256v1"), "BTD-199 leaf key");
	ee.signer = ca;
	ee.notBefore = a1time(now.addDays(-1));
	ee.notAfter = a1time(now.addYears(1));
	ee.hashAlgo = digest(NID_sha256);
	ee.extensions.basicCA = ExtensionSpec::bc_not_ca;
	ee.extensions.keyUsage << "digitalSignature";
	leaf = Database.model<db_x509>()->newCert(ctx, ee);

	rsaKey = keys->newKey(ctx, keyjob("RSA:2048"), "BTD-199 RSA key");
	edKey = keys->newKey(ctx, keyjob("ED25519"), "BTD-199 Ed25519 key");

	RequestSpec r;
	r.name = "BTD-199 request";
	r.subject.addEntryByNid(NID_commonName, r.name);
	r.key = rsaKey;
	req = Database.model<db_x509req>()->newRequest(ctx, r);

	crljob job(ca);
	job.hashAlgo = digest(NID_sha256);
	crl = Database.model<db_crl>()->newCrl(ctx, job);

	TemplateSpec t;
	t.name = "BTD-199 template";
	t.extensions.basicCA = ExtensionSpec::bc_not_ca;
	t.extensions.keyUsage << "digitalSignature";
	temp = Database.model<db_temp>()->newTemplate(ctx, t);
}

pki_base *test_service_export_integrity::object(const QString &kind)
{
	if (kind == "certificate")
		return leaf;
	if (kind == "rsa")
		return rsaKey;
	if (kind == "ed25519")
		return edKey;
	if (kind == "request")
		return req;
	if (kind == "crl")
		return crl;
	if (kind == "template")
		return temp;
	return nullptr;
}

qint64 test_service_export_integrity::lastSeq()
{
	QList<AuditEntry> all = AuditLog::entries();
	return all.isEmpty() ? 0 : all.last().seq;
}

QStringList test_service_export_integrity::entriesAfter(qint64 seq)
{
	QStringList list;
	for (const AuditEntry &e : AuditLog::entries()) {
		if (e.seq > seq)
			list << QString("%1 %2 %3").arg(e.action, e.result,
						e.errorCode).trimmed();
	}
	return list;
}

QString test_service_export_integrity::failingExport(pki_base *pki,
		int format, bool clipboard, const QString &name)
{
	ExportSpec spec;
	spec.items << pki;
	spec.clipboard = clipboard;
	if (!clipboard) {
		spec.format = pki_export::by_id(format);
		spec.fileName = dir.filePath(name);
	}
	spec.passwordSource = QString("env:%1").arg(passVar);
	try {
		Fault fault(encodeFault::bioWrites);
		QByteArray out = Database.modelForPki(pki)->exportItems(ctx, spec);
		qWarning() << "export reported success," << out.size() << "bytes";
		return QString();
	} catch (serviceError &err) {
		qInfo().noquote() << err.code << err.getString();
		return err.code;
	} catch (errorEx &err) {
		return "errorEx: " + err.getString();
	}
}

/* A PKCS#12 export whose i2d_PKCS12_bio() fails is no success: no file,
 * no success entry, a failure entry */
void test_service_export_integrity::pkcs12WriterFails()
{
	qint64 seq = lastSeq();
	QString name = dir.filePath("leaf.p12");
	QCOMPARE(failingExport(leaf, 15, false, "leaf.p12"),
		QString("export_failed"));
	QVERIFY2(!QFile::exists(name), "a file was written");
	QCOMPARE(entriesAfter(seq),
		QStringList({ "object.export failure export_failed" }));
}

/* A PEM certificate export whose PEM_write_bio_X509() fails is no
 * success */
void test_service_export_integrity::pemCertificateWriterFails()
{
	qint64 seq = lastSeq();
	QString name = dir.filePath("leaf.crt");
	QCOMPARE(failingExport(leaf, 1, false, "leaf.crt"),
		QString("export_failed"));
	QVERIFY2(!QFile::exists(name), "a file was written");
	QCOMPARE(entriesAfter(seq),
		QStringList({ "object.export failure export_failed" }));
}

/* i2d_bytearray() with a failing encoder: an error, never the empty DER
 * whose SHA-256 (e3b0c442...) would stand as the fingerprint */
void test_service_export_integrity::i2dFailureNoEmptyFingerprint()
{
	X509 *x = leaf->getCert();
	try {
		Fault fault(encodeFault::i2d);
		QByteArray der = i2d_bytearray(I2D_VOID(i2d_X509), x);
		QString fp = fingerprint(der, EVP_sha256());
		QFAIL(qPrintable(QString("i2d_bytearray() returned %1 bytes, "
			"fingerprint %2").arg(der.size()).arg(fp)));
	} catch (serviceError &err) {
		QCOMPARE(err.code, QString("encoding_failed"));
	}
	/* the hook off again: the real DER */
	QVERIFY(!i2d_bytearray(I2D_VOID(i2d_X509), x).isEmpty());
}

void test_service_export_integrity::everyFormatFails_data()
{
	QTest::addColumn<QString>("kind");
	QTest::addColumn<int>("format");
	QTest::addColumn<bool>("clipboard");

	QTest::newRow("certificate PEM") << "certificate" << 1 << false;
	QTest::newRow("certificate PEM chain") << "certificate" << 2 << false;
	QTest::newRow("certificate PEM + key") << "certificate" << 6 << false;
	QTest::newRow("certificate PEM + PKCS#8") << "certificate" << 7 << false;
	QTest::newRow("certificate DER") << "certificate" << 13 << false;
	QTest::newRow("certificate PKCS#7") << "certificate" << 8 << false;
	QTest::newRow("certificate PKCS#7 chain") << "certificate" << 12 << false;
	QTest::newRow("certificate PKCS#12") << "certificate" << 15 << false;
	QTest::newRow("certificate PKCS#12 chain") << "certificate" << 14 << false;
	QTest::newRow("certificate clipboard") << "certificate" << 0 << true;
	QTest::newRow("key PEM public") << "rsa" << 19 << false;
	QTest::newRow("key PEM private") << "rsa" << 20 << false;
	QTest::newRow("key PEM encrypted") << "rsa" << 21 << false;
	QTest::newRow("key SSH2 private RSA") << "rsa" << 22 << false;
	QTest::newRow("key SSH2 private Ed25519") << "ed25519" << 22 << false;
	QTest::newRow("key DER public") << "rsa" << 24 << false;
	QTest::newRow("key DER private") << "rsa" << 25 << false;
	QTest::newRow("key PVK") << "rsa" << 26 << false;
	QTest::newRow("key PKCS#8 encrypted") << "rsa" << 28 << false;
	QTest::newRow("key PKCS#8") << "rsa" << 29 << false;
	QTest::newRow("key clipboard") << "rsa" << 0 << true;
	QTest::newRow("request PEM") << "request" << 30 << false;
	QTest::newRow("request DER") << "request" << 31 << false;
	QTest::newRow("request clipboard") << "request" << 0 << true;
	QTest::newRow("CRL PEM") << "crl" << 32 << false;
	QTest::newRow("CRL DER") << "crl" << 33 << false;
	QTest::newRow("CRL clipboard") << "crl" << 0 << true;
	QTest::newRow("template") << "template" << 35 << false;
	QTest::newRow("template clipboard") << "template" << 0 << true;
}

/* Every format whose writer fails: the typed error, no file, no success
 * entry (object.export, key.export_private), one failure entry */
void test_service_export_integrity::everyFormatFails()
{
	QFETCH(QString, kind);
	QFETCH(int, format);
	QFETCH(bool, clipboard);
	pki_base *pki = object(kind);
	QVERIFY(pki);
	qint64 seq = lastSeq();
	QString name = dir.filePath("out");
	QCOMPARE(failingExport(pki, format, clipboard, "out"),
		QString("export_failed"));
	QVERIFY2(!QFile::exists(name), "a file was written");
	QCOMPARE(entriesAfter(seq),
		QStringList({ "object.export failure export_failed" }));
}

/* An issuance whose DER encoding fails stores no certificate and no
 * success entry: the fingerprint of empty bytes never reaches the
 * database or the audit log */
void test_service_export_integrity::i2dFailureStoresNothing()
{
	int certs = Store.getAll<pki_x509>().size();
	qint64 seq = lastSeq();
	QDateTime now = QDateTime::currentDateTimeUtc();
	IssuanceSpec ee;
	ee.name = "BTD-199 no DER";
	ee.subject.addEntryByNid(NID_commonName, ee.name);
	ee.key = rsaKey;
	ee.signer = ca;
	ee.notBefore = a1time(now.addDays(-1));
	ee.notAfter = a1time(now.addYears(1));
	ee.hashAlgo = digest(NID_sha256);
	ee.extensions.basicCA = ExtensionSpec::bc_not_ca;
	ee.extensions.keyUsage << "digitalSignature";
	QString code;
	try {
		Fault fault(encodeFault::i2d);
		Database.model<db_x509>()->newCert(ctx, ee);
	} catch (serviceError &err) {
		code = err.code;
	} catch (errorEx &err) {
		code = "errorEx: " + err.getString();
	}
	QCOMPARE(code, QString("encoding_failed"));
	QCOMPARE(Store.getAll<pki_x509>().size(), certs);
	for (const AuditEntry &e : AuditLog::entries()) {
		if (e.seq <= seq)
			continue;
		QVERIFY2(e.result != "success", qPrintable(e.action));
		QVERIFY2(e.params.value("fingerprint").toString() !=
			fingerprint(QByteArray(), EVP_sha256()),
			qPrintable(e.action));
	}
}

XCA_SERVICE_TEST_MAIN(test_service_export_integrity)
#include "test_service_export_integrity.moc"
