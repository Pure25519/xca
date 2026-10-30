/* vi: set sw=4 ts=4:
 *
 * Every loader checks its OpenSSL result itself (BTD-95): _openssl_error()
 * only prints (decision b of 2026-10-28), so a loader that relies on it
 * leaves an object without content behind. Broken input through the
 * import service must end in an import error and an object.import failure
 * entry, with no object in the store or the database and no crash; a
 * broken row of the database is skipped with a message instead of being
 * loaded as an empty object. StrictWarning fails on any other message, and
 * xcaWarning::error() drops an errorEx without text, so a loader that
 * throws one goes unnoticed: the expected messages name their cause.
 *
 * The template loader is the last one the import probe tries; it took any
 * 8 bytes or more as an XCA template (BTD-88), which hid every error of the
 * loaders before it. It accepts only a well-formed template export.
 */

#include <QFile>
#include <QRandomGenerator>
#include <QSqlQuery>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>

#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/exception.h"
#include "lib/importexport.h"
#include "lib/pki_crl.h"
#include "lib/pki_evp.h"
#include "lib/pki_multi.h"
#include "lib/pki_temp.h"
#include "lib/pki_x509.h"
#include "lib/pki_x509req.h"

#include "ServiceTestCase.h"

class test_service_loaders : public ServiceTestCase
{
	Q_OBJECT

	ServiceContext ctx{ ServiceContext::cli, "os:service-test" };

	static int rows(const QString &table);
	static int storedObjects();

  private slots:
	void brokenInput_data();
	void brokenInput();
	void brokenDatabaseRow_data();
	void brokenDatabaseRow();
	void noTemplate_data();
	void noTemplate();
	void templatesImport_data();
	void templatesImport();
	void opensslErrorText();
};

/* -- valid objects, built with OpenSSL ------------------------------------ */

static EVP_PKEY *ecKey()
{
	return EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256");
}

static X509_NAME *cn(const char *name)
{
	X509_NAME *n = X509_NAME_new();
	X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC,
		(const unsigned char *)name, -1, -1, 0);
	return n;
}

static X509 *selfSigned(EVP_PKEY *key, const char *name)
{
	X509 *x = X509_new();
	X509_set_version(x, X509_VERSION_3);
	ASN1_INTEGER_set(X509_get_serialNumber(x), 0x95);
	X509_gmtime_adj(X509_getm_notBefore(x), 0);
	X509_gmtime_adj(X509_getm_notAfter(x), 86400);
	X509_set_pubkey(x, key);
	X509_NAME *n = cn(name);
	X509_set_subject_name(x, n);
	X509_set_issuer_name(x, n);
	X509_NAME_free(n);
	X509_sign(x, key, EVP_sha256());
	return x;
}

static X509_REQ *request(EVP_PKEY *key, const char *name)
{
	X509_REQ *r = X509_REQ_new();
	X509_REQ_set_pubkey(r, key);
	X509_NAME *n = cn(name);
	X509_REQ_set_subject_name(r, n);
	X509_NAME_free(n);
	X509_REQ_sign(r, key, EVP_sha256());
	return r;
}

static X509_CRL *crl(EVP_PKEY *key, X509 *issuer)
{
	X509_CRL *c = X509_CRL_new();
	X509_CRL_set_version(c, X509_CRL_VERSION_2);
	X509_CRL_set_issuer_name(c, X509_get_subject_name(issuer));
	ASN1_TIME *t = ASN1_TIME_set(nullptr, time(nullptr));
	X509_CRL_set1_lastUpdate(c, t);
	ASN1_TIME_adj(t, time(nullptr), 1, 0);
	X509_CRL_set1_nextUpdate(c, t);
	ASN1_TIME_free(t);
	X509_CRL_sign(c, key, EVP_sha256());
	return c;
}

static PKCS7 *pkcs7(X509 *cert)
{
	PKCS7 *p7 = PKCS7_new();
	PKCS7_set_type(p7, NID_pkcs7_signed);
	PKCS7_content_new(p7, NID_pkcs7_data);
	PKCS7_add_certificate(p7, cert);
	return p7;
}

static QByteArray memory(BIO *b)
{
	char *p;
	long n = BIO_get_mem_data(b, &p);
	QByteArray ba(p, (int)n);
	BIO_free(b);
	return ba;
}

#define DER(i2d, obj) [&]() { \
		unsigned char *buf = nullptr; \
		int n = i2d(obj, &buf); \
		QByteArray ba((const char *)buf, n > 0 ? n : 0); \
		OPENSSL_free(buf); \
		return ba; }()
#define PEM(write, obj) [&]() { \
		BIO *b = BIO_new(BIO_s_mem()); \
		write(b, obj); \
		return memory(b); }()

/* -- broken variants ------------------------------------------------------- */

/* The first DER bytes of the body become 0xff: no ASN.1 tag */
static QByteArray brokenPemBody(const QByteArray &pem)
{
	QByteArray ba = pem;
	int body = ba.indexOf('\n') + 1;
	ba.replace(body, 4, "////");
	return ba;
}

static QByteArray truncated(const QByteArray &der)
{
	return der.left(der.size() / 2);
}

/* An EC private key (SEC1) carrying the public point of another key */
static QByteArray inconsistentEcKey(EVP_PKEY *a, EVP_PKEY *b)
{
	QByteArray da = DER(i2d_PrivateKey, a);
	QByteArray db = DER(i2d_PrivateKey, b);
	/* prime256v1: the uncompressed point (65 bytes) ends both */
	da.replace(da.size() - 65, 65, db.right(65));
	BIO *bio = BIO_new(BIO_s_mem());
	PEM_write_bio(bio, "EC PRIVATE KEY", "",
		(const unsigned char *)da.constData(), da.size());
	return memory(bio);
}

int test_service_loaders::rows(const QString &table)
{
	QSqlQuery q;
	if (!q.exec(QString("SELECT COUNT(*) FROM %1").arg(table)) || !q.next())
		return -1;
	return q.value(0).toInt();
}

int test_service_loaders::storedObjects()
{
	return Store.getAll<pki_base>().size();
}

void test_service_loaders::brokenInput_data()
{
	QTest::addColumn<QByteArray>("data");
	/* pki_multi shows the error of a damaged PEM item; DER has none */
	QTest::addColumn<QString>("message");

	EVP_PKEY *key = ecKey(), *other = ecKey();
	X509 *cert = selfSigned(key, "BTD-95 loader");
	X509_REQ *req = request(key, "BTD-95 loader");
	X509_CRL *revocations = crl(key, cert);
	PKCS7 *p7 = pkcs7(cert);
	PKCS12 *p12 = PKCS12_create("btd95", "BTD-95", key, cert, nullptr,
		0, 0, 0, 0, 0);

	QTest::newRow("certificate PEM body")
		<< brokenPemBody(PEM(PEM_write_bio_X509, cert))
		<< QString("Unable to load the certificate in file");
	QTest::newRow("certificate DER truncated")
		<< truncated(DER(i2d_X509, cert))
		<< QString("");
	QTest::newRow("request PEM body")
		<< brokenPemBody(PEM(PEM_write_bio_X509_REQ, req))
		<< QString("Unable to load the certificate request");
	QTest::newRow("request DER truncated")
		<< truncated(DER(i2d_X509_REQ, req))
		<< QString("");
	QTest::newRow("CRL PEM body")
		<< brokenPemBody(PEM(PEM_write_bio_X509_CRL, revocations))
		<< QString("Unable to load the revocation list");
	QTest::newRow("CRL DER truncated")
		<< truncated(DER(i2d_X509_CRL, revocations))
		<< QString("");
	QTest::newRow("PKCS#7 PEM body")
		<< brokenPemBody(PEM(PEM_write_bio_PKCS7, p7))
		<< QString("Unable to load the PKCS#7 file");
	QTest::newRow("PKCS#7 DER truncated")
		<< truncated(DER(i2d_PKCS7, p7))
		<< QString("");
	QTest::newRow("PKCS#12 truncated")
		<< truncated(DER(i2d_PKCS12, p12))
		<< QString("");
	QTest::newRow("private key PEM body")
		<< brokenPemBody([&]() {
			BIO *b = BIO_new(BIO_s_mem());
			PEM_write_bio_PrivateKey(b, key, nullptr, nullptr, 0,
				nullptr, nullptr);
			return memory(b); }())
		<< QString("cannot be read");
	QTest::newRow("private key DER truncated")
		<< truncated(DER(i2d_PrivateKey, key))
		<< QString("");
	QTest::newRow("public key PEM body")
		<< brokenPemBody(PEM(PEM_write_bio_PUBKEY, key))
		<< QString("cannot be read");
	QTest::newRow("inconsistent EC key")
		<< inconsistentEcKey(key, other)
		<< QString("incomplete or inconsistent");

	PKCS12_free(p12);
	PKCS7_free(p7);
	X509_CRL_free(revocations);
	X509_REQ_free(req);
	X509_free(cert);
	EVP_PKEY_free(other);
	EVP_PKEY_free(key);
}

/* An import error, a failure entry and nothing stored */
void test_service_loaders::brokenInput()
{
	QFETCH(QByteArray, data);
	QFETCH(QString, message);
	if (!message.isEmpty())
		warning->expectMessage(message);
	int objects = storedObjects(), items = rows("items");
	int audit = AuditLog::entries().size();

	ImportSpec spec;
	spec.data = data;
	spec.dataName = "btd95-broken";
	spec.passwordSource = "pass:btd95";
	try {
		ImportResult r = Database.importItems(ctx, spec);
		QStringList what;
		for (pki_base *pki : r.all())
			what << QString("%1 '%2'").arg(pki->getTypeString(),
				pki->getIntName());
		QFAIL(qPrintable("imported " + what.join(", ")));
	} catch (serviceError &err) {
		QVERIFY2(err.code == "no_pki_data" ||
			err.code == "unreadable_input", qPrintable(err.code));
	}
	QCOMPARE(storedObjects(), objects);
	QCOMPARE(rows("items"), items);
	QList<AuditEntry> entries = AuditLog::entries();
	QCOMPARE(entries.size(), audit + 1);
	QCOMPARE(entries.last().action, QString("object.import"));
	QCOMPARE(entries.last().result, QString("failure"));
}

void test_service_loaders::brokenDatabaseRow_data()
{
	QTest::addColumn<QString>("table");
	QTest::addColumn<QString>("column");
	QTest::addColumn<QString>("type");

	QTest::newRow("certificate") << "certs" << "cert" << "x509";
	QTest::newRow("request") << "requests" << "request" << "x509req";
	QTest::newRow("CRL") << "crls" << "crl" << "crl";
	QTest::newRow("key") << "public_keys" << "\"public\"" << "key";
}

/* A row whose DER no longer decodes is reported and skipped; the other
 * objects load */
void test_service_loaders::brokenDatabaseRow()
{
	QFETCH(QString, table);
	QFETCH(QString, column);
	QFETCH(QString, type);

	EVP_PKEY *key = ecKey();
	X509 *cert = selfSigned(key, "BTD-95 row");
	X509_REQ *req = request(key, "BTD-95 row request");
	X509_CRL *revocations = crl(key, cert);
	ImportSpec spec;
	spec.data = PEM(PEM_write_bio_X509, cert) +
		PEM(PEM_write_bio_X509_REQ, req) +
		PEM(PEM_write_bio_X509_CRL, revocations) +
		PEM(PEM_write_bio_PUBKEY, key);
	spec.dataName = "btd95-row";
	X509_CRL_free(revocations);
	X509_REQ_free(req);
	X509_free(cert);
	EVP_PKEY_free(key);
	QCOMPARE(Database.importItems(ctx, spec).created.size(), 4);

	QSqlQuery q;
	QVERIFY(q.exec(QString("UPDATE %1 SET %2='/////w=='")
		.arg(table, column)));
	warning->expectMessage("cannot be decoded");
	reopenDatabase();

	QCOMPARE(storedObjects(), 3);
	for (pki_base *pki : Store.getAll<pki_base>()) {
		if (type == "x509")
			QVERIFY(!dynamic_cast<pki_x509 *>(pki));
		else if (type == "x509req")
			QVERIFY(!dynamic_cast<pki_x509req *>(pki));
		else if (type == "crl")
			QVERIFY(!dynamic_cast<pki_crl *>(pki));
		else
			QVERIFY(!dynamic_cast<pki_key *>(pki));
	}
}

/* A valid template export: header (size, version) and the data */
static QByteArray templateExport(QByteArray *pem = nullptr)
{
	pki_temp tmpl("BTD-88 template");
	QByteArray p = tmpl.toExportData();
	if (pem)
		*pem = p;
	QByteArray body;
	for (const QByteArray &line : p.split('\n')) {
		if (!line.startsWith("-----"))
			body += line.trimmed();
	}
	return QByteArray::fromBase64(body);
}

void test_service_loaders::noTemplate_data()
{
	QTest::addColumn<QByteArray>("data");

	QTest::newRow("text") << QByteArray("no certificate here");
	QRandomGenerator rnd(88);
	for (int n : { 8, 9, 16, 33, 64 }) {
		QByteArray ba(n, 0);
		for (char &c : ba)
			c = (char)rnd.bounded(256);
		QTest::newRow(qPrintable(QString("%1 random bytes").arg(n)))
			<< ba;
	}
	QByteArray valid = templateExport();
	QTest::newRow("truncated template")
		<< valid.left(valid.size() - 7);
	QByteArray longer = valid + QByteArray("trailing");
	QTest::newRow("template with trailing data") << longer;
}

/* No PKI data, neither for the import service nor for the probe:
 * no object and no success entry */
void test_service_loaders::noTemplate()
{
	QFETCH(QByteArray, data);
	int objects = storedObjects(), audit = AuditLog::entries().size();

	pki_multi read;
	read.probeData(data, "btd88-junk");
	QList<pki_base *> items = read.pull();
	int probed = items.size();
	qDeleteAll(items);
	QCOMPARE(probed, 0);
	QCOMPARE(read.failed_files, QStringList("btd88-junk"));

	ImportSpec spec;
	spec.data = data;
	spec.dataName = "btd88-junk";
	try {
		Database.importItems(ctx, spec);
		QFAIL("importItems() did not throw");
	} catch (serviceError &err) {
		QCOMPARE(err.code, QString("no_pki_data"));
	}
	QCOMPARE(storedObjects(), objects);
	QCOMPARE(Store.getAll<pki_temp>().size(), 0);
	QList<AuditEntry> entries = AuditLog::entries();
	QCOMPARE(entries.size(), audit + 1);
	QCOMPARE(entries.last().result, QString("failure"));
}

void test_service_loaders::templatesImport_data()
{
	QTest::addColumn<QByteArray>("data");

	QByteArray pem;
	QByteArray binary = templateExport(&pem);
	QTest::newRow("PEM, current version") << pem;
	QTest::newRow("binary, current version") << binary;
	/* exports of XCA 2007 and 2009 (misc/CA.xca of the fork's git
	 * history, data/README.md) */
	for (const char *name : { "CA-v2.xca", "CA-v6.xca" }) {
		QFile f(QString(SERVICE_TEST_DATA "/templates/") + name);
		QVERIFY(f.open(QIODevice::ReadOnly));
		QTest::newRow(name) << f.readAll();
	}
}

/* Valid templates keep importing, the old binary versions too */
void test_service_loaders::templatesImport()
{
	QFETCH(QByteArray, data);
	ImportSpec spec;
	spec.data = data;
	spec.dataName = "btd88-template";
	ImportResult r = Database.importItems(ctx, spec);
	QCOMPARE(r.created.size(), 1);
	QVERIFY(dynamic_cast<pki_temp *>(r.created[0]));
}

/* The text of the OpenSSL errors: a fallback for an empty queue, the data
 * string of an error, the queue empty afterwards */
void test_service_loaders::opensslErrorText()
{
	ERR_clear_error();
	QCOMPARE(take_openssl_errors(), QString("unknown OpenSSL error"));

	ERR_raise_data(ERR_LIB_USER, 1, "BTD-95 data %d", 7);
	ERR_raise(ERR_LIB_USER, 2);
	QStringList lines = take_openssl_errors().split("\n");
	QCOMPARE(lines.size(), 2);
	QVERIFY2(lines[0].endsWith("(BTD-95 data 7)"), qPrintable(lines[0]));
	QVERIFY2(!lines[1].contains("BTD-95"), qPrintable(lines[1]));
	QCOMPARE(ERR_peek_error(), 0UL);
}

XCA_SERVICE_TEST_MAIN(test_service_loaders)
#include "test_service_loaders.moc"
