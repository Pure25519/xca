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
#include <algorithm>
#include <QRandomGenerator>
#include <QSqlQuery>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/db_key.h"
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
	void brokenCaRowThenLeaf();
	void passwordChangeWithBrokenKeyRow();
	void staleErrorQueue();
	void noTemplate_data();
	void noTemplate();
	void templatesImport_data();
	void templatesImport();
	void opensslErrorText();
	void templateRowTrailingBytes();
	void nameEntryRefused();
	void requestAttributeRefused();
	void ignoredErrorText();
	void skippedRowsAudited();
	void skippedRowsOncePerChange();
	void skippedRowsDatabaseLocked();
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
	/* with the OpenSSL reason: d2i_bytearray() cleared the queue
	 * before (review of xca#59, MINOR 3) */
	warning->expectMessage("encoding routines");
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

/* A CA that signs a leaf */
static X509 *caCert(EVP_PKEY *key)
{
	X509 *x = selfSigned(key, "BTD-95 row CA");
	X509V3_CTX v3;
	X509V3_set_ctx_nodb(&v3);
	X509V3_set_ctx(&v3, x, x, nullptr, nullptr, 0);
	X509_EXTENSION *bc = X509V3_EXT_conf_nid(nullptr, &v3,
		NID_basic_constraints, "critical,CA:TRUE");
	X509_add_ext(x, bc, -1);
	X509_EXTENSION_free(bc);
	X509_sign(x, key, EVP_sha256());
	return x;
}

static X509 *leafOf(X509 *ca, EVP_PKEY *caKey, EVP_PKEY *key)
{
	X509 *x = X509_new();
	X509_set_version(x, X509_VERSION_3);
	ASN1_INTEGER_set(X509_get_serialNumber(x), 0x9501);
	X509_gmtime_adj(X509_getm_notBefore(x), 0);
	X509_gmtime_adj(X509_getm_notAfter(x), 86400);
	X509_set_pubkey(x, key);
	X509_NAME *n = cn("BTD-95 row leaf");
	X509_set_subject_name(x, n);
	X509_NAME_free(n);
	X509_set_issuer_name(x, X509_get_subject_name(ca));
	X509_sign(x, caKey, EVP_sha256());
	return x;
}

/* A CA row left out on open keeps its x509super row: the import of a
 * certificate with that issuer hash crashed in searchIssuer(), which
 * read the missing issuer before its NULL check (review of xca#59,
 * blocker 1) */
void test_service_loaders::brokenCaRowThenLeaf()
{
	EVP_PKEY *caKey = ecKey(), *leafKey = ecKey();
	X509 *ca = caCert(caKey);
	X509 *leaf = leafOf(ca, caKey, leafKey);
	ImportSpec spec;
	spec.data = PEM(PEM_write_bio_X509, ca);
	spec.dataName = "btd95-ca";
	QByteArray leafPem = PEM(PEM_write_bio_X509, leaf);
	X509_free(leaf);
	X509_free(ca);
	EVP_PKEY_free(leafKey);
	EVP_PKEY_free(caKey);
	QCOMPARE(Database.importItems(ctx, spec).created.size(), 1);

	QSqlQuery q;
	QVERIFY(q.exec("UPDATE certs SET cert='/////w=='"));
	warning->expectMessage("cannot be decoded");
	reopenDatabase();
	QCOMPARE(storedObjects(), 0);

	ImportSpec in;
	in.data = leafPem;
	in.dataName = "btd95-leaf";
	ImportResult r = Database.importItems(ctx, in);
	QCOMPARE(r.created.size(), 1);
	pki_x509 *imported = dynamic_cast<pki_x509 *>(r.created[0]);
	QVERIFY(imported);
	QVERIFY(!imported->getSigner());
}

/* A key whose row was left out on open would keep the old password while
 * the password changes: the change is refused (review of xca#59,
 * MINOR 2) */
void test_service_loaders::passwordChangeWithBrokenKeyRow()
{
	pki_key *key = Database.model<db_key>()->newKey(ctx,
		keyjob("EC:prime256v1"), "BTD-95 key");
	QVERIFY(key);
	QString hash = Settings["pwhash"];
	QSqlQuery q;
	QVERIFY(q.exec("UPDATE public_keys SET \"public\"='/////w=='"));
	warning->expectMessage("cannot be decoded");
	reopenDatabase();
	Passwd pass;
	pass = "BTD-95-new-password";
	try {
		Database.model<db_key>()->changeDatabasePassword(pass);
		QFAIL("the password changed with a key left out");
	} catch (serviceError &err) {
		QCOMPARE(err.code, QString("database_incomplete"));
	}
	QCOMPARE(QString(Settings["pwhash"]), hash);
}

/* An old entry of the OpenSSL error queue does not reject a valid object
 * (review of xca#59, MINOR 5): fromBytes() took any entry for a failure */
void test_service_loaders::staleErrorQueue()
{
	EVP_PKEY *key = ecKey();
	X509 *cert = selfSigned(key, "BTD-95 stale");
	X509_REQ *req = request(key, "BTD-95 stale");
	X509_CRL *revocations = crl(key, cert);
	QByteArray certPem = PEM(PEM_write_bio_X509, cert);
	QByteArray reqPem = PEM(PEM_write_bio_X509_REQ, req);
	QByteArray crlPem = PEM(PEM_write_bio_X509_CRL, revocations);
	X509_CRL_free(revocations);
	X509_REQ_free(req);
	X509_free(cert);
	EVP_PKEY_free(key);

	pki_x509 x;
	ERR_raise(ERR_LIB_USER, 95);
	x.fromBytes(certPem, "btd95-stale.pem");
	pki_x509req r;
	ERR_raise(ERR_LIB_USER, 95);
	r.fromBytes(reqPem, "btd95-stale.csr");
	pki_crl c;
	ERR_raise(ERR_LIB_USER, 95);
	c.fromBytes(crlPem, "btd95-stale.crl");
	QCOMPARE(x.getSubject().getEntryByNid(NID_commonName),
		QString("BTD-95 stale"));
}


/* -- BTD-209: follow-ups of the review of xca#59 ------------------------- */

/* A stored template row with bytes after the settings map loads: the
 * end-of-data check of BTD-88 is for imports only (MINOR 7). The export
 * file with trailing data stays refused (noTemplate). */
void test_service_loaders::templateRowTrailingBytes()
{
	ImportSpec spec;
	spec.data = templateExport();
	spec.dataName = "btd209-template";
	QCOMPARE(Database.importItems(ctx, spec).created.size(), 1);

	QSqlQuery q;
	QVERIFY(q.exec("SELECT item, template FROM templates") && q.next());
	qlonglong item = q.value(0).toLongLong();
	QByteArray data = QByteArray::fromBase64(q.value(1).toByteArray());
	q.finish();
	QVERIFY(q.prepare("UPDATE templates SET template=? WHERE item=?"));
	q.bindValue(0, QString::fromLatin1((data + "BTD-209").toBase64()));
	q.bindValue(1, item);
	QVERIFY2(q.exec(), qPrintable(q.lastError().text()));

	reopenDatabase();
	QList<pki_temp *> temps = Store.getAll<pki_temp>();
	QCOMPARE(temps.size(), 1);
	QCOMPARE(temps[0]->getIntName(), QString("BTD-88 template"));
}

/* An entry OpenSSL refuses to add (an unknown NID) ends in a typed error,
 * not in a name without it (MINOR 10) */
void test_service_loaders::nameEntryRefused()
{
	x509name n;
	QString code;
	try {
		n.addEntryByNid(99999, "BTD-209");
	} catch (serviceError &err) {
		code = err.code;
	}
	QCOMPARE(code, QString("invalid_string"));
	QCOMPARE(n.entryCount(), 0);
}

void test_service_loaders::requestAttributeRefused()
{
	pki_x509req req("BTD-209 request");
	QString code;
	try {
		req.addAttribute(99999, "BTD-209");
	} catch (serviceError &err) {
		code = err.code;
	}
	QCOMPARE(code, QString("invalid_string"));
}

/* _ign_openssl_error() takes the text of the queue like
 * take_openssl_errors(), with the data string, and leaves the queue empty;
 * it no longer writes OpenSSL's static buffer (MINOR 11) */
void test_service_loaders::ignoredErrorText()
{
	ERR_clear_error();
	QVERIFY(!ign_openssl_error());
	ERR_raise_data(ERR_LIB_USER, 1, "BTD-209 data %d", 9);
	QTest::ignoreMessage(QtDebugMsg, QRegularExpression(
		R"(IGNORED .*test_service_loaders.*\(BTD-209 data 9\))"));
	QVERIFY(ign_openssl_error());
	QCOMPARE(ERR_peek_error(), 0UL);
}

/* Rows left out on open leave a trace in the audit log: one entry
 * database.rows_skipped naming every skipped item, and one message
 * naming the same items (implementer reply on xca#59) */
void test_service_loaders::skippedRowsAudited()
{
	EVP_PKEY *key = ecKey();
	ImportSpec keySpec;
	keySpec.data = PEM(PEM_write_bio_PUBKEY, key);
	EVP_PKEY_free(key);
	keySpec.dataName = "btd209-key";
	QCOMPARE(Database.importItems(ctx, keySpec).created.size(), 1);
	ImportSpec tmplSpec;
	tmplSpec.data = templateExport();
	tmplSpec.dataName = "btd209-template";
	QCOMPARE(Database.importItems(ctx, tmplSpec).created.size(), 1);
	QString keyId = Store.getAll<pki_key>()[0]->getSqlItemId().toString();
	QString tmplId = Store.getAll<pki_temp>()[0]->getSqlItemId().toString();
	int audit = AuditLog::entries().size();

	QSqlQuery q;
	QVERIFY(q.exec("UPDATE public_keys SET \"public\"='/////w=='"));
	QVERIFY(q.exec("UPDATE templates SET template='/////w=='"));
	warning->expectMessage(QString("key %1").arg(keyId));
	reopenDatabase();

	QCOMPARE(storedObjects(), 0);
	QList<AuditEntry> entries = AuditLog::entries();
	QList<AuditEntry> skipped;
	for (int i = audit; i < entries.size(); i++)
		if (entries[i].action == "database.rows_skipped")
			skipped << entries[i];
	QCOMPARE(skipped.size(), 1);
	QCOMPARE(skipped[0].result, QString("success"));
	QCOMPARE(skipped[0].params.value("count").toLongLong(), 2LL);
	QString items = skipped[0].params.value("skipped_items").toString();
	QVERIFY2(items.split(",").contains("key:" + keyId), qPrintable(items));
	QVERIFY2(items.split(",").contains("template:" + tmplId),
		qPrintable(items));
	QCOMPARE(skipped[0].params.value("warning").toString(),
		QString("rows_skipped"));
	QVERIFY(AuditLog::verify().ok());
}

/* One database.rows_skipped entry per change of the skipped set, not
 * per open (BTD-221): every open appended an identical entry, also the
 * read-only ones of --list-items or --print */
void test_service_loaders::skippedRowsOncePerChange()
{
	ImportSpec spec;
	for (int i = 0; i < 2; i++) {
		EVP_PKEY *key = ecKey();
		spec.data = PEM(PEM_write_bio_PUBKEY, key);
		EVP_PKEY_free(key);
		spec.dataName = QString("btd221-key%1").arg(i);
		QCOMPARE(Database.importItems(ctx, spec).created.size(), 1);
	}
	QList<pki_key *> keys = Store.getAll<pki_key>();
	QCOMPARE(keys.size(), 2);
	QString id0 = keys[0]->getSqlItemId().toString();
	QString id1 = keys[1]->getSqlItemId().toString();
	QMap<QString, QString> good;
	QSqlQuery q;
	QVERIFY(q.exec("SELECT item, \"public\" FROM public_keys"));
	while (q.next())
		good[q.value(0).toString()] = q.value(1).toString();
	auto setPublic = [&](const QString &id, const QString &value) {
		QSqlQuery u;
		u.prepare("UPDATE public_keys SET \"public\"=? WHERE item=?");
		u.addBindValue(value);
		u.addBindValue(id);
		QVERIFY(u.exec());
	};
	/* the skipped_items of every entry from first on, in order */
	auto skippedEntries = [](int first) {
		QStringList list;
		QList<AuditEntry> entries = AuditLog::entries();
		for (int i = first; i < entries.size(); i++)
			if (entries[i].action == "database.rows_skipped")
				list << QString("%1:%2").arg(entries[i].params
					.value("count").toLongLong()).arg(entries[i]
					.params.value("skipped_items").toString());
		return list;
	};
	int audit = AuditLog::entries().size();

	/* one broken row, three opens: one entry */
	setPublic(id0, "/////w==");
	for (int i = 0; i < 3; i++) {
		warning->expectMessage(QString("key %1").arg(id0));
		reopenDatabase();
		QVERIFY(AuditLog::verify().ok());
	}
	QCOMPARE(skippedEntries(audit), QStringList("1:key:" + id0));

	/* a second broken row changes the set: a new entry */
	setPublic(id1, "/////w==");
	warning->expectMessage(QString("key %1").arg(id1));
	reopenDatabase();
	QStringList both { "key:" + id0, "key:" + id1 };
	both.sort();
	QCOMPARE(skippedEntries(audit).size(), 2);
	QCOMPARE(skippedEntries(audit).last(), "2:" + both.join(","));

	/* the same set in another order is the same set: an entry written
	 * in reverse order (as older code could) adds nothing */
	{
		Transaction;
		QVERIFY(TransBegin());
		std::reverse(both.begin(), both.end());
		AuditLog::append(ctx, "database.rows_skipped", "database",
			QString(), AuditParams().set("count", 2LL)
				.set("skipped_items", both.join(",")));
		QVERIFY(TransCommit());
	}
	int before = skippedEntries(audit).size();
	warning->expectMessage(QString("key %1").arg(id0));
	reopenDatabase();
	QCOMPARE(skippedEntries(audit).size(), before);

	/* one repaired, one still broken: a new entry */
	setPublic(id0, good[id0]);
	warning->expectMessage(QString("key %1").arg(id1));
	reopenDatabase();
	QCOMPARE(skippedEntries(audit).last(), "1:key:" + id1);

	/* all repaired: one closing entry with count 0, then nothing */
	setPublic(id1, good[id1]);
	reopenDatabase();
	QCOMPARE(skippedEntries(audit).last(), QString("0:"));
	before = skippedEntries(audit).size();
	reopenDatabase();
	reopenDatabase();
	QCOMPARE(skippedEntries(audit).size(), before);
	QCOMPARE(storedObjects(), 2);
	QVERIFY(AuditLog::verify().ok());
}

/* A second connection holds the write lock while it lives (BEGIN
 * IMMEDIATE): reading works, every write fails with SQLITE_BUSY */
class WriteLock
{
	QString name{ "btd209-lock" };

  public:
	WriteLock(const QString &file)
	{
		QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", name);
		db.setDatabaseName(file);
		db.setConnectOptions("QSQLITE_BUSY_TIMEOUT=0");
		if (!db.open() || !QSqlQuery(db).exec("BEGIN IMMEDIATE"))
			qFatal("BTD-209 test: no write lock");
	}
	~WriteLock()
	{
		{
			QSqlDatabase db = QSqlDatabase::database(name);
			QSqlQuery(db).exec("ROLLBACK");
			db.close();
		}
		QSqlDatabase::removeDatabase(name);
	}
};

/* The entry of the skipped rows is best effort: with the database locked
 * by another connection the open still works and reads, the rows are
 * named, and no entry or part of one is left (condition of the review
 * of xca#75). The read-only file is test_cli_skipped_rows_readonly. */
void test_service_loaders::skippedRowsDatabaseLocked()
{
	EVP_PKEY *key = ecKey();
	ImportSpec keySpec;
	keySpec.data = PEM(PEM_write_bio_PUBKEY, key);
	EVP_PKEY_free(key);
	keySpec.dataName = "btd209-locked";
	QCOMPARE(Database.importItems(ctx, keySpec).created.size(), 1);
	QSqlQuery q;
	QVERIFY(q.exec("UPDATE public_keys SET \"public\"='/////w=='"));
	q.finish();
	int audit = AuditLog::entries().size();

	Database.close();
	{
		WriteLock lock(dbFile);
		warning->expectMessage("left out");
		openDatabase();
		QVERIFY(Database.isOpen());
		QCOMPARE(storedObjects(), 0);
		QCOMPARE(AuditLog::entries().size(), audit);
	}
	QCOMPARE(AuditLog::entries().size(), audit);
	QVERIFY(AuditLog::verify().ok());
}

XCA_SERVICE_TEST_MAIN(test_service_loaders)
#include "test_service_loaders.moc"
