/* vi: set sw=4 ts=4:
 *
 * JSON documents of the XCA objects (BTD-39, lib/json_report.h): the
 * fixtures of data/json (made once by data/json/gen.sh) are imported into
 * a fresh database, and the document of each object type is compared
 * with the fixed expected JSON in the same folder. Only the creation date
 * is volatile: it is checked against the item and then set to the value
 * of the expected file. Ids are those of a fresh database in import order.
 * The display text of extensions is not compared (BTD-182). gen.sh
 * re-issues the certificates and the CRL with the same keys; afterwards
 * the .actual files of a run in the temporary directory are the new
 * expected files, after a review of their diff.
 */

#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QRegularExpression>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "lib/asn1int.h"
#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/db_temp.h"
#include "lib/exception.h"
#include "lib/importexport.h"
#include "lib/json_report.h"
#include "lib/pki_crl.h"
#include "lib/pki_evp.h"
#include "lib/pki_temp.h"
#include "lib/pki_x509.h"
#include "lib/pki_x509req.h"
#include "lib/template.h"

#include "ServiceTestCase.h"

#define DATA SERVICE_TEST_DATA "/json/"

class test_service_json : public ServiceTestCase
{
	Q_OBJECT

	ServiceContext ctx{ ServiceContext::cli, "os:service-test" };

	static const char importPassword[];
	static const char ownPassword[];

	void importFixtures();
	pki_base *item(const QString &type, const QString &name);
	static void compare(QJsonObject actual, const QString &expectedFile,
				const pki_base *pki);
	static void noSecrets(const QJsonObject &doc);
	static pki_crl *makeCrl(const char *number, bool nextUpdate);

  private slots:
	void certificate();
	void fileCertificate();
	void request();
	void requestWithoutChallenge();
	void crl();
	void crlNumberRange_data();
	void crlNumberRange();
	void crlWithoutNextUpdate();
	void keys();
	void templates();
	void lists();
	void errors();
	void timestamps();
};

const char test_service_json::importPassword[] = "Import-Secret-11";
const char test_service_json::ownPassword[] = "Own-Secret-77";

/* One file after the other, so the ids are those of the order here */
void test_service_json::importFixtures()
{
	static const char * const files[] = {
		"ca.crt", "ca.key", "device.crt", "device.csr", "ca.crl",
		"device.pub", "rsa-enc.key", "ec.key", "own.key",
		"rsa-pss.key",
	};
	for (const char *f : files) {
		ImportSpec spec;
		spec.files << QString(DATA) + f;
		if (QString(f) == "rsa-enc.key")
			spec.passwordSource = QString("pass:") + importPassword;
		ImportResult r = Database.importItems(ctx, spec);
		QVERIFY2(r.created.size() == 1, f);
		/* Comments name the import path; fixed for the comparison */
		r.created[0]->setComment(QString());
	}
}

pki_base *test_service_json::item(const QString &type, const QString &name)
{
	for (pki_base *pki : Store.getAll<pki_base>()) {
		if (JsonReport::objectType(pki) == type &&
		    pki->getIntName() == name)
			return pki;
	}
	return nullptr;
}

/* The secrets of the fixtures appear nowhere */
void test_service_json::noSecrets(const QJsonObject &doc)
{
	QByteArray line = JsonReport::line(doc);
	for (const char *secret : { "PRIVATE KEY", "ENCRYPTED", importPassword,
				ownPassword, "Chall-Secret-42", dbPassword }) {
		QVERIFY2(!line.contains(secret), secret);
	}
}

/* The value of an extension is the display text of OpenSSL, which
 * changes between OpenSSL versions (AKID with or without "keyid:", the
 * names of extended key usages). It must be there but is not compared;
 * name, oid, critical and everything else are (BTD-182). Returns the
 * document without these texts; *missing names an extension without
 * one. */
static QJsonValue withoutExtensionText(const QJsonValue &v, QString *missing)
{
	if (v.isArray()) {
		QJsonArray a;
		for (const QJsonValue &e : v.toArray())
			a.append(withoutExtensionText(e, missing));
		return a;
	}
	if (!v.isObject())
		return v;
	QJsonObject o = v.toObject();
	for (auto it = o.begin(); it != o.end(); ++it) {
		if (it.key() != "extensions" || !it.value().isArray()) {
			it.value() = withoutExtensionText(it.value(), missing);
			continue;
		}
		QJsonArray exts;
		for (const QJsonValue &e : it.value().toArray()) {
			QJsonObject ext = e.toObject();
			if (ext.value("value").toString().isEmpty())
				*missing = ext.value("oid").toString();
			ext.remove("value");
			exts.append(ext);
		}
		it.value() = exts;
	}
	return o;
}

void test_service_json::compare(QJsonObject actual,
			const QString &expectedFile, const pki_base *pki)
{
	/* A missing expected file fails below, with the actual document */
	QFile f(QString(DATA) + expectedFile);
	QJsonObject expected;
	if (f.open(QIODevice::ReadOnly)) {
		QJsonParseError err;
		expected = QJsonDocument::fromJson(f.readAll(), &err).object();
		QVERIFY2(err.error == QJsonParseError::NoError,
			CCHAR(err.errorString()));
	}

	/* One line, parsable, the same document */
	QByteArray line = JsonReport::line(actual);
	QVERIFY(line.endsWith('\n'));
	QCOMPARE(line.count('\n'), 1);
	QCOMPARE(QJsonDocument::fromJson(line).object(), actual);
	noSecrets(actual);

	/* The volatile creation date: the item's, then the expected one */
	if (pki && pki->getSqlItemId().isValid()) {
		QCOMPARE(actual.value("created").toString(),
			AuditLog::rfc3339(pki->getInsertionDate()));
		QVERIFY(QRegularExpression("^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
			"[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]+)?Z$")
			.match(actual.value("created").toString()).hasMatch());
		actual["created"] = expected.value("created");
	}
	QString missing;
	QJsonObject full = actual;
	actual = withoutExtensionText(actual, &missing).toObject();
	QVERIFY2(missing.isEmpty(), CCHAR(QString("extension %1 has no value")
		.arg(missing)));
	QString ignored;
	expected = withoutExtensionText(expected, &ignored).toObject();
	if (actual != expected) {
		QFile out(QDir::temp().filePath(expectedFile + ".actual"));
		if (out.open(QIODevice::WriteOnly))
			out.write(QJsonDocument(full).toJson());
		QFAIL(CCHAR(QString("%1 differs, actual in %2:\n%3")
			.arg(expectedFile).arg(out.fileName())
			.arg(QString(QJsonDocument(full).toJson()))));
	}
}

void test_service_json::certificate()
{
	importFixtures();
	pki_x509 *ca = dynamic_cast<pki_x509 *>(item("certificate",
							"JSON Test CA"));
	pki_x509 *device = dynamic_cast<pki_x509 *>(item("certificate",
							"plc11"));
	QVERIFY(ca && device);
	device->setComment("OPC UA server certificate of plc11");

	compare(JsonReport::certificate(ca), "ca.crt.json", ca);
	compare(JsonReport::certificate(device), "device.crt.json", device);
	compare(JsonReport::object(device), "device.crt.json", device);
}

/* An item read from a file, not stored: id and created are null, it
 * refers to no item of the database (decision 4 of BTD-39) */
void test_service_json::fileCertificate()
{
	pki_x509 cert;
	cert.fload(QString(DATA) + "device.crt");
	cert.setComment("OPC UA server certificate of plc11");
	cert.setIntName("plc11");
	cert.pkiSource = generated;

	QJsonObject doc = JsonReport::certificate(&cert);
	QVERIFY(doc.value("id").isNull());
	QVERIFY(doc.value("created").isNull());
	QVERIFY(doc.value("issuer_item").isNull());
	QVERIFY(doc.value("key_item").isNull());
	QVERIFY(doc.value("revocation").isNull());
	compare(doc, "device-file.crt.json", nullptr);
}

void test_service_json::request()
{
	importFixtures();
	pki_x509req *req = dynamic_cast<pki_x509req *>(item("request",
							"plc11"));
	QVERIFY(req);
	QJsonObject doc = JsonReport::request(req);

	/* The challengePassword attribute is a secret (PLAN.md 6.4), and
	 * the signed request contains it: no pem, no der, only the flag */
	for (const QJsonValue &a : doc.value("attributes").toArray())
		QVERIFY(a.toObject().value("oid") != "1.2.840.113549.1.9.7");
	QCOMPARE(doc.value("challenge_password_present"), QJsonValue(true));
	QVERIFY(!doc.contains("pem"));
	QVERIFY(!doc.contains("der"));
	compare(doc, "device.csr.json", req);
}

/* Without a challenge password the request is embedded as PEM */
void test_service_json::requestWithoutChallenge()
{
	importFixtures();
	ImportSpec spec;
	spec.files << QString(DATA) + "plain.csr";
	ImportResult r = Database.importItems(ctx, spec);
	QCOMPARE(r.created.size(), 1);
	r.created[0]->setComment(QString());
	pki_x509req *req = dynamic_cast<pki_x509req *>(r.created[0]);
	QVERIFY(req);
	QJsonObject doc = JsonReport::request(req);
	QCOMPARE(doc.value("challenge_password_present"), QJsonValue(false));
	QVERIFY(doc.value("pem").toString().startsWith(
		"-----BEGIN CERTIFICATE REQUEST-----\n"));
	compare(doc, "plain.csr.json", req);
}

void test_service_json::crl()
{
	importFixtures();
	pki_crl *c = dynamic_cast<pki_crl *>(item("crl", "JSON Test CA"));
	QVERIFY(c);
	QJsonObject doc = JsonReport::crl(c);
	QCOMPARE(doc.value("revoked_count").toInt(),
		doc.value("revoked").toArray().size());
	compare(doc, "ca.crl.json", c);
}

/* A CRL of its own key, signed here, with the given cRLNumber (decimal,
 * or none for nullptr) and with or without nextUpdate (BTD-182) */
pki_crl *test_service_json::makeCrl(const char *number, bool nextUpdate)
{
	EVP_PKEY *key = EVP_EC_gen("P-256");
	X509_CRL *c = X509_CRL_new();
	X509_NAME *name = X509_NAME_new();
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8,
		(const unsigned char *)"JSON Range CA", -1, -1, 0);
	X509_CRL_set_version(c, X509_CRL_VERSION_2);
	X509_CRL_set_issuer_name(c, name);
	ASN1_TIME *t = ASN1_TIME_new();
	ASN1_TIME_set_string_X509(t, "20261101000000Z");
	X509_CRL_set1_lastUpdate(c, t);
	if (nextUpdate) {
		ASN1_TIME_set_string_X509(t, "20261108000000Z");
		X509_CRL_set1_nextUpdate(c, t);
	}
	if (number) {
		BIGNUM *bn = nullptr;
		BN_dec2bn(&bn, number);
		ASN1_INTEGER *n = BN_to_ASN1_INTEGER(bn, nullptr);
		X509_CRL_add1_ext_i2d(c, NID_crl_number, n, 0, 0);
		ASN1_INTEGER_free(n);
		BN_free(bn);
	}
	X509_CRL_sign(c, key, EVP_sha256());
	BIO *bio = BIO_new(BIO_s_mem());
	PEM_write_bio_X509_CRL(bio, c);
	pki_crl *crl = new pki_crl("range");
	crl->fromPEM_BIO(bio, "range");
	BIO_free(bio);
	ASN1_TIME_free(t);
	X509_NAME_free(name);
	X509_CRL_free(c);
	EVP_PKEY_free(key);
	return crl;
}

/* MINOR 4 of the review of BTD-39 (BTD-182): a cRLNumber is exact, an
 * integer up to 2^53-1 (what a JSON parser keeps exactly) and the
 * decimal string beyond, never 0 or a rounded number */
void test_service_json::crlNumberRange_data()
{
	QTest::addColumn<QString>("number");
	QTest::addColumn<bool>("asInteger");
	QTest::newRow("1") << "1" << true;
	QTest::newRow("2^53-1") << "9007199254740991" << true;
	QTest::newRow("2^53") << "9007199254740992" << false;
	QTest::newRow("2^63") << "9223372036854775808" << false;
	QTest::newRow("2^159") <<
		"730750818665451459101842416358141509827966271488" << false;
}

void test_service_json::crlNumberRange()
{
	QFETCH(QString, number);
	QFETCH(bool, asInteger);
	pki_crl *c = makeCrl(CCHAR(number), true);
	QJsonValue v = JsonReport::crl(c).value("crl_number");
	delete c;
	if (asInteger) {
		QVERIFY2(v.isDouble(), CCHAR(QString("type %1").arg(v.type())));
		QCOMPARE(QString::number(v.toInteger()), number);
	} else {
		QVERIFY2(v.isString(), CCHAR(QString("type %1, value %2")
			.arg(v.type()).arg(v.toVariant().toString())));
		QCOMPARE(v.toString(), number);
	}
}

/* MINOR 10 (BTD-182): a CRL without nextUpdate has next_update null; the
 * document goes to schemas/examples/crl of bxc-pki */
void test_service_json::crlWithoutNextUpdate()
{
	pki_crl *c = makeCrl("7", false);
	QJsonObject doc = JsonReport::crl(c);
	delete c;
	QVERIFY(doc.contains("next_update"));
	QVERIFY(doc.value("next_update").isNull());
	QCOMPARE(doc.value("crl_number"), QJsonValue(7));
	QFile out(QDir::temp().filePath("crl-without-next-update.json"));
	if (out.open(QIODevice::WriteOnly))
		out.write(QJsonDocument(doc).toJson());
}

/* Acceptance criterion 4: an encrypted key and one with its own
 * password give their public part and the kind of protection only */
void test_service_json::keys()
{
	importFixtures();
	pki_evp *own = dynamic_cast<pki_evp *>(item("key", "own"));
	QVERIFY(own);
	pwdialog->expect(ownPassword);
	own->setOwnPass(pki_key::ptPrivate);
	QCOMPARE(own->getOwnPass(), pki_key::ptPrivate);

	struct { const char *name, *file; } keys[] = {
		{ "ca", "ca.key.json" },
		{ "device", "device.pub.json" },
		{ "rsa-enc", "rsa-enc.key.json" },
		{ "ec", "ec.key.json" },
		{ "own", "own.key.json" },
		/* MINOR 10 of the review of BTD-39 (BTD-182) */
		{ "rsa-pss", "rsa-pss.key.json" },
	};
	for (const auto &k : keys) {
		pki_key *key = dynamic_cast<pki_key *>(item("key", k.name));
		QVERIFY2(key, k.name);
		/* No prompt: nothing decrypts the key */
		compare(JsonReport::key(key), k.file, key);
	}
}

void test_service_json::templates()
{
	TemplateSpec spec;
	spec.name = "OPC UA server";
	spec.subject.addEntryByNid(NID_organizationName, "BxC Lab");
	spec.extensions.basicCA = ExtensionSpec::bc_not_ca;
	spec.extensions.basicCritical = true;
	spec.extensions.subjectKeyId = true;
	spec.extensions.authorityKeyId = true;
	spec.extensions.keyUsage << "digitalSignature" << "keyEncipherment";
	spec.extensions.keyUsageCritical = true;
	spec.extensions.extKeyUsage << "serverAuth" << "clientAuth";
	spec.extensions.subjectAltName = "URI:urn:bxc:{CN}";
	pki_temp *stored = Database.model<db_temp>()->newTemplate(ctx, spec);
	QVERIFY(stored);
	compare(JsonReport::temp(stored), "stored.xca.json", stored);

	/* A predefined template: not in the database */
	pki_temp predefined("CA");
	TemplateSpec ca;
	ca.name = "CA";
	ca.extensions.basicCA = ExtensionSpec::bc_ca;
	ca.extensions.basicCritical = true;
	ca.extensions.subjectKeyId = true;
	ca.extensions.authorityKeyId = true;
	ca.extensions.keyUsage << "keyCertSign" << "cRLSign";
	ca.extensions.keyUsageCritical = true;
	ca.validity = 10;
	ca.unit = TemplateSpec::years;
	ca.toTemplate(&predefined);
	predefined.pkiSource = unknown;
	predefined.setAsPreDefined();
	QJsonObject doc = JsonReport::temp(&predefined);
	QVERIFY(doc.value("id").isNull());
	QVERIFY(doc.value("created").isNull());
	compare(doc, "predefined.xca.json", nullptr);
}

void test_service_json::lists()
{
	importFixtures();
	QList<pki_base *> items = Store.getAll<pki_base>();
	std::sort(items.begin(), items.end(), [](pki_base *a, pki_base *b) {
		return a->getSqlItemId().toULongLong() <
			b->getSqlItemId().toULongLong();
	});
	compare(JsonReport::itemList(items), "items.json", nullptr);
	pki_x509 *ca = dynamic_cast<pki_x509 *>(item("certificate",
							"JSON Test CA"));
	compare(JsonReport::issuerList(QList<pki_x509 *>() << ca),
		"issuers.json", nullptr);
	compare(JsonReport::index(), "index.json", nullptr);
	compare(JsonReport::hierarchy(), "hierarchy.json", nullptr);
}

void test_service_json::errors()
{
	QJsonObject e = JsonReport::error(serviceError("unknown_issuer",
					"Issuer 'x' not found"));
	QCOMPARE(e.value("schema").toString(),
		QString("urn:bxc-pki:schema:error:v1"));
	QCOMPARE(e.value("type").toString(),
		QString("urn:bxc-pki:error:unknown_issuer"));
	QCOMPARE(e.value("title").toString(), QString("Unknown issuer"));
	QCOMPARE(e.value("detail").toString(), QString("Issuer 'x' not found"));
	QCOMPARE(e.value("code").toString(), QString("unknown_issuer"));
	QCOMPARE(e.size(), 5);

	/* Any other exception: internal_error */
	e = JsonReport::error(errorEx("boom"));
	QCOMPARE(e.value("code").toString(), QString("internal_error"));
	QCOMPARE(e.value("title").toString(), QString("Internal error"));

	/* Typed codes of secrets and questions (BTD-41) */
	e = JsonReport::error(secretError(secretError::rejected, "no"));
	QCOMPARE(e.value("code").toString(), QString("password_rejected"));
	e = JsonReport::error(secretError(secretError::missing, "no"));
	QCOMPARE(e.value("code").toString(), QString("missing_password"));
	e = JsonReport::error(secretError(secretError::unreadable, "no"));
	QCOMPARE(e.value("code").toString(), QString("missing_password"));
	e = JsonReport::error(confirmationError("key.size", "no"));
	QCOMPARE(e.value("code").toString(), QString("not_confirmed"));
	QCOMPARE(e.value("type").toString(),
		QString("urn:bxc-pki:error:not_confirmed"));
}

void test_service_json::timestamps()
{
	a1time t;
	t.setUndefined();
	QCOMPARE(JsonReport::timestamp(t).toString(),
		QString("9999-12-31T23:59:59Z"));
	t.fromPlain("20261028213542Z");
	QCOMPARE(JsonReport::timestamp(t).toString(),
		QString("2026-10-28T21:35:42Z"));
	QCOMPARE(JsonReport::revocationReason(10).toString(),
		QString("aACompromise"));
	QVERIFY(JsonReport::revocationReason(7).isNull());
	QVERIFY(JsonReport::revocationReason(-1).isNull());

	/* Serials of legacy objects (BTD-41): whole octets, "00" for zero,
	 * "-" before the magnitude of a negative one */
	QCOMPARE(JsonReport::serial(a1int(0L)), QString("00"));
	QCOMPARE(JsonReport::serial(a1int(-10L)), QString("-0A"));
	QCOMPARE(JsonReport::serial(a1int(0x80FFL)), QString("80FF"));
	a1int empty;
	QCOMPARE(JsonReport::serial(empty), QString("00"));
}

XCA_SERVICE_TEST_MAIN(test_service_json)
#include "test_service_json.moc"
