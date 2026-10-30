/* vi: set sw=4 ts=4:
 *
 * Extension input that OpenSSL cannot encode is an error, not a missing
 * extension (BTD-197, groups 1 and 5 of the BTD-95 review list): before,
 * x509v3ext::create() cleared the OpenSSL error and returned an empty
 * extension, the advanced block dropped itself on a syntax error and
 * tested X509V3_EXT_add_nconf() inverted, and the merge paths took an
 * undecodable request extension for an absent one. The certificate, the
 * request or the CRL was signed without the extension and audited as
 * success.
 */

#include <QSqlQuery>

#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/db_key.h"
#include "lib/db_x509.h"
#include "lib/db_x509req.h"
#include "lib/exception.h"
#include "lib/importexport.h"
#include "lib/issuance.h"
#include "lib/pki_x509.h"
#include "lib/pki_x509req.h"
#include "lib/request.h"

#include "ServiceTestCase.h"

class test_service_extension_errors : public ServiceTestCase
{
	Q_OBJECT

	ServiceContext ctx{ ServiceContext::cli, "os:service-test" };

	static x509name dn(const QString &cn)
	{
		x509name n;
		n.addEntryByNid(NID_commonName, cn);
		return n;
	}
	static int rows(const QString &table)
	{
		QSqlQuery q;
		if (!q.exec(QString("SELECT COUNT(*) FROM %1").arg(table)) ||
		    !q.next())
			return -1;
		return q.value(0).toInt();
	}
	pki_key *key(const QString &name)
	{
		return Database.model<db_key>()->newKey(ctx,
			keyjob("EC:prime256v1"), name);
	}
	IssuanceSpec rootSpec(const QString &cn, pki_key *k)
	{
		IssuanceSpec spec;
		spec.name = cn;
		spec.subject = dn(cn);
		spec.key = k;
		spec.notBefore = a1time();
		spec.notAfter = a1time(
			QDateTime::currentDateTimeUtc().addDays(30));
		spec.hashAlgo = digest(NID_sha256);
		spec.extensions.basicCA = ExtensionSpec::bc_ca;
		spec.extensions.keyUsage << "keyCertSign" << "cRLSign";
		return spec;
	}
	/* A request whose extension nid holds no valid value, imported */
	pki_x509req *junkRequest(int nid);
	pki_x509 *root()
	{
		pki_key *ca = key("BTD-197 CA key");
		return ca ? Database.model<db_x509>()->newCert(ctx,
			rootSpec("BTD-197 CA", ca)) : nullptr;
	}
	/* The call throws invalid_extension (or code) naming input; no
	 * new certificate or request, one failure entry */
	void expectRefused(std::function<void()> call, const QString &action,
		const QString &code, const QString &input);

  private slots:
	void certificate_data();
	void certificate();
	void validAdvancedBlock();
	void request();
	void undecodableRequestExtension();
	void undecodableRequestSan();
};

pki_x509req *test_service_extension_errors::junkRequest(int nid)
{
	EVP_PKEY *leaf = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256");
	X509_REQ *req = X509_REQ_new();
	X509_REQ_set_pubkey(req, leaf);
	X509_NAME *n = X509_NAME_new();
	X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC,
		(const unsigned char *)"BTD-197 leaf", -1, -1, 0);
	X509_REQ_set_subject_name(req, n);
	X509_NAME_free(n);
	/* an OCTET STRING where the extension wants its own structure */
	ASN1_OCTET_STRING *junk = ASN1_OCTET_STRING_new();
	ASN1_OCTET_STRING_set(junk, (const unsigned char *)"\x04\x01\x00", 3);
	X509_EXTENSION *ext = X509_EXTENSION_create_by_NID(nullptr, nid, 0,
		junk);
	STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();
	sk_X509_EXTENSION_push(exts, ext);
	X509_REQ_add_extensions(req, exts);
	sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
	ASN1_OCTET_STRING_free(junk);
	X509_REQ_sign(req, leaf, EVP_sha256());
	unsigned char *der = nullptr;
	int len = i2d_X509_REQ(req, &der);
	ImportSpec in;
	in.data = QByteArray((const char *)der, len);
	in.dataName = QString("btd197-%1.csr").arg(OBJ_nid2sn(nid));
	OPENSSL_free(der);
	X509_REQ_free(req);
	EVP_PKEY_free(leaf);
	return dynamic_cast<pki_x509req *>(
		Database.importItems(ctx, in).created.value(0));
}

void test_service_extension_errors::expectRefused(
	std::function<void()> call, const QString &action,
	const QString &code, const QString &input)
{
	int certs = rows("certs"), reqs = rows("requests");
	int audit = AuditLog::entries().size();
	try {
		call();
		QFAIL("created and audited as success");
	} catch (serviceError &err) {
		QCOMPARE(err.code, code);
		QVERIFY2(err.getString().contains(input),
			qPrintable(err.getString()));
	}
	QCOMPARE(rows("certs"), certs);
	QCOMPARE(rows("requests"), reqs);
	QList<AuditEntry> entries = AuditLog::entries();
	QCOMPARE(entries.size(), audit + 1);
	QCOMPARE(entries.last().action, action);
	QCOMPARE(entries.last().result, QString("failure"));
	QCOMPARE(entries.last().errorCode, code);
}

void test_service_extension_errors::certificate_data()
{
	QTest::addColumn<QString>("field");
	QTest::addColumn<QString>("value");
	QTest::addColumn<QString>("named");

	QTest::newRow("SAN") << "san" << "IP:300.1.1.1" << "300.1.1.1";
	QTest::newRow("IAN") << "ian" << "IP:300.1.1.1" << "300.1.1.1";
	QTest::newRow("keyUsage") << "ku" << "signDigitalStuff"
		<< "signDigitalStuff";
	QTest::newRow("extKeyUsage") << "eku" << "fooAuth" << "fooAuth";
	QTest::newRow("nameConstraints") << "nc" << "permitted;FOO:bar"
		<< "FOO:bar";
	QTest::newRow("advanced, syntax") << "advanced"
		<< "[default\nnsComment = BTD-197" << "line";
	QTest::newRow("advanced, value") << "advanced"
		<< "subjectAltName = IP:300.1.1.1" << "300.1.1.1";
}

/* Each invalid input refuses the certificate */
void test_service_extension_errors::certificate()
{
	QFETCH(QString, field);
	QFETCH(QString, value);
	QFETCH(QString, named);

	pki_key *k = key("BTD-197 key");
	QVERIFY(k);
	IssuanceSpec spec = rootSpec("BTD-197 " + field, k);
	ExtensionSpec &e = spec.extensions;
	if (field == "san")
		e.subjectAltName = value;
	else if (field == "ian")
		e.issuerAltName = value;
	else if (field == "ku")
		e.keyUsage << value;
	else if (field == "eku")
		e.extKeyUsage << value;
	else if (field == "nc")
		e.nameConstraints = value;
	else
		e.advanced = value;
	expectRefused([&]() {
		Database.model<db_x509>()->newCert(ctx, spec); },
		"certificate.issue", "invalid_extension", named);
}

/* The check of X509V3_EXT_add_nconf() was inverted: a valid block still
 * reaches the certificate */
void test_service_extension_errors::validAdvancedBlock()
{
	pki_key *k = key("BTD-197 key");
	QVERIFY(k);
	IssuanceSpec spec = rootSpec("BTD-197 advanced", k);
	spec.extensions.advanced = "nsComment = BTD-197 valid";
	pki_x509 *cert = Database.model<db_x509>()->newCert(ctx, spec);
	QVERIFY(cert);
	QVERIFY(X509_get_ext_by_NID(cert->getCert(), NID_netscape_comment,
		-1) >= 0);
}

/* The same for a request */
void test_service_extension_errors::request()
{
	pki_key *k = key("BTD-197 key");
	QVERIFY(k);
	RequestSpec spec;
	spec.name = "BTD-197 request";
	spec.subject = dn("BTD-197 request");
	spec.key = k;
	spec.hashAlgo = digest(NID_sha256);
	spec.extensions.subjectAltName = "IP:300.1.1.1";
	expectRefused([&]() {
		Database.model<db_x509req>()->newRequest(ctx, spec); },
		"request.create", "invalid_extension", "300.1.1.1");
}

/* A request whose keyUsage does not decode: with the request's KU
 * merged, the certificate was issued without keyUsage */
void test_service_extension_errors::undecodableRequestExtension()
{
	pki_x509 *ca = root();
	pki_x509req *csr = junkRequest(NID_key_usage);
	QVERIFY(ca && csr);
	IssuanceSpec spec;
	spec.request = csr;
	spec.subject = csr->getSubject();
	spec.signer = ca;
	spec.notBefore = a1time();
	spec.notAfter = a1time(QDateTime::currentDateTimeUtc().addDays(10));
	spec.hashAlgo = digest(NID_sha256);
	spec.extensions.basicCA = ExtensionSpec::bc_not_ca;
	spec.extensions.kuMerge = ExtensionSpec::merge_request;
	expectRefused([&]() {
		Database.model<db_x509>()->newCert(ctx, spec); },
		"certificate.issue", "invalid_request_extension", "keyUsage");
}

/* A profile takes the SAN from the request: IssuanceChecks::request()
 * refuses one that does not decode before requestSan() runs (BTD-65);
 * requestSan() checks its own steps as well. A regression guard, green
 * before BTD-197 too */
void test_service_extension_errors::undecodableRequestSan()
{
	pki_x509 *ca = root();
	pki_x509req *csr = junkRequest(NID_subject_alt_name);
	QVERIFY(ca && csr);
	IssuanceSpec spec;
	spec.request = csr;
	spec.subject = csr->getSubject();
	spec.signer = ca;
	spec.notBefore = a1time();
	spec.notAfter = a1time(QDateTime::currentDateTimeUtc().addDays(10));
	spec.hashAlgo = digest(NID_sha256);
	spec.extensions.basicCA = ExtensionSpec::bc_not_ca;
	spec.csrPolicy.profile = true;
	spec.csrPolicy.registeredUri = "urn:btd197:device";
	expectRefused([&]() {
		Database.model<db_x509>()->newCert(ctx, spec); },
		"certificate.issue", "csr_san_invalid", "");
}

XCA_SERVICE_TEST_MAIN(test_service_extension_errors)
#include "test_service_extension_errors.moc"
