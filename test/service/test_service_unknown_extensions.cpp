/* vi: set sw=4 ts=4:
 *
 * Extensions under an OID OpenSSL does not know (BTD-169): they are
 * valid when they have an OID and data, they are shown with their dotted
 * OID, critical flag and value as hex DER in text and JSON, and
 * certificate and request creation keep them. Before, isValid() needed an
 * OID OpenSSL knows, so the value was empty or unreadable and
 * extList::delInvalid() dropped the extension silently.
 */

#include <QJsonArray>
#include <QJsonObject>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/db_key.h"
#include "lib/db_x509.h"
#include "lib/db_x509req.h"
#include "lib/exception.h"
#include "lib/issuance.h"
#include "lib/json_report.h"
#include "lib/pki_x509.h"
#include "lib/pki_x509req.h"
#include "lib/request.h"
#include "lib/x509v3ext.h"

#include "ServiceTestCase.h"

/* a private OID, critical, an UTF8String "abc"; and a non-critical one
 * with an OCTET STRING ab cd */
static const char CRIT[] = "1.3.6.1.4.1.55555.1";
static const char PLAIN[] = "1.3.6.1.4.1.55555.2";
static const char ADVANCED[] =
	"1.3.6.1.4.1.55555.1=critical,DER:0C:03:61:62:63\n"
	"1.3.6.1.4.1.55555.2=DER:04:02:AB:CD\n";

class test_service_unknown_extensions : public ServiceTestCase
{
	Q_OBJECT

	ServiceContext ctx{ ServiceContext::cli, "os:service-test" };

	static x509name dn(const QString &cn)
	{
		x509name n;
		n.addEntryByNid(NID_commonName, cn);
		return n;
	}
	pki_key *key(const QString &name)
	{
		return Database.model<db_key>()->newKey(ctx,
			keyjob("EC:prime256v1"), name);
	}
	/* the extension of oid in the stack, or null */
	static const X509_EXTENSION *find(const STACK_OF(X509_EXTENSION) *sk,
					const char *oid)
	{
		ASN1_OBJECT *o = OBJ_txt2obj(oid, 1);
		const X509_EXTENSION *found = nullptr;
		for (int i = 0; i < sk_X509_EXTENSION_num(sk); i++) {
			const X509_EXTENSION *e = sk_X509_EXTENSION_value(sk, i);
			if (!OBJ_cmp(X509_EXTENSION_get_object(e), o))
				found = e;
		}
		ASN1_OBJECT_free(o);
		return found;
	}
	/* A certificate with both extensions, made with OpenSSL alone */
	static X509 *opensslCert();

  private slots:
	void validAndShown();
	void jsonShowsOidFlagAndHex();
	void certificateKeepsThem();
	void requestKeepsThem();
	void emptyDataStaysInvalid();
};

X509 *test_service_unknown_extensions::opensslCert()
{
	EVP_PKEY *k = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256");
	X509 *x = X509_new();
	X509_set_version(x, X509_VERSION_3);
	ASN1_INTEGER_set(X509_get_serialNumber(x), 7);
	X509_NAME *n = X509_NAME_new();
	X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC,
		(const unsigned char *)"BTD-169", -1, -1, 0);
	X509_set_subject_name(x, n);
	X509_set_issuer_name(x, n);
	X509_NAME_free(n);
	X509_gmtime_adj(X509_getm_notBefore(x), 0);
	X509_gmtime_adj(X509_getm_notAfter(x), 86400);
	X509_set_pubkey(x, k);
	for (const char *v : { "critical,DER:0C:03:61:62:63", "DER:04:02:AB:CD" }) {
		X509_EXTENSION *e = X509V3_EXT_nconf(nullptr, nullptr,
				v[0] == 'c' ? CRIT : PLAIN, v);
		X509_add_ext(x, e, -1);
		X509_EXTENSION_free(e);
	}
	X509_sign(x, k, EVP_sha256());
	EVP_PKEY_free(k);
	return x;
}

/* valid, with the dotted OID and the DER bytes as hex in the value */
void test_service_unknown_extensions::validAndShown()
{
	X509 *x = opensslCert();
	QVERIFY(x);
	extList el;
	el.setStack(X509_get0_extensions(x));
	X509_free(x);
	QCOMPARE(el.size(), 2);
	for (const x509v3ext &e : el) {
		QVERIFY2(e.isValid(), qPrintable(e.getObject()));
		QString v = e.getValue().toUpper();
		QVERIFY2(v.contains("0C:03:61:62:63") || v.contains("04:02:AB:CD"),
			qPrintable(e.getObject() + ": " + e.getValue()));
	}
	QCOMPARE(el.delInvalid(), 0);
	QCOMPARE(el.size(), 2);
}

void test_service_unknown_extensions::jsonShowsOidFlagAndHex()
{
	pki_x509 cert(opensslCert());
	QJsonArray exts = JsonReport::object(&cert)["extensions"].toArray();
	int seen = 0;
	for (const QJsonValue &v : exts) {
		QJsonObject o = v.toObject();
		QString oid = o["oid"].toString();
		if (oid != CRIT && oid != PLAIN)
			continue;
		seen++;
		QCOMPARE(o["critical"].toBool(), oid == CRIT);
		QString value = o["value"].toString().toUpper();
		QVERIFY2(value.contains(oid == CRIT ? "0C:03:61:62:63" :
				"04:02:AB:CD"), qPrintable(oid + ": " + value));
	}
	QCOMPARE(seen, 2);
}

/* the advanced section of a template: issued with both extensions */
void test_service_unknown_extensions::certificateKeepsThem()
{
	IssuanceSpec spec;
	spec.name = "BTD-169 cert";
	spec.subject = dn(spec.name);
	spec.key = key("BTD-169 cert key");
	QVERIFY(spec.key);
	spec.notBefore = a1time();
	spec.notAfter = a1time(QDateTime::currentDateTimeUtc().addDays(30));
	spec.hashAlgo = digest(NID_sha256);
	spec.extensions.advanced = ADVANCED;
	pki_x509 *cert = Database.model<db_x509>()->newCert(ctx, spec);
	QVERIFY(cert);
	const STACK_OF(X509_EXTENSION) *sk =
		X509_get0_extensions(cert->getCert());
	const X509_EXTENSION *c = find(sk, CRIT), *p = find(sk, PLAIN);
	QVERIFY2(c, "the critical unknown extension was dropped");
	QVERIFY2(p, "the non-critical unknown extension was dropped");
	QCOMPARE(X509_EXTENSION_get_critical(c), 1);
	QCOMPARE(X509_EXTENSION_get_critical(p), 0);
}

/* CSR creation with the same advanced section: the request keeps both */
void test_service_unknown_extensions::requestKeepsThem()
{
	RequestSpec spec;
	spec.name = "BTD-169 request";
	spec.subject = dn(spec.name);
	spec.key = key("BTD-169 request key");
	QVERIFY(spec.key);
	spec.hashAlgo = digest(NID_sha256);
	spec.extensions.advanced = ADVANCED;
	pki_x509req *req = Database.model<db_x509req>()->newRequest(ctx, spec);
	QVERIFY(req);
	STACK_OF(X509_EXTENSION) *sk = X509_REQ_get_extensions(req->getReq());
	bool c = find(sk, CRIT), p = find(sk, PLAIN);
	sk_X509_EXTENSION_pop_free(sk, X509_EXTENSION_free);
	QVERIFY2(c, "the critical unknown extension was dropped");
	QVERIFY2(p, "the non-critical unknown extension was dropped");
}

/* an extension with an OID but no data keeps its handling: invalid */
void test_service_unknown_extensions::emptyDataStaysInvalid()
{
	ASN1_OCTET_STRING *empty = ASN1_OCTET_STRING_new();
	ASN1_OBJECT *o = OBJ_txt2obj(PLAIN, 1);
	X509_EXTENSION *e = X509_EXTENSION_create_by_OBJ(nullptr, o, 0, empty);
	x509v3ext ext(e);
	QVERIFY(!ext.isValid());
	X509_EXTENSION_free(e);
	ASN1_OBJECT_free(o);
	ASN1_OCTET_STRING_free(empty);
}

XCA_SERVICE_TEST_MAIN(test_service_unknown_extensions)
#include "test_service_unknown_extensions.moc"
