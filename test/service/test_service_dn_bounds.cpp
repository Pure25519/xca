/* vi: set sw=4 ts=4:
 *
 * RFC 5280 upper bounds of DN values (BTD-202). x509name::addEntryByNid
 * passed a fixed string type to OpenSSL, which applies the bounds of its
 * string table only to MBSTRING_* input, so C=DEU or an O of 65
 * characters went into certificates and requests. Every value is now
 * checked in characters, at entry creation and on the finished subject
 * of every certificate and request; a violation is invalid_dn_value
 * naming attribute, length and limit, before any object, serial or
 * signature. A subject copied byte-faithfully from a device CSR is
 * refused the same way.
 */

#include <QProcess>
#include <QTemporaryDir>

#include <openssl/pem.h>

#include "lib/audit.h"
#include "lib/db_key.h"
#include "lib/db_x509.h"
#include "lib/db_x509req.h"
#include "lib/exception.h"
#include "lib/pki_x509.h"
#include "lib/pki_x509req.h"
#include "lib/profile.h"
#include "lib/request.h"

#include "ServiceTestCase.h"

class test_service_dn_bounds : public ServiceTestCase
{
	Q_OBJECT

	ServiceContext ctx{ ServiceContext::cli, "os:service-test" };
	QTemporaryDir dir{};

	pki_x509 *ca();
	/* a name with one entry of the given string type, without any
	 * check, as OpenSSL's API or a device builds it */
	static x509name rawName(int nid, const QString &value);
	/* a device CSR whose subject holds O=<o>, built without checks */
	pki_x509req *deviceCsr(const QString &o);
	template <class F> static QString code(F f, QString *detail = nullptr)
	{
		try {
			f();
			return QString();
		} catch (serviceError &err) {
			if (detail)
				*detail = err.getString();
			return err.code;
		}
	}

  private slots:
	void bounds_data();
	void bounds();
	void characters();
	void profileValues();
	void deviceCsrSubject();
};

pki_x509 *test_service_dn_bounds::ca()
{
	IssuanceSpec s;
	s.name = "Bounds CA";
	s.subject.addEntryByNid(NID_commonName, s.name);
	s.key = Database.model<db_key>()->newKey(keyjob("EC:prime256v1"), s.name);
	s.notBefore = a1time(QDateTime::currentDateTimeUtc().addDays(-1));
	s.notAfter = a1time(QDateTime::currentDateTimeUtc().addYears(5));
	s.hashAlgo = digest(NID_sha256);
	s.extensions.basicCA = ExtensionSpec::bc_ca;
	s.extensions.keyUsage << "keyCertSign" << "cRLSign";
	return Database.model<db_x509>()->newCert(ctx, s);
}

x509name test_service_dn_bounds::rawName(int nid, const QString &value)
{
	x509name n;
	n.addEntryByNid(NID_commonName, "raw");
	X509_NAME *x = n.get();
	QByteArray v = value.toUtf8();
	int type = nid == NID_countryName || nid == NID_serialNumber ?
		V_ASN1_PRINTABLESTRING : nid == NID_pkcs9_emailAddress ?
		V_ASN1_IA5STRING : V_ASN1_UTF8STRING;
	X509_NAME_add_entry_by_NID(x, nid, type,
		(const unsigned char *)v.constData(), v.size(), -1, 0);
	x509name r(x);
	X509_NAME_free(x);
	return r;
}

pki_x509req *test_service_dn_bounds::deviceCsr(const QString &o)
{
#ifndef OPENSSL_PROGRAM
	Q_UNUSED(o);
	return nullptr;
#else
	static int n = 0;
	QString keyFile = dir.filePath(QString("device-%1.key").arg(++n));
	QString out = dir.filePath(QString("device-%1.csr").arg(n));
	QProcess proc;
	proc.start(OPENSSL_PROGRAM, { "genpkey", "-algorithm", "RSA",
		"-pkeyopt", "rsa_keygen_bits:2048", "-out", keyFile });
	if (!proc.waitForFinished(30000) || proc.exitCode() != 0)
		return nullptr;
	BIO *b = BIO_new_file(CCHAR(keyFile), "r");
	EVP_PKEY *pkey = PEM_read_bio_PrivateKey(b, nullptr, nullptr, nullptr);
	BIO_free(b);
	X509_REQ *r = X509_REQ_new();
	X509_NAME *name = X509_NAME_new();
	QByteArray ov = o.toUtf8();
	X509_NAME_add_entry_by_NID(name, NID_organizationName, V_ASN1_UTF8STRING,
		(const unsigned char *)ov.constData(), ov.size(), -1, 0);
	X509_NAME_add_entry_by_NID(name, NID_commonName, V_ASN1_UTF8STRING,
		(const unsigned char *)"device.example", -1, -1, 0);
	X509_REQ_set_subject_name(r, name);
	X509_NAME_free(name);
	X509_REQ_set_pubkey(r, pkey);
	X509_REQ_sign(r, pkey, EVP_sha256());
	b = BIO_new_file(CCHAR(out), "w");
	PEM_write_bio_X509_REQ(b, r);
	BIO_free(b);
	X509_REQ_free(r);
	EVP_PKEY_free(pkey);
	pki_x509req *req = new pki_x509req("device");
	req->fload(out);
	return dynamic_cast<pki_x509req *>(
			Database.model<db_x509req>()->insert(req));
#endif
}

/* RFC 5280 Appendix A per attribute: at the limit the certificate and
 * the request are created, one character over (or under for C) gives
 * invalid_dn_value naming attribute and limit, and nothing is created */
void test_service_dn_bounds::bounds_data()
{
	QTest::addColumn<int>("nid");
	QTest::addColumn<QString>("ok");
	QTest::addColumn<QString>("bad");
	QTest::addColumn<QString>("limit");
	auto row = [](const char *name, int nid, int max, QChar c) {
		QTest::newRow(name) << nid << QString(max, c)
			<< QString(max + 1, c) << QString("at most %1").arg(max);
	};
	QTest::newRow("C DEU") << (int)NID_countryName << "DE" << "DEU"
		<< "exactly 2";
	QTest::newRow("C D") << (int)NID_countryName << "DE" << "D"
		<< "exactly 2";
	row("CN", NID_commonName, 64, 'c');
	row("O", NID_organizationName, 64, 'o');
	row("OU", NID_organizationalUnitName, 64, 'u');
	row("L", NID_localityName, 128, 'l');
	row("ST", NID_stateOrProvinceName, 128, 's');
	row("serialNumber", NID_serialNumber, 64, '7');
	row("title", NID_title, 64, 't');
	QString local(243, 'e');
	QTest::newRow("emailAddress") << (int)NID_pkcs9_emailAddress
		<< local + "@example.com" << local + "e@example.com"
		<< "at most 255";
}

void test_service_dn_bounds::bounds()
{
	QFETCH(int, nid);
	QFETCH(QString, ok);
	QFETCH(QString, bad);
	QFETCH(QString, limit);
	pki_x509 *issuer = ca();
	QVERIFY(issuer);
	db_x509 *certs = Database.model<db_x509>();
	db_x509req *reqs = Database.model<db_x509req>();
	pki_key *key = Database.model<db_key>()->newKey(keyjob("EC:prime256v1"),
				"subject key");

	/* entry creation: dialog, templates, profiles, registrations */
	x509name good;
	good.addEntryByNid(NID_commonName, "at the limit");
	good.addEntryByNid(nid, ok);
	QString detail;
	QCOMPARE(code([&]() { x509name n; n.addEntryByNid(nid, bad); },
		&detail), QString("invalid_dn_value"));
	QVERIFY2(detail.contains(OBJ_nid2ln(nid)) && detail.contains(limit) &&
		 detail.contains(QString("has %1 characters").arg(bad.size())),
		CCHAR(detail));

	/* at the limit: certificate and request */
	IssuanceSpec s;
	s.name = "at the limit";
	s.subject = good;
	s.key = key;
	s.signer = issuer;
	s.notBefore = a1time(QDateTime::currentDateTimeUtc().addDays(-1));
	s.notAfter = a1time(QDateTime::currentDateTimeUtc().addYears(1));
	s.hashAlgo = digest(NID_sha256);
	QVERIFY(certs->newCert(ctx, s));
	RequestSpec r;
	r.name = "at the limit";
	r.subject = good;
	r.key = key;
	r.hashAlgo = digest(NID_sha256);
	QVERIFY(reqs->newRequest(ctx, r));

	/* one over, built without the entry check (OpenSSL API, CLI):
	 * refused by the service before anything is written */
	int nCerts = Store.getAll<pki_x509>().size();
	int nReqs = Store.getAll<pki_x509req>().size();
	s.name = r.name = "over the limit";
	s.subject = r.subject = rawName(nid, bad);
	QCOMPARE(s.subject.entryCount(), 2);
	QCOMPARE(code([&]() { certs->newCert(ctx, s); }, &detail),
		QString("invalid_dn_value"));
	QVERIFY2(detail.contains(limit), CCHAR(detail));
	AuditEntry e = AuditLog::entries().last();
	QCOMPARE(e.action, QString("certificate.issue"));
	QCOMPARE(e.errorCode, QString("invalid_dn_value"));
	QVERIFY(!e.params.contains("serial"));
	QCOMPARE(code([&]() { reqs->newRequest(ctx, r); }),
		QString("invalid_dn_value"));
	QCOMPARE(AuditLog::entries().last().errorCode,
		QString("invalid_dn_value"));
	QCOMPARE(Store.getAll<pki_x509>().size(), nCerts);
	QCOMPARE(Store.getAll<pki_x509req>().size(), nReqs);
}

/* the bounds count characters, not UTF-8 bytes */
void test_service_dn_bounds::characters()
{
	x509name n;
	n.addEntryByNid(NID_commonName, QString(64, QChar(0x00e4)));
	QCOMPARE(n.getEntryByNid(NID_commonName).size(), 64);
	QCOMPARE(code([]() { x509name m;
		m.addEntryByNid(NID_commonName, QString(65, QChar(0x00e4))); }),
		QString("invalid_dn_value"));
	/* a character outside the BMP is one character */
	char32_t lock = 0x1F512;
	QString emoji = QString::fromUcs4(&lock, 1);
	QString cn;
	for (int i = 0; i < 64; i++)
		cn += emoji;
	x509name e;
	e.addEntryByNid(NID_commonName, cn);
	QCOMPARE(code([&]() { x509name m;
		m.addEntryByNid(NID_commonName, cn + emoji); }),
		QString("invalid_dn_value"));
}

/* profile path: the registration's O (missingO) and its user name as CN
 * over the limit are refused with the same code */
void test_service_dn_bounds::profileValues()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	Profile p = Profile::fromFile(SERVICE_TEST_DATA "/profiles/opcua-user.json");
	QString out = dir.filePath("user.csr");
	QProcess proc;
	proc.start(OPENSSL_PROGRAM, { "req", "-new", "-newkey", "ec",
		"-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
		"-keyout", dir.filePath("user.key"), "-out", out,
		"-subj", "/CN=operator" });
	QVERIFY(proc.waitForFinished(30000) && proc.exitCode() == 0);
	pki_x509req *req = new pki_x509req("user");
	req->fload(out);
	req = dynamic_cast<pki_x509req *>(
			Database.model<db_x509req>()->insert(req));
	QVERIFY(req);
	pki_x509 *issuer = ca();
	auto issue = [&](const QString &user, const QString &o) {
		Registration reg;
		reg.userName = user;
		reg.organization = o;
		return code([&]() {
			IssuanceSpec spec = p.apply(req, nullptr, reg, issuer);
			Database.model<db_x509>()->newCert(ctx, spec);
		});
	};
	int nCerts = Store.getAll<pki_x509>().size();
	QCOMPARE(issue("operator", QString(65, 'o')), QString("invalid_dn_value"));
	QCOMPARE(issue(QString(65, 'u'), "BxC"), QString("invalid_dn_value"));
	QCOMPARE(Store.getAll<pki_x509>().size(), nCerts);
	QCOMPARE(issue(QString(64, 'u'), QString(64, 'o')), QString());
	QCOMPARE(Store.getAll<pki_x509>().size(), nCerts + 1);
#endif
}

/* A subject copied byte-faithfully from a device CSR (BTD-65) is refused
 * like any other: under a profile and without one. Decision of BTD-202:
 * no warn mode; a strict peer (OPC UA stack, TLS library) would reject
 * the certificate. */
void test_service_dn_bounds::deviceCsrSubject()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	pki_x509req *over = deviceCsr(QString(65, 'o'));
	pki_x509req *atLimit = deviceCsr(QString(64, 'o'));
	QVERIFY(over && atLimit);
	QCOMPARE(over->getSubject().getEntryByNid(NID_organizationName).size(), 65);
	pki_x509 *issuer = ca();
	Profile p = Profile::fromFile(SERVICE_TEST_DATA
			"/profiles/generic/xca-tls-server.json");
	int nCerts = Store.getAll<pki_x509>().size();
	QString detail;
	QCOMPARE(code([&]() {
		IssuanceSpec spec = p.apply(over, nullptr, Registration(), issuer);
		Database.model<db_x509>()->newCert(ctx, spec);
	}, &detail), QString("invalid_dn_value"));
	QVERIFY2(detail.contains("organizationName") &&
		 detail.contains("at most 64"), CCHAR(detail));

	/* without a profile: the request's subject as it is */
	IssuanceSpec s;
	s.name = "plain";
	s.request = over;
	s.subject = over->getSubject();
	s.signer = issuer;
	s.notBefore = a1time(QDateTime::currentDateTimeUtc().addDays(-1));
	s.notAfter = a1time(QDateTime::currentDateTimeUtc().addYears(1));
	s.hashAlgo = digest(NID_sha256);
	QCOMPARE(code([&]() { Database.model<db_x509>()->newCert(ctx, s); }),
		QString("invalid_dn_value"));
	QCOMPARE(Store.getAll<pki_x509>().size(), nCerts);

	QCOMPARE(code([&]() {
		IssuanceSpec spec = p.apply(atLimit, nullptr, Registration(), issuer);
		Database.model<db_x509>()->newCert(ctx, spec);
	}), QString());
	QCOMPARE(Store.getAll<pki_x509>().size(), nCerts + 1);
#endif
}

XCA_SERVICE_TEST_MAIN(test_service_dn_bounds)
#include "test_service_dn_bounds.moc"
