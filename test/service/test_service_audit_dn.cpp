/* vi: set sw=4 ts=4:
 *
 * DN parameters of audit entries in RFC 4514 form (BTD-104, PLAN.md
 * section 7): subject and issuer of certificate.issue, request.create,
 * crl.generate and template.create, for a DN with a multi-valued RDN,
 * values that need escaping and UTF-8. Before, they were written in the
 * OpenSSL one-line form "C = DE, O = ...". Entries written in the old form
 * stay valid: verify() does not read DNs.
 */

#include <QDateTime>

#include <openssl/x509.h>

#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/db_crl.h"
#include "lib/db_key.h"
#include "lib/db_temp.h"
#include "lib/db_x509.h"
#include "lib/db_x509req.h"
#include "lib/issuance.h"
#include "lib/pki_crl.h"
#include "lib/pki_x509.h"
#include "lib/pki_x509req.h"
#include "lib/request.h"
#include "lib/template.h"
#include "lib/x509name.h"

#include "ServiceTestCase.h"

class test_service_audit_dn : public ServiceTestCase
{
	Q_OBJECT

	ServiceContext ctx{ ServiceContext::cli, "os:service-test" };

	/* C=DE, O=Müller, Lab, then one RDN of OU=Ops and CN=a+b */
	static x509name dn();
	static const QString expected;
	static QVariantMap params(const QString &action);
	pki_key *key(const QString &name)
	{
		return Database.model<db_key>()->newKey(ctx,
			keyjob("EC:prime256v1"), name);
	}
	pki_x509 *issue(const QString &name, const x509name &subject,
			pki_x509 *signer);

  private slots:
	void issuance();
	void request();
	void crl();
	void templateCreate();
	void oldFormVerifies();
};

/* Most significant RDN last; the members of the multi-valued RDN joined
 * with '+' (in the order of the stored name, which RFC 4514 2.2 leaves
 * open); ',' and '+' in a value escaped with '\'; UTF-8 as it is
 * (RFC 4514 2.1-2.4) */
const QString test_service_audit_dn::expected =
	QString::fromUtf8("OU=Ops+CN=a\\+b,O=M\xc3\xbcller\\, Lab,C=DE");

x509name test_service_audit_dn::dn()
{
	X509_NAME *n = X509_NAME_new();
	X509_NAME_add_entry_by_txt(n, "C", MBSTRING_UTF8,
		(const unsigned char *)"DE", -1, -1, 0);
	X509_NAME_add_entry_by_txt(n, "O", MBSTRING_UTF8,
		(const unsigned char *)"M\xc3\xbcller, Lab", -1, -1, 0);
	X509_NAME_add_entry_by_txt(n, "OU", MBSTRING_UTF8,
		(const unsigned char *)"Ops", -1, -1, 0);
	/* set -1: into the RDN of the entry before */
	X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_UTF8,
		(const unsigned char *)"a+b", -1, -1, -1);
	x509name name(n);
	X509_NAME_free(n);
	return name;
}

QVariantMap test_service_audit_dn::params(const QString &action)
{
	QVariantMap p;
	for (const AuditEntry &e : AuditLog::entries())
		if (e.action == action)
			p = e.params;
	return p;
}

pki_x509 *test_service_audit_dn::issue(const QString &name,
			const x509name &subject, pki_x509 *signer)
{
	IssuanceSpec spec;
	spec.name = name;
	spec.subject = subject;
	spec.key = key(name + " key");
	spec.signer = signer;
	spec.notBefore = a1time(QDateTime::currentDateTimeUtc().addDays(-1));
	spec.notAfter = a1time(QDateTime::currentDateTimeUtc().addDays(30));
	spec.hashAlgo = digest(NID_sha256);
	spec.extensions.subjectKeyId = true;
	if (signer) {
		spec.extensions.basicCA = ExtensionSpec::bc_not_ca;
		spec.extensions.authorityKeyId = true;
	} else {
		spec.extensions.basicCA = ExtensionSpec::bc_ca;
		spec.extensions.keyUsage << "keyCertSign" << "cRLSign";
	}
	return Database.model<db_x509>()->newCert(ctx, spec);
}

void test_service_audit_dn::issuance()
{
	/* self-signed: subject and issuer are the DN */
	pki_x509 *ca = issue("dn-ca", dn(), nullptr);
	QVERIFY(ca);
	QVariantMap p = params("certificate.issue");
	QCOMPARE(p.value("subject").toString(), expected);

	x509name ee;
	ee.addEntryByNid(NID_commonName, "ee.example");
	QVERIFY(issue("dn-ee", ee, ca));
	p = params("certificate.issue");
	QCOMPARE(p.value("subject").toString(), QString("CN=ee.example"));
	QCOMPARE(p.value("issuer").toString(), expected);
}

void test_service_audit_dn::request()
{
	RequestSpec spec;
	spec.name = "dn-request";
	spec.subject = dn();
	spec.key = key("dn-request key");
	spec.hashAlgo = digest(NID_sha256);
	QVERIFY(Database.model<db_x509req>()->newRequest(ctx, spec));
	QCOMPARE(params("request.create").value("subject").toString(),
		expected);
}

void test_service_audit_dn::crl()
{
	pki_x509 *ca = issue("dn-ca", dn(), nullptr);
	QVERIFY(ca);
	QVERIFY(Database.model<db_crl>()->newCrl(ctx, crljob(ca)));
	QCOMPARE(params(AuditLog::actionCrlGenerate).value("issuer")
		.toString(), expected);
}

void test_service_audit_dn::templateCreate()
{
	TemplateSpec spec;
	spec.name = "dn-template";
	spec.subject = dn();
	QVERIFY(Database.model<db_temp>()->newTemplate(ctx, spec));
	QCOMPARE(params("template.create").value("subject").toString(),
		expected);
}

void test_service_audit_dn::oldFormVerifies()
{
	/* An entry as a build before BTD-104 wrote it: the hash chain
	 * covers the text as it is, verify() does not parse it */
	AuditParams p;
	p.set("subject", "C = DE, O = BxC, CN = old.example");
	AuditLog::append(ctx, "certificate.issue", "cert", "1", p);
	pki_x509 *ca = issue("dn-ca", dn(), nullptr);
	QVERIFY(ca);
	AuditVerifyResult r = AuditLog::verify();
	QVERIFY2(r.ok(), r.toJson().constData());
	QCOMPARE(AuditLog::entries().first().params.value("subject")
		.toString(), QString("C = DE, O = BxC, CN = old.example"));
}

QTEST_MAIN(test_service_audit_dn)
#include "test_service_audit_dn.moc"
