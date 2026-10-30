/* vi: set sw=4 ts=4:
 *
 * Templates through the service functions of BTD-35: TemplateSpec
 * (lib/template.h), db_temp::newTemplate(), updateTemplate() and the
 * deletion through db_base::deleteItems(). A template applied to an
 * IssuanceSpec issues the same extensions as the spec it was made
 * from; one audit entry per operation, the chain verifies.
 */

#include <QDateTime>
#include <QTimeZone>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/db_key.h"
#include "lib/db_temp.h"
#include "lib/db_x509.h"
#include "lib/exception.h"
#include "lib/issuance.h"
#include "lib/pki_temp.h"
#include "lib/pki_x509.h"
#include "lib/template.h"

#include "ServiceTestCase.h"

class test_service_template : public ServiceTestCase
{
	Q_OBJECT

	ServiceContext ctx{ ServiceContext::cli, "os:service-test" };

	static db_temp *temps()
	{
		return Database.model<db_temp>();
	}
	static pki_key *newKey(const QString &name)
	{
		return Database.model<db_key>()->newKey(
				keyjob("EC:prime256v1"), name);
	}
	pki_x509 *rootCa(const QString &cn);
	static TemplateSpec serverTemplate();
	static IssuanceSpec issuance(pki_key *key, pki_x509 *signer);
	static QList<QByteArray> extensionsDer(pki_x509 *cert);
	static void lastEntry(const QString &action, const QString &result,
				const QString &code = QString());
	static void verifyChain();

  private slots:
	void storedFormRoundTrip();
	void templateRoundTrip();
	void validityPeriod_data();
	void validityPeriod();
	void updateTemplate();
	void updateRejected();
	void fromObject();
	void fromIssuanceSpec();
	void deleteTemplate();
};

pki_x509 *test_service_template::rootCa(const QString &cn)
{
	IssuanceSpec spec;
	QDateTime now = QDateTime::currentDateTimeUtc();

	spec.name = cn;
	spec.subject.addEntryByNid(NID_commonName, cn);
	spec.key = newKey(cn + " key");
	spec.notBefore = a1time(now.addDays(-1));
	spec.notAfter = a1time(now.addYears(10));
	spec.hashAlgo = digest(NID_sha256);
	spec.extensions.basicCA = ExtensionSpec::bc_ca;
	spec.extensions.basicCritical = true;
	spec.extensions.subjectKeyId = true;
	spec.extensions.keyUsage << "keyCertSign" << "cRLSign";
	return Database.model<db_x509>()->newCert(ctx, spec);
}

/* Every kind of value a template stores */
TemplateSpec test_service_template::serverTemplate()
{
	TemplateSpec t;
	ExtensionSpec &e = t.extensions;

	t.name = "TLS server";
	t.comment = "for the lab servers";
	t.subject.addEntryByNid(NID_organizationName, "BxC Security");
	t.subject.addEntryByNid(NID_commonName, "server.lab");
	e.basicCA = ExtensionSpec::bc_not_ca;
	e.basicCritical = true;
	e.subjectKeyId = true;
	e.authorityKeyId = true;
	e.keyUsage << "digitalSignature" << "keyAgreement";
	e.keyUsageCritical = true;
	e.extKeyUsage << "serverAuth" << "clientAuth";
	e.subjectAltName = "DNS:server.lab, IP:10.10.10.10";
	e.crlDistPoints = "URI:http://pki.lab/ca.crl";
	e.authInfoAccess = "OCSP;URI:http://pki.lab/ocsp";
	e.ocspMustStaple = true;
	e.netscape = true;
	e.nsCertType << "server";
	e.nsComment = "lab server";
	t.validity = 2;
	t.unit = TemplateSpec::years;
	t.midnight = true;
	return t;
}

IssuanceSpec test_service_template::issuance(pki_key *key, pki_x509 *signer)
{
	IssuanceSpec spec;
	spec.name = "server";
	spec.key = key;
	spec.signer = signer;
	spec.hashAlgo = digest(NID_sha256);
	return spec;
}

QList<QByteArray> test_service_template::extensionsDer(pki_x509 *cert)
{
	QList<QByteArray> list;
	const X509 *x = cert->getCert();

	for (int i = 0; i < X509_get_ext_count(x); i++) {
		const X509_EXTENSION *ext = X509_get_ext(x, i);
		unsigned char *der = nullptr;
		int len = i2d_X509_EXTENSION(ext, &der);
		list << QByteArray((const char *)der, len);
		OPENSSL_free(der);
	}
	return list;
}

void test_service_template::lastEntry(const QString &action,
			const QString &result, const QString &code)
{
	AuditEntry e = AuditLog::entries().last();
	QCOMPARE(e.action, action);
	QCOMPARE(e.result, result);
	QCOMPARE(e.errorCode, code);
}

void test_service_template::verifyChain()
{
	AuditVerifyResult v = AuditLog::verify();
	QVERIFY2(v.ok(), v.toJson().constData());
}

static void compareSpecs(const TemplateSpec &a, const TemplateSpec &b)
{
	QCOMPARE(a.name, b.name);
	QCOMPARE(a.comment, b.comment);
	QCOMPARE(a.subject.oneLine(), b.subject.oneLine());
	QCOMPARE(a.extensions.basicCA, b.extensions.basicCA);
	QCOMPARE(a.extensions.basicCritical, b.extensions.basicCritical);
	QCOMPARE(a.extensions.pathLen, b.extensions.pathLen);
	QCOMPARE(a.extensions.subjectKeyId, b.extensions.subjectKeyId);
	QCOMPARE(a.extensions.authorityKeyId, b.extensions.authorityKeyId);
	QCOMPARE(a.extensions.keyUsage, b.extensions.keyUsage);
	QCOMPARE(a.extensions.keyUsageCritical, b.extensions.keyUsageCritical);
	QCOMPARE(a.extensions.extKeyUsage, b.extensions.extKeyUsage);
	QCOMPARE(a.extensions.extKeyUsageCritical,
		b.extensions.extKeyUsageCritical);
	QCOMPARE(a.extensions.nameConstraints, b.extensions.nameConstraints);
	QCOMPARE(a.extensions.subjectAltName, b.extensions.subjectAltName);
	QCOMPARE(a.extensions.issuerAltName, b.extensions.issuerAltName);
	QCOMPARE(a.extensions.crlDistPoints, b.extensions.crlDistPoints);
	QCOMPARE(a.extensions.authInfoAccess, b.extensions.authInfoAccess);
	QCOMPARE(a.extensions.ocspMustStaple, b.extensions.ocspMustStaple);
	QCOMPARE(a.extensions.advanced, b.extensions.advanced);
	QCOMPARE(a.extensions.nsCertType, b.extensions.nsCertType);
	QCOMPARE(a.extensions.nsComment, b.extensions.nsComment);
	QCOMPARE(a.validity, b.validity);
	QCOMPARE(a.unit, b.unit);
	QCOMPARE(a.midnight, b.midnight);
	QCOMPARE(a.noWellDefinedExpDate, b.noWellDefinedExpDate);
}

/* TemplateSpec -> stored settings -> TemplateSpec loses nothing, also
 * through the database and its export form */
void test_service_template::storedFormRoundTrip()
{
	TemplateSpec spec = serverTemplate();
	spec.extensions.pathLen = "3";
	spec.extensions.nameConstraints = "permitted;DNS:.lab";
	spec.extensions.advanced = "1.2.3.4=ASN1:UTF8String:lab";

	pki_temp temp;
	spec.toTemplate(&temp);
	compareSpecs(TemplateSpec::fromTemplate(&temp), spec);

	pki_temp copy;
	copy.fromBytes(temp.toExportData(), "copy.xca");
	compareSpecs(TemplateSpec::fromTemplate(&copy), spec);

	pki_temp *stored = temps()->newTemplate(ctx, spec);
	QVERIFY(stored);
	QVariant id = stored->getSqlItemId();
	reopenDatabase();
	stored = Store.lookupPki<pki_temp>(id);
	QVERIFY(stored);
	TemplateSpec reread = TemplateSpec::fromTemplate(stored);
	compareSpecs(reread, spec);
	QCOMPARE(stored->pkiSource, generated);
}

/* Acceptance criterion 1: create, apply to an IssuanceSpec, issue,
 * compare the extensions with a certificate issued from the same
 * values without the template */
void test_service_template::templateRoundTrip()
{
	pki_x509 *ca = rootCa("Template CA");
	QVERIFY(ca);
	int entries = AuditLog::entries().size();

	TemplateSpec spec = serverTemplate();
	pki_temp *temp = temps()->newTemplate(ctx, spec);
	QVERIFY(temp);
	QCOMPARE(AuditLog::entries().size(), entries + 1);
	AuditEntry e = AuditLog::entries().last();
	QCOMPARE(e.action, QString("template.create"));
	QCOMPARE(e.result, QString("success"));
	QCOMPARE(e.objectType, QString("template"));
	QCOMPARE(e.objectId, temp->getSqlItemId().toString());
	QCOMPARE(e.params.value("name").toString(), spec.name);
	QCOMPARE(e.params.value("subject").toString(), spec.subject.oneLine());
	QCOMPARE(temp->getIntName(), spec.name);
	QCOMPARE(temp->getComment(), spec.comment);
	QVERIFY(Store.getAll<pki_temp>().contains(temp));

	/* the stored template, as the issuance dialog would apply it */
	pki_key *key = newKey("server key");
	IssuanceSpec fromTemplate = issuance(key, ca);
	TemplateSpec::fromTemplate(temp).applyTo(fromTemplate);
	QCOMPARE(fromTemplate.templateName, spec.name);
	QCOMPARE(fromTemplate.subject.oneLine(), spec.subject.oneLine());

	IssuanceSpec direct = issuance(key, ca);
	direct.subject = spec.subject;
	direct.extensions = spec.extensions;
	direct.notBefore = fromTemplate.notBefore;
	direct.notAfter = fromTemplate.notAfter;

	db_x509 *certs = Database.model<db_x509>();
	pki_x509 *a = certs->newCert(ctx, fromTemplate);
	pki_x509 *b = certs->newCert(ctx, direct);
	QVERIFY(a && b);
	QList<QByteArray> extA = extensionsDer(a), extB = extensionsDer(b);
	QCOMPARE(extA.size(), 11);
	QCOMPARE(extA, extB);
	QCOMPARE(AuditLog::entries().last().params.value("template").toString(),
		QString());
	QCOMPARE(AuditLog::entries().at(AuditLog::entries().size() - 2)
		.params.value("template").toString(), spec.name);

	/* what the template asked for is in the certificate */
	X509 *x = a->getCert();
	GENERAL_NAMES *san = (GENERAL_NAMES *)X509_get_ext_d2i(x,
				NID_subject_alt_name, nullptr, nullptr);
	QVERIFY(san);
	QCOMPARE(sk_GENERAL_NAME_num(san), 2);
	GENERAL_NAMES_free(san);
	QCOMPARE(X509_get_key_usage(x), (uint32_t)(KU_DIGITAL_SIGNATURE |
				KU_KEY_AGREEMENT));
	QCOMPARE(X509_get_extended_key_usage(x), (uint32_t)(XKU_SSL_SERVER |
				XKU_SSL_CLIENT));
	QVERIFY(X509_get_extension_flags(x) & EXFLAG_BCONS);
	QVERIFY(!(X509_get_extension_flags(x) & EXFLAG_CA));
	verifyChain();
}

void test_service_template::validityPeriod_data()
{
	QTest::addColumn<int>("unit");
	QTest::addColumn<bool>("midnight");
	QTest::addColumn<QString>("notBefore");
	QTest::addColumn<QString>("notAfter");

	QTest::newRow("days") << (int)TemplateSpec::days << false
		<< "20261029101500Z" << "20261108101500Z";
	QTest::newRow("months") << (int)TemplateSpec::months << false
		<< "20261029101500Z" << "20270829101500Z";
	QTest::newRow("years midnight") << (int)TemplateSpec::years << true
		<< "20261029000000Z" << "20361028235959Z";
}

/* As the dialog's Apply: from the minute of now, or from midnight to
 * 23:59:59 of the day before */
void test_service_template::validityPeriod()
{
	QFETCH(int, unit);
	QFETCH(bool, midnight);
	QFETCH(QString, notBefore);
	QFETCH(QString, notAfter);

	TemplateSpec t;
	t.validity = 10;
	t.unit = (enum TemplateSpec::validityUnit)unit;
	t.midnight = midnight;
	a1time now(QDateTime(QDate(2026, 10, 29), QTime(10, 15, 42),
				QTimeZone::UTC));
	IssuanceSpec spec;
	t.applyTo(spec, now);
	QCOMPARE(spec.notBefore.toPlain(), notBefore);
	QCOMPARE(spec.notAfter.toPlain(), notAfter);

	t.noWellDefinedExpDate = true;
	t.applyTo(spec, now);
	QVERIFY(spec.notAfter.isUndefined());
}

void test_service_template::updateTemplate()
{
	pki_temp *temp = temps()->newTemplate(ctx, serverTemplate());
	QVERIFY(temp);
	QVariant id = temp->getSqlItemId();

	TemplateSpec spec = TemplateSpec::fromTemplate(temp);
	spec.name = "TLS server v2";
	spec.extensions.subjectAltName = "DNS:server2.lab";
	spec.extensions.extKeyUsage = QStringList() << "serverAuth";
	temps()->updateTemplate(ctx, temp, spec);

	AuditEntry e = AuditLog::entries().last();
	QCOMPARE(e.action, QString("template.update"));
	QCOMPARE(e.result, QString("success"));
	QCOMPARE(e.objectId, id.toString());
	QCOMPARE(e.params.value("name").toString(), QString("TLS server v2"));
	QCOMPARE(e.params.value("old_name").toString(), QString("TLS server"));

	reopenDatabase();
	temp = Store.lookupPki<pki_temp>(id);
	QVERIFY(temp);
	compareSpecs(TemplateSpec::fromTemplate(temp), spec);

	/* same name: no old_name */
	spec.comment = "changed";
	temps()->updateTemplate(ctx, temp, spec);
	QVERIFY(!AuditLog::entries().last().params.contains("old_name"));
	verifyChain();
}

/* A template that is not stored: nothing changes, one failure entry */
void test_service_template::updateRejected()
{
	pki_temp loose("loose");
	TemplateSpec spec = serverTemplate();
	int entries = AuditLog::entries().size();

	try {
		temps()->updateTemplate(ctx, &loose, spec);
		QFAIL("no serviceError");
	} catch (serviceError &err) {
		QCOMPARE(err.code, QString("missing_template"));
	}
	QCOMPARE(AuditLog::entries().size(), entries + 1);
	lastEntry("template.update", "failure", "missing_template");
	QCOMPARE(loose.getIntName(), QString("loose"));
	QCOMPARE(loose.getSetting("subAltName"), QString());

	try {
		temps()->updateTemplate(ctx, nullptr, spec);
		QFAIL("no serviceError");
	} catch (serviceError &err) {
		QCOMPARE(err.code, QString("missing_template"));
	}
	verifyChain();
}

/* Transform > Template: the template carries subject and extensions
 * of the certificate */
void test_service_template::fromObject()
{
	pki_x509 *ca = rootCa("Object CA");
	QVERIFY(ca);
	IssuanceSpec is = issuance(newKey("ee key"), ca);
	serverTemplate().applyTo(is);
	pki_x509 *cert = Database.model<db_x509>()->newCert(ctx, is);
	QVERIFY(cert);

	extList notPorted;
	TemplateSpec spec = TemplateSpec::fromObject(cert, &notPorted);
	QCOMPARE(spec.name, cert->getIntName());
	QCOMPARE(spec.source, transformed);
	QCOMPARE(spec.extensions.subjectAltName,
		QString("DNS:server.lab,IP:10.10.10.10"));
	QCOMPARE(spec.extensions.extKeyUsage,
		QStringList() << "serverAuth" << "clientAuth");
	/* pki_temp::fromCert(): 729 days are 24 months */
	QCOMPARE(spec.unit, TemplateSpec::months);
	QCOMPARE(spec.validity, 24);
	QVERIFY(spec.midnight);

	pki_temp *temp = temps()->newTemplate(ctx, spec);
	QVERIFY(temp);
	QCOMPARE(temp->pkiSource, transformed);
	lastEntry("template.create", "success");
	verifyChain();
}

void test_service_template::fromIssuanceSpec()
{
	IssuanceSpec is;
	is.templateName = "from issuance";
	is.subject.addEntryByNid(NID_commonName, "x");
	is.extensions.subjectAltName = "DNS:x.lab";
	is.notBefore = a1time(QDateTime(QDate(2026, 1, 1), QTime(0, 0, 0),
				QTimeZone::UTC));
	is.notAfter = a1time(QDateTime(QDate(2026, 12, 31), QTime(23, 59, 59),
				QTimeZone::UTC));

	TemplateSpec t = TemplateSpec::fromIssuanceSpec(is);
	QCOMPARE(t.name, QString("from issuance"));
	QCOMPARE(t.extensions.subjectAltName, QString("DNS:x.lab"));
	QCOMPARE(t.unit, TemplateSpec::days);
	QCOMPARE(t.validity, 365);
	QVERIFY(t.midnight);

	IssuanceSpec back;
	t.applyTo(back, is.notBefore);
	QCOMPARE(back.notBefore.toPlain(), is.notBefore.toPlain());
	QCOMPARE(back.notAfter.toPlain(), is.notAfter.toPlain());

	is.notAfter.setUndefined();
	QVERIFY(TemplateSpec::fromIssuanceSpec(is).noWellDefinedExpDate);
}

void test_service_template::deleteTemplate()
{
	pki_temp *temp = temps()->newTemplate(ctx, serverTemplate());
	QVERIFY(temp);
	QString id = temp->getSqlItemId().toString();

	DeleteResult r = temps()->deleteItems(ctx, { temp });
	QCOMPARE(r.deleted.size(), 1);
	QCOMPARE(r.deleted[0].objectType, QString("template"));
	QCOMPARE(r.deleted[0].id, id);
	QCOMPARE(r.deleted[0].name, QString("TLS server"));
	QVERIFY(r.dependents.isEmpty());

	AuditEntry e = AuditLog::entries().last();
	QCOMPARE(e.action, QString("template.delete"));
	QCOMPARE(e.result, QString("success"));
	QCOMPARE(e.objectId, id);
	QCOMPARE(e.params.value("name").toString(), QString("TLS server"));
	QVERIFY(Store.getAll<pki_temp>().isEmpty());
	reopenDatabase();
	QVERIFY(Store.getAll<pki_temp>().isEmpty());
	verifyChain();
}

XCA_SERVICE_TEST_MAIN(test_service_template)
#include "test_service_template.moc"
