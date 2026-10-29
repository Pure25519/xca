/* vi: set sw=4 ts=4:
 *
 * Profiles and name policies as stored, versioned, audited documents
 * (BTD-167): every profile and policy of bxc-pki imports, is listed and
 * shown with its version; an update makes a new version; a version that
 * issued a certificate is kept; a profile is assigned to a CA only when
 * its signature fits the CA key; the issued certificate's audit entry
 * names profile, version, policies and the policy result.
 */

#include <QDir>
#include <QJsonArray>
#include <QProcess>
#include <QSqlQuery>
#include <QTemporaryDir>

#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/db_key.h"
#include "lib/db_x509.h"
#include "lib/db_x509req.h"
#include "lib/exception.h"
#include "lib/pki_x509.h"
#include "lib/pki_x509req.h"
#include "lib/profile.h"
#include "lib/profile_store.h"

#include "ServiceTestCase.h"

class test_service_profile_store : public ServiceTestCase
{
	Q_OBJECT

	ServiceContext ctx{ ServiceContext::cli, "os:service-test" };
	QTemporaryDir dir{};

	static QStringList files(const QString &sub)
	{
		QDir d(QString(SERVICE_TEST_DATA "/") + sub);
		QStringList list;
		for (const QString &f : d.entryList({ "*.json" }, QDir::Files))
			if (f != "PROVENANCE.json")
				list << d.filePath(f);
		return list;
	}
	pki_x509 *ca(const QString &job);
	pki_x509req *csr(const QString &subject, const QString &san);
	/* the error code of f, "" when it succeeded */
	template <class F> static QString code(F f)
	{
		try {
			f();
			return QString();
		} catch (serviceError &err) {
			return err.code;
		}
	}

  private slots:
	void importAndVersions();
	void invalidImport();
	void versionInUseIsKept();
	void assignmentChecksSignature();
	void issuedUnderProfileAndPolicy();
};

pki_x509 *test_service_profile_store::ca(const QString &job)
{
	IssuanceSpec s;
	s.name = "Store CA " + job;
	x509name n;
	n.addEntryByNid(NID_organizationName, "BxC Security");
	n.addEntryByNid(NID_commonName, s.name);
	s.subject = n;
	s.key = Database.model<db_key>()->newKey(keyjob(job), s.name);
	s.notBefore = a1time(QDateTime::currentDateTimeUtc().addDays(-1));
	s.notAfter = a1time(QDateTime::currentDateTimeUtc().addDays(1000));
	s.hashAlgo = digest(NID_sha256);
	s.extensions.basicCA = ExtensionSpec::bc_ca;
	s.extensions.basicCritical = true;
	s.extensions.subjectKeyId = true;
	s.extensions.keyUsage << "keyCertSign" << "cRLSign";
	s.extensions.keyUsageCritical = true;
	return Database.model<db_x509>()->newCert(ctx, s);
}

pki_x509req *test_service_profile_store::csr(const QString &subject,
			const QString &san)
{
#ifndef OPENSSL_PROGRAM
	Q_UNUSED(subject); Q_UNUSED(san);
	return nullptr;
#else
	static int n = 0;
	QString out = dir.filePath(QString("store-%1.csr").arg(++n));
	QStringList args { "req", "-new", "-newkey", "ec", "-pkeyopt",
		"ec_paramgen_curve:P-256", "-nodes", "-keyout", out + ".key",
		"-out", out, "-subj", subject };
	if (!san.isEmpty())
		args << "-addext" << "subjectAltName=" + san;
	QProcess proc;
	proc.start(OPENSSL_PROGRAM, args);
	if (!proc.waitForFinished(30000) || proc.exitCode() != 0)
		return nullptr;
	pki_x509req *req = new pki_x509req(subject);
	req->fload(out);
	return dynamic_cast<pki_x509req *>(
			Database.model<db_x509req>()->insert(req));
#endif
}

void test_service_profile_store::importAndVersions()
{
	int before = AuditLog::entries().size();
	QStringList profiles = files("profiles") + files("profiles/generic");
	QCOMPARE(profiles.size(), 14);
	for (const QString &f : profiles)
		QCOMPARE(ProfileStore::importFile(ctx, "profile", f).version, 1);
	for (const QString &f : files("policies"))
		QCOMPARE(ProfileStore::importFile(ctx, "policy", f).version, 1);

	QList<ProfileStore::Document> list = ProfileStore::list("profile");
	QCOMPARE(list.size(), 14);
	QCOMPARE(ProfileStore::list("policy").size(), 3);
	ProfileStore::Document web = ProfileStore::show("profile", "tls-server-web");
	QCOMPARE(web.version, 1);
	QCOMPARE(Profile::fromJson(web.document).id, QString("tls-server-web"));
	QVERIFY(!web.created.isEmpty());

	/* an update is the next version, the old one stays readable */
	QJsonObject changed = web.document;
	changed["description"] = "Web servers, second version";
	QCOMPARE(ProfileStore::update(ctx, "profile", changed).version, 2);
	QCOMPARE(ProfileStore::show("profile", "tls-server-web").version, 2);
	QCOMPARE(ProfileStore::show("profile", "tls-server-web", 1)
		.document["description"], web.document["description"]);
	QCOMPARE(ProfileStore::list("profile").size(), 14);
	QCOMPARE(code([&]() { ProfileStore::create(ctx, "profile", changed); }),
		QString("document_exists"));
	QJsonObject unknown = changed;
	unknown["id"] = "unknown-profile";
	QCOMPARE(code([&]() { ProfileStore::update(ctx, "profile", unknown); }),
		QString("document_not_found"));

	/* one entry per change, the chain verifies */
	QList<AuditEntry> e = AuditLog::entries().mid(before);
	QStringList actions;
	for (const AuditEntry &a : e)
		actions << a.action + ":" + a.result;
	QCOMPARE(actions.count("profile.import:success"), 14);
	QCOMPARE(actions.count("policy.import:success"), 3);
	QCOMPARE(actions.count("profile.update:success"), 1);
	QCOMPARE(actions.count("profile.create:failure"), 1);
	QCOMPARE(actions.count("profile.update:failure"), 1);
	AuditEntry update = e[e.size() - 3];
	QCOMPARE(update.objectId, QString("tls-server-web"));
	QCOMPARE(update.params.value("version").toInt(), 2);
	QCOMPARE(update.actor, QString("os:service-test"));
	QVERIFY(AuditLog::verify().ok());
}

/* A document that fails its checks is not stored */
void test_service_profile_store::invalidImport()
{
	QFile f(SERVICE_TEST_DATA "/profiles/opcua-server.json");
	QVERIFY(f.open(QIODevice::ReadOnly));
	QJsonObject doc = QJsonDocument::fromJson(f.readAll()).object();
	doc["eku_default"] = QJsonArray{ "clientAuth" };
	QCOMPARE(code([&]() { ProfileStore::create(ctx, "profile", doc); }),
		QString("invalid_profile"));
	QCOMPARE(ProfileStore::list("profile").size(), 0);
	QFile bad(dir.filePath("bad.json"));
	QVERIFY(bad.open(QIODevice::WriteOnly));
	bad.write("{ no json");
	bad.close();
	QCOMPARE(code([&]() { ProfileStore::importFile(ctx, "policy", bad.fileName()); }),
		QString("invalid_policy"));
	QCOMPARE(code([&]() { ProfileStore::list("template"); }),
		QString("invalid_kind"));
	QCOMPARE(AuditLog::entries().last().action, QString("policy.import"));
	QCOMPARE(AuditLog::entries().last().result, QString("failure"));
}

/* A version that issued a certificate is never deleted; an unused one is */
void test_service_profile_store::versionInUseIsKept()
{
	ProfileStore::importFile(ctx, "profile",
		SERVICE_TEST_DATA "/profiles/generic/xca-tls-client.json");
	pki_x509 *c = ca("EC:prime256v1");
	ProfileStore::assign(ctx, c, "profile", "xca-tls-client");
	pki_x509req *req = csr("/CN=client", "");
	QVERIFY(req);
	pki_x509 *cert = ProfileStore::issue(ctx, c, "xca-tls-client", req,
				nullptr, Registration());
	QVERIFY(cert);
	QCOMPARE(code([&]() { ProfileStore::remove(ctx, "profile", "xca-tls-client", 1); }),
		QString("profile_in_use"));
	ProfileStore::Document v2 = ProfileStore::update(ctx, "profile",
		ProfileStore::show("profile", "xca-tls-client").document);
	QCOMPARE(v2.version, 2);
	QCOMPARE(code([&]() { ProfileStore::remove(ctx, "profile", "xca-tls-client", 2); }),
		QString());
	QCOMPARE(ProfileStore::show("profile", "xca-tls-client").version, 1);
	QCOMPARE(AuditLog::entries().last().action, QString("profile.delete"));

	/* retired: listed, but it issues no more */
	ProfileStore::retire(ctx, "profile", "xca-tls-client");
	QVERIFY(ProfileStore::show("profile", "xca-tls-client").retired);
	pki_x509req *again = csr("/CN=client2", "");
	QCOMPARE(code([&]() { ProfileStore::issue(ctx, c, "xca-tls-client", again,
				nullptr, Registration()); }),
		QString("profile_not_assigned"));
}

/* OpenXPKI #960: a profile whose signature does not fit the CA key is
 * refused when it is assigned, not when it issues */
void test_service_profile_store::assignmentChecksSignature()
{
	QFile f(SERVICE_TEST_DATA "/profiles/generic/xca-tls-client.json");
	QVERIFY(f.open(QIODevice::ReadOnly));
	QJsonObject pss = QJsonDocument::fromJson(f.readAll()).object();
	pss["id"] = "rsa-pss-client";
	pss["key_types"] = QJsonArray{ "rsa-2048", "rsa-3072" };
	QJsonObject ku = pss["ku_by_key_type"].toObject();
	ku.remove("ec");
	pss["ku_by_key_type"] = ku;
	pss["signature"] = QJsonObject{ { "rsa", QJsonObject{
		{ "padding", "pss" }, { "hashes", QJsonArray{ "sha256" } } } } };
	ProfileStore::create(ctx, "profile", pss);
	ProfileStore::importFile(ctx, "profile",
		SERVICE_TEST_DATA "/profiles/tls-server-web.json");

	pki_x509 *ec = ca("EC:prime256v1");
	int before = AuditLog::entries().size();
	QCOMPARE(code([&]() { ProfileStore::assign(ctx, ec, "profile", "rsa-pss-client"); }),
		QString("profile_signature_mismatch"));
	QCOMPARE(AuditLog::entries().size(), before + 1);
	QCOMPARE(AuditLog::entries().last().result, QString("failure"));
	QVERIFY(ProfileStore::assigned(ec, "profile").isEmpty());

	pki_x509 *rsa = ca("RSA:2048");
	QCOMPARE(code([&]() { ProfileStore::assign(ctx, rsa, "profile", "rsa-pss-client"); }),
		QString());
	QCOMPARE(code([&]() { ProfileStore::assign(ctx, ec, "profile", "tls-server-web"); }),
		QString());
	QCOMPARE(code([&]() { ProfileStore::assign(ctx, ec, "profile", "tls-server-web"); }),
		QString("already_assigned"));
	QCOMPARE(ProfileStore::assigned(ec, "profile"), QStringList{ "tls-server-web" });

	/* only an assigned profile issues; the profile is chosen by name */
	pki_x509req *req = csr("/CN=plc10", "DNS:plc10");
	QCOMPARE(code([&]() { ProfileStore::issue(ctx, rsa, "tls-server-web", req,
				nullptr, Registration()); }),
		QString("profile_not_assigned"));
	QCOMPARE(AuditLog::entries().last().errorCode, QString("profile_not_assigned"));
	ProfileStore::unassign(ctx, ec, "profile", "tls-server-web");
	QVERIFY(ProfileStore::assigned(ec, "profile").isEmpty());
}

/* The audit entry of the certificate names profile, version, policies and
 * the result; a name outside the policy is refused before signing */
void test_service_profile_store::issuedUnderProfileAndPolicy()
{
	ProfileStore::importFile(ctx, "profile",
		SERVICE_TEST_DATA "/profiles/tls-server-web.json");
	ProfileStore::importFile(ctx, "policy",
		SERVICE_TEST_DATA "/policies/ot-lab-names.json");
	ProfileStore::importFile(ctx, "policy",
		SERVICE_TEST_DATA "/policies/strict-content.json");
	pki_x509 *c = ca("EC:prime256v1");
	ProfileStore::assign(ctx, c, "profile", "tls-server-web");
	ProfileStore::assign(ctx, c, "policy", "ot-lab-names");
	ProfileStore::assignToProfile(ctx, "tls-server-web", "strict-content");

	pki_x509req *req = csr("/O=BxC Security/CN=plc10", "DNS:plc10");
	QVERIFY(req);
	pki_x509 *cert = ProfileStore::issue(ctx, c, "tls-server-web", req,
				nullptr, Registration());
	QVERIFY(cert);
	AuditEntry e = AuditLog::entries().last();
	QCOMPARE(e.action, QString("certificate.issue"));
	QCOMPARE(e.params.value("profile").toString(), QString("tls-server-web"));
	QCOMPARE(e.params.value("profile_version").toInt(), 1);
	QCOMPARE(e.params.value("policies").toString(),
		QString("ot-lab-names,strict-content"));
	QCOMPARE(e.params.value("policy_result").toString(), QString("pass"));
	QSqlQuery q;
	QVERIFY(q.exec(QString("SELECT profile, version, policies FROM "
		"issued_profiles WHERE item=%1").arg(cert->getSqlItemId().toLongLong())));
	QVERIFY(q.next());
	QCOMPARE(q.value(0).toString() + "|" + q.value(1).toString() + "|" +
		q.value(2).toString(),
		QString("tls-server-web|1|ot-lab-names,strict-content"));

	int stored = Store.getAll<pki_x509>().size();
	pki_x509req *outside = csr("/O=BxC Security/CN=www", "DNS:www.example.com");
	QCOMPARE(code([&]() { ProfileStore::issue(ctx, c, "tls-server-web", outside,
				nullptr, Registration()); }),
		QString("policy_name_not_allowed"));
	QCOMPARE(Store.getAll<pki_x509>().size(), stored);
	QCOMPARE(AuditLog::entries().last().params.value("policies").toString(),
		QString("ot-lab-names,strict-content"));

	/* a policy that issued is kept as well */
	QCOMPARE(code([&]() { ProfileStore::remove(ctx, "policy", "ot-lab-names", 1); }),
		QString("profile_in_use"));
	QVERIFY(AuditLog::verify().ok());
}

XCA_SERVICE_TEST_MAIN(test_service_profile_store)
#include "test_service_profile_store.moc"
