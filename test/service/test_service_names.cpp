/* vi: set sw=4 ts=4:
 *
 * The names of a certificate before it is signed (BTD-167): the syntax of
 * every dNSName (the fuzz table of step-ca #2714), the name constraints of
 * every CA up to the root, the EKU as a subset of the issuers' EKU and the
 * name policies of bxc-pki (schemas/policy.schema.json, examples copied
 * to data/policies/). A refused name is a typed error that names the rule
 * and the value, audited as a failure; no row is stored and no serial is
 * drawn.
 */

#include <QJsonArray>
#include <QJsonDocument>
#include <QSqlQuery>

#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/db_key.h"
#include "lib/db_x509.h"
#include "lib/exception.h"
#include "lib/issuance.h"
#include "lib/pki_x509.h"
#include "lib/policy.h"
#include "lib/x509rev.h"

#include "ServiceTestCase.h"

class test_service_names : public ServiceTestCase
{
	Q_OBJECT

	ServiceContext ctx{ ServiceContext::cli, "os:service-test" };

	static pki_key *newKey(const QString &name)
	{
		return Database.model<db_key>()->newKey(keyjob("EC:prime256v1"), name);
	}
	static x509name dn(const QString &cn, const QString &o = "BxC Security")
	{
		x509name n;
		n.addEntryByNid(NID_countryName, "DE");
		if (!o.isEmpty())
			n.addEntryByNid(NID_organizationName, o);
		n.addEntryByNid(NID_commonName, cn);
		return n;
	}
	static IssuanceSpec caSpec(const QString &cn, pki_x509 *signer);
	static IssuanceSpec leafSpec(const QString &san, pki_x509 *signer);
	static Policy policy(const QString &id)
	{
		return Policy::fromFile(QString(SERVICE_TEST_DATA "/policies/%1.json")
					.arg(id));
	}
	pki_x509 *issue(const IssuanceSpec &spec);
	/* the code, "" when issued; a refusal must store nothing */
	QString attempt(const IssuanceSpec &spec, QString *message = nullptr);

  private slots:
	void dnsSyntax_data();
	void dnsSyntax();
	void nameConstraintsOverTheChain();
	void ekuSubsetOfIssuer();
	void policyNames_data();
	void policyNames();
	void policyIsTyped();
	void minimumContent();
	void strictIssuerKeyUsage();
	void uniquenessWithStatusFilter();
	void invalidPolicy();
	void otherNameForms_data();
	void otherNameForms();
	void ruleBoundaries_data();
	void ruleBoundaries();
};

IssuanceSpec test_service_names::caSpec(const QString &cn, pki_x509 *signer)
{
	IssuanceSpec spec;
	spec.name = cn;
	spec.subject = dn(cn);
	spec.key = newKey(cn);
	spec.signer = signer;
	spec.notBefore = a1time();
	spec.notAfter = a1time(QDateTime::currentDateTimeUtc().addDays(
				signer ? 1825 : 3650));
	spec.hashAlgo = digest(NID_sha256);
	spec.extensions.basicCA = ExtensionSpec::bc_ca;
	spec.extensions.basicCritical = true;
	spec.extensions.subjectKeyId = true;
	spec.extensions.authorityKeyId = true;
	spec.extensions.keyUsage << "keyCertSign" << "cRLSign";
	spec.extensions.keyUsageCritical = true;
	return spec;
}

IssuanceSpec test_service_names::leafSpec(const QString &san, pki_x509 *signer)
{
	IssuanceSpec spec;
	spec.name = "leaf " + san;
	spec.subject = dn("leaf");
	spec.key = newKey(spec.name);
	spec.signer = signer;
	spec.notBefore = a1time();
	spec.notAfter = a1time(QDateTime::currentDateTimeUtc().addDays(90));
	spec.hashAlgo = digest(NID_sha256);
	spec.extensions.basicCA = ExtensionSpec::bc_not_ca;
	spec.extensions.basicCritical = true;
	spec.extensions.subjectKeyId = true;
	spec.extensions.authorityKeyId = true;
	spec.extensions.keyUsage << "digitalSignature";
	spec.extensions.extKeyUsage << "serverAuth";
	spec.extensions.subjectAltName = san;
	return spec;
}

pki_x509 *test_service_names::issue(const IssuanceSpec &spec)
{
	try {
		return Database.model<db_x509>()->newCert(ctx, spec);
	} catch (errorEx &err) {
		qWarning() << "newCert failed:" << err.getString();
		return nullptr;
	}
}

QString test_service_names::attempt(const IssuanceSpec &spec, QString *message)
{
	int stored = Store.getAll<pki_x509>().size();
	int audit = AuditLog::entries().size();
	QSqlQuery q;
	q.exec("SELECT COUNT(*) FROM certs");
	int rows = q.next() ? q.value(0).toInt() : -1;
	try {
		Database.model<db_x509>()->newCert(ctx, spec);
		return QString();
	} catch (serviceError &err) {
		if (message)
			*message = err.getString();
		/* refused before the serial: nothing stored, one failure entry */
		if (Store.getAll<pki_x509>().size() != stored)
			return "<stored>";
		q.exec("SELECT COUNT(*) FROM certs");
		if (!q.next() || q.value(0).toInt() != rows)
			return "<row>";
		QList<AuditEntry> e = AuditLog::entries();
		if (e.size() != audit + 1 || e.last().result != "failure" ||
		    e.last().errorCode != err.code)
			return "<audit>";
		return err.code;
	} catch (errorEx &err) {
		return "<errorEx: " + err.getString() + ">";
	}
}

/* The fuzz table: what a dNSName must look like, with or without policy */
void test_service_names::dnsSyntax_data()
{
	QTest::addColumn<QString>("san");
	QTest::addColumn<QString>("code");

	QTest::newRow("host name") << "DNS:plc10.plant.example" << "";
	QTest::newRow("single label without policy") << "DNS:plc10" << "";
	QTest::newRow("wildcard") << "DNS:*.plant.example" << "";
	QTest::newRow("A-label") << "DNS:xn--mnchen-3ya.example" << "";
	QTest::newRow("empty label") << "DNS:plc10..example" << "invalid_dns_name";
	QTest::newRow("trailing dot") << "DNS:plc10.example." << "invalid_dns_name";
	QTest::newRow("U-label") << "DNS:münchen.example" << "invalid_dns_name";
	QTest::newRow("invalid A-label") << "DNS:xn--zz.example" << "invalid_dns_name";
	QTest::newRow("wildcard inside") << "DNS:www.*.example" << "invalid_dns_name";
	QTest::newRow("hyphen first") << "DNS:-plc.example" << "invalid_dns_name";
	QTest::newRow("underscore") << "DNS:plc_10.example" << "invalid_dns_name";
	QTest::newRow("wildcard on a TLD") << "DNS:*.com" << "invalid_dns_name";
	QTest::newRow("IP address as name") << "DNS:10.0.0.1" << "invalid_dns_name";
	QTest::newRow("longer than 253") << "DNS:" + QString("a.").repeated(127) + "example"
		<< "invalid_dns_name";
}

void test_service_names::dnsSyntax()
{
	QFETCH(QString, san);
	QFETCH(QString, code);
	pki_x509 *ca = issue(caSpec("Root CA", nullptr));
	QVERIFY(ca);
	QString message;
	QCOMPARE(attempt(leafSpec(san, ca), &message), code);
	if (!code.isEmpty())
		QVERIFY2(message.contains(san.mid(4)), CCHAR(message));
}

/* A SAN the intermediate permits but the root excludes is refused, and
 * the error names the root */
void test_service_names::nameConstraintsOverTheChain()
{
	IssuanceSpec r = caSpec("Plant Root", nullptr);
	r.extensions.nameConstraints =
		"critical, permitted;DNS:plant.example, excluded;DNS:secret.plant.example";
	pki_x509 *root = issue(r);
	QVERIFY(root);
	IssuanceSpec m = caSpec("Line CA", root);
	m.extensions.nameConstraints = "critical, permitted;DNS:plant.example";
	pki_x509 *mid = issue(m);
	QVERIFY(mid);

	QCOMPARE(attempt(leafSpec("DNS:plc10.line.plant.example", mid)), QString());
	QString message;
	QCOMPARE(attempt(leafSpec("DNS:plc11.secret.plant.example", mid), &message),
		QString("name_constraints_violation"));
	QVERIFY2(message.contains("Plant Root") && !message.contains("'Line CA'"),
		CCHAR(message));
	QCOMPARE(attempt(leafSpec("DNS:plc12.other.example", mid), &message),
		QString("name_constraints_violation"));
	QVERIFY2(message.contains("Line CA"), CCHAR(message));
	/* a CN that looks like a host name counts when there is no SAN
	 * (review of xca#56, NAME_CONSTRAINTS_check_CN) */
	IssuanceSpec cnOnly = leafSpec("", mid);
	cnOnly.subject = dn("plc13.secret.plant.example");
	QCOMPARE(attempt(cnOnly, &message), QString("name_constraints_violation"));
}

/* step-ca #2536: an end entity cannot have purposes its CA does not */
void test_service_names::ekuSubsetOfIssuer()
{
	IssuanceSpec c = caSpec("TLS Server CA", nullptr);
	c.extensions.extKeyUsage << "serverAuth";
	pki_x509 *ca = issue(c);
	QVERIFY(ca);
	QCOMPARE(attempt(leafSpec("DNS:www.example", ca)), QString());
	IssuanceSpec both = leafSpec("DNS:both.example", ca);
	both.extensions.extKeyUsage << "clientAuth";
	QString message;
	QCOMPARE(attempt(both, &message), QString("eku_not_in_issuer"));
	QVERIFY2(message.contains("clientAuth") && message.contains("TLS Server CA"),
		CCHAR(message));

	IssuanceSpec any = caSpec("Any CA", nullptr);
	any.extensions.extKeyUsage << "anyExtendedKeyUsage";
	pki_x509 *anyCa = issue(any);
	QVERIFY(anyCa);
	IssuanceSpec leaf = leafSpec("DNS:any.example", anyCa);
	leaf.extensions.extKeyUsage << "clientAuth" << "codeSigning";
	QCOMPARE(attempt(leaf), QString());
}

void test_service_names::policyNames_data()
{
	QTest::addColumn<QString>("policy");
	QTest::addColumn<QString>("san");
	QTest::addColumn<QString>("o");
	QTest::addColumn<QString>("code");

	QString lab = "ot-lab-names", web = "web-wildcard", O = "BxC Security";
	QTest::newRow("lab subtree") << lab << "DNS:plc10.lab.bxc-technology.de" << O << "";
	QTest::newRow("lab single label") << lab << "DNS:plc10" << O << "";
	QTest::newRow("lab single label, other pattern") << lab << "DNS:scalance" << O << "";
	QTest::newRow("single label without explicit rule") << lab << "DNS:switch" << O
		<< "policy_name_not_allowed";
	QTest::newRow("single label not matching") << lab << "DNS:plc10x" << O
		<< "policy_name_not_allowed";
	QTest::newRow("denied exact") << lab << "DNS:ca.lab.bxc-technology.de" << O
		<< "policy_name_denied";
	QTest::newRow("outside the subtree") << lab << "DNS:www.example.com" << O
		<< "policy_name_not_allowed";
	/* it covers the denied ca.lab.bxc-technology.de */
	QTest::newRow("wildcard without flag") << lab << "DNS:*.lab.bxc-technology.de" << O
		<< "policy_name_denied";
	QTest::newRow("wildcard without flag, nothing denied below") << lab
		<< "DNS:*.line1.lab.bxc-technology.de" << O << "policy_name_not_allowed";
	QTest::newRow("lab network") << lab << "IP:192.168.0.10" << O << "";
	QTest::newRow("outside the networks") << lab << "IP:172.16.0.1" << O
		<< "policy_name_not_allowed";
	QTest::newRow("urn prefix") << lab << "URI:urn:bxc:lab:plc10" << O << "";
	QTest::newRow("other urn") << lab << "URI:urn:other:plc10" << O
		<< "policy_name_not_allowed";
	QTest::newRow("no e-mail at all") << lab << "email:ops@bxc-technology.de" << O
		<< "policy_name_not_allowed";
	QTest::newRow("other organisation") << lab << "DNS:plc10" << "Other"
		<< "policy_name_not_allowed";

	QTest::newRow("wildcard covering a denied subtree") << web << "DNS:*.example.com"
		<< O << "policy_name_denied";
	QTest::newRow("wildcard allowed") << web << "DNS:*.www.example.com" << O << "";
	QTest::newRow("wildcard in denied subtree") << web << "DNS:*.internal.example.com"
		<< O << "policy_name_denied";
	QTest::newRow("host in denied subtree") << web << "DNS:db.internal.example.com"
		<< O << "policy_name_denied";
	QTest::newRow("wildcard elsewhere") << web << "DNS:*.example.org" << O
		<< "policy_name_not_allowed";
	QTest::newRow("IPv6 network") << web << "IP:2001:db8::1" << O << "";
	QTest::newRow("IPv6 denied") << web << "IP:2001:db8:ffff::1" << O
		<< "policy_name_denied";
	QTest::newRow("URI host subtree") << web << "URI:https://www.example.com/x" << O << "";
	QTest::newRow("URI other host") << web << "URI:https://example.org/" << O
		<< "policy_name_not_allowed";
	QTest::newRow("mailbox at the host") << web << "email:bob@example.com" << O << "";
	QTest::newRow("denied mailbox") << web << "email:root@example.com" << O
		<< "policy_name_denied";
	QTest::newRow("mailbox below the host") << web << "email:bob@mail.example.com" << O
		<< "policy_name_not_allowed";
}

void test_service_names::policyNames()
{
	QFETCH(QString, policy);
	QFETCH(QString, san);
	QFETCH(QString, o);
	QFETCH(QString, code);
	pki_x509 *ca = issue(caSpec("Policy CA", nullptr));
	QVERIFY(ca);
	IssuanceSpec spec = leafSpec(san, ca);
	spec.subject = dn("leaf", o);
	spec.policies << test_service_names::policy(policy);
	QString message;
	QCOMPARE(attempt(spec, &message), code);
	if (!code.isEmpty())
		QVERIFY2(message.contains(policy), CCHAR(message));
}

/* The error names the policy, the rule and the value */
void test_service_names::policyIsTyped()
{
	pki_x509 *ca = issue(caSpec("Policy CA", nullptr));
	IssuanceSpec spec = leafSpec("DNS:ca.lab.bxc-technology.de", ca);
	spec.policies << policy("ot-lab-names");
	QString message;
	QCOMPARE(attempt(spec, &message), QString("policy_name_denied"));
	QVERIFY2(message.contains("ot-lab-names") &&
		 message.contains("ca.lab.bxc-technology.de") &&
		 message.contains("\"type\":\"exact\""), CCHAR(message));
	/* without the policy the same name is issued */
	spec.policies.clear();
	QCOMPARE(attempt(spec), QString());
}

/* A certificate without extensions and one without the required O are
 * refused only under a policy that asks for them */
void test_service_names::minimumContent()
{
	pki_x509 *ca = issue(caSpec("Content CA", nullptr));
	IssuanceSpec bare;
	bare.name = "bare";
	bare.subject = dn("bare");
	bare.key = newKey("bare");
	bare.signer = ca;
	bare.notBefore = a1time();
	bare.notAfter = a1time(QDateTime::currentDateTimeUtc().addDays(30));
	bare.hashAlgo = digest(NID_sha256);
	bare.policies << policy("strict-content");
	QCOMPARE(attempt(bare), QString("policy_no_extensions"));
	bare.policies.clear();
	QCOMPARE(attempt(bare), QString());

	IssuanceSpec noO = leafSpec("DNS:no-o.example", ca);
	noO.subject = dn("no-o", QString());
	noO.policies << policy("strict-content");
	QString message;
	QCOMPARE(attempt(noO, &message), QString("policy_missing_dn_attribute"));
	QVERIFY2(message.contains("O ") || message.contains(" O"), CCHAR(message));
	noO.policies.clear();
	QCOMPARE(attempt(noO), QString());
}

/* Strict mode refuses an issuer without key usage; the default lets it
 * sign with a warning (BTD-55) */
void test_service_names::strictIssuerKeyUsage()
{
	IssuanceSpec c = caSpec("No KU CA", nullptr);
	c.extensions.keyUsage.clear();
	pki_x509 *ca = issue(c);
	QVERIFY(ca);
	IssuanceSpec leaf = leafSpec("DNS:strict.example", ca);
	leaf.policies << policy("strict-content");
	QCOMPARE(attempt(leaf), QString("policy_issuer_key_usage"));
	leaf.policies.clear();
	QCOMPARE(attempt(leaf), QString());
	QVERIFY(AuditLog::entries().last().params.value("warning").toString()
		.contains("issuer_without_key_usage"));
}

/* Only valid certificates count: after the revocation the same subject
 * can be issued again */
void test_service_names::uniquenessWithStatusFilter()
{
	pki_x509 *ca = issue(caSpec("Unique CA", nullptr));
	IssuanceSpec first = leafSpec("DNS:unique.example", ca);
	first.policies << policy("strict-content");
	pki_x509 *cert = issue(first);
	QVERIFY(cert);
	IssuanceSpec second = leafSpec("DNS:other.example", ca);
	second.policies << policy("strict-content");
	QString message;
	QCOMPARE(attempt(second, &message), QString("policy_not_unique"));
	QVERIFY2(message.contains("subject_dn"), CCHAR(message));

	/* another CA is another scope */
	pki_x509 *other = issue(caSpec("Other CA", nullptr));
	IssuanceSpec elsewhere = leafSpec("DNS:elsewhere.example", other);
	elsewhere.policies << policy("strict-content");
	QCOMPARE(attempt(elsewhere), QString());

	x509rev rev;
	rev.setReason("Key Compromise");
	Database.model<db_x509>()->revoke(ctx, cert, rev);
	QCOMPARE(attempt(second), QString());
}

void test_service_names::invalidPolicy()
{
	QJsonObject doc = policy("ot-lab-names").document();
	QCOMPARE(Policy::fromJson(doc).id, QString("ot-lab-names"));
	QJsonObject v2 = doc;
	v2["schema"] = "urn:bxc-pki:schema:policy:v2";
	QJsonObject empty;
	empty["schema"] = doc["schema"];
	empty["id"] = "empty";
	QJsonObject regex = doc;
	QJsonObject names = regex["names"].toObject();
	QJsonObject dns = names["dns"].toObject();
	dns["allow"] = QJsonArray{ QJsonObject{ { "type", "single-label" },
					{ "pattern", "plc[0-9" } } };
	names["dns"] = dns;
	regex["names"] = names;
	QList<QJsonObject> bad { v2, empty, regex };
	/* every rule as the schema has it (review of xca#56, blocker 5) */
	auto with = [&](const char *form, const char *list, const QJsonValue &rule) {
		QJsonObject d = doc;
		QJsonObject n = d["names"].toObject();
		QJsonObject f = n[form].toObject();
		f[list] = QJsonArray{ rule };
		n[form] = f;
		d["names"] = n;
		return d;
	};
	bad << with("ip", "allow", "192.168.0.10")
	    << with("ip", "deny", "10.0.0.0/33")
	    << with("ip", "deny", QJsonObject{ { "network", "10.0.0.0/8" } })
	    << with("dns", "deny", QJsonObject{ { "type", "subtree " },
					{ "value", "example.com" } })
	    << with("dns", "deny", QJsonObject{ { "type", "exact" },
					{ "value", ".example.com" } })
	    << with("dns", "allow", QJsonObject{ { "type", "subtree" },
					{ "value", "example.com" }, { "extra", 1 } })
	    << with("email", "deny", QJsonObject{ { "type", "mailbox" },
					{ "value", "a@b@example.com" } })
	    << with("uri", "deny", QJsonObject{ { "type", "starts-with" },
					{ "value", "urn:" } })
	    << with("dn", "allow", QJsonObject{ { "type", "exact" } });
	for (const QJsonObject &b : bad) {
		try {
			Policy::fromJson(b);
			QFAIL(QJsonDocument(b["names"].toObject()).toJson().constData());
		} catch (serviceError &err) {
			QCOMPARE(err.code, QString("invalid_policy"));
		}
	}
}

/* Blocker 4: names of other forms and the subject emailAddress do not
 * pass a policy that rules on names */
void test_service_names::otherNameForms_data()
{
	QTest::addColumn<QString>("san");
	QTest::addColumn<QString>("email");
	QTest::addColumn<QString>("code");
	QTest::newRow("otherName") << "DNS:plc10, otherName:1.3.6.1.4.1.311.20.2.3;UTF8:ceo@evil.org"
		<< "" << "policy_name_not_allowed";
	QTest::newRow("registeredID") << "DNS:plc10, RID:1.2.3.4" << ""
		<< "policy_name_not_allowed";
	QTest::newRow("subject emailAddress") << "DNS:plc10" << "ceo@evil.org"
		<< "policy_name_not_allowed";
	QTest::newRow("only allowed names") << "DNS:plc10" << "" << "";
}

void test_service_names::otherNameForms()
{
	QFETCH(QString, san);
	QFETCH(QString, email);
	QFETCH(QString, code);
	pki_x509 *ca = issue(caSpec("Policy CA", nullptr));
	IssuanceSpec spec = leafSpec(san, ca);
	if (!email.isEmpty()) {
		x509name n = dn("leaf");
		n.addEntryByNid(NID_pkcs9_emailAddress, email);
		spec.subject = n;
	}
	spec.policies << policy("ot-lab-names");
	QCOMPARE(attempt(spec), code);
}

/* Minors 7 and 8: a URI prefix ends at a boundary, an IPv4-mapped IPv6
 * address is an IPv4 address */
void test_service_names::ruleBoundaries_data()
{
	QTest::addColumn<QString>("san");
	QTest::addColumn<QString>("code");
	QTest::newRow("URI below the prefix") << "URI:https://plc.example.com/opc"
		<< "";
	QTest::newRow("URI host continues") << "URI:https://plc.example.com.evil.org/"
		<< "policy_name_not_allowed";
	QTest::newRow("URI user part") << "URI:https://plc.example.com@evil.org/"
		<< "policy_name_not_allowed";
	QTest::newRow("IPv4") << "IP:192.168.1.5" << "";
	QTest::newRow("IPv4 denied") << "IP:10.1.2.3" << "policy_name_denied";
	QTest::newRow("IPv4-mapped denied") << "IP:::ffff:10.1.2.3" << "policy_name_denied";
}

void test_service_names::ruleBoundaries()
{
	QFETCH(QString, san);
	QFETCH(QString, code);
	QJsonObject doc {
		{ "schema", "urn:bxc-pki:schema:policy:v1" },
		{ "id", "boundaries" },
		{ "description", "URI prefix and IP rules" },
		{ "names", QJsonObject{
			{ "uri", QJsonObject{ { "allow", QJsonArray{ QJsonObject{
				{ "type", "prefix" },
				{ "value", "https://plc.example.com" } } } } } },
			{ "ip", QJsonObject{ { "deny", QJsonArray{ "10.0.0.0/8" } } } },
		} },
	};
	pki_x509 *ca = issue(caSpec("Policy CA", nullptr));
	IssuanceSpec spec = leafSpec(san, ca);
	spec.policies << Policy::fromJson(doc);
	QCOMPARE(attempt(spec), code);
}

XCA_SERVICE_TEST_MAIN(test_service_names)
#include "test_service_names.moc"
