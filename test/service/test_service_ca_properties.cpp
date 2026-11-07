/* vi: set sw=4 ts=4:
 *
 * The CA Properties of the GUI (BTD-219): the CRL days change the stored
 * CRL setting of the CA (the crlpolicy_<id> row the command line uses)
 * with one ca.crl_settings entry, a template change is audited, and a
 * failed store leaves database and memory as they were.
 */

#include <QSqlError>
#include <QSqlQuery>

#include "lib/audit.h"
#include "lib/crl_policy.h"
#include "lib/database_model.h"
#include "lib/db_key.h"
#include "lib/db_temp.h"
#include "lib/db_x509.h"
#include "lib/exception.h"
#include "lib/issuance.h"
#include "lib/pki_temp.h"
#include "lib/template.h"
#include "lib/pki_x509.h"

#include "ServiceTestCase.h"

class test_service_ca_properties : public ServiceTestCase
{
	Q_OBJECT

	ServiceContext cli{ ServiceContext::cli, "os:service-test" };
	ServiceContext gui{ ServiceContext::gui, "os:service-test" };

	static db_x509 *certs()
	{
		return Database.model<db_x509>();
	}
	pki_x509 *rootCa(const QString &cn);
	pki_temp *newTemplate(const QString &name);
	static bool sql(const QString &statement);
	static QString storedPolicy(pki_x509 *ca);
	static int storedCrlDays(pki_x509 *ca);
	static QVariant storedTemplate(pki_x509 *ca);
	/* the CA Properties dialog: CRL days and template of ca */
	void setProperties(pki_x509 *ca, int days, pki_temp *temp);

  private slots:
	void crlDaysUpdateTheCrlSetting();
	void templateChangeIsAudited();
	void failedStoreKeepsEverything();
};

pki_x509 *test_service_ca_properties::rootCa(const QString &cn)
{
	QDateTime now = QDateTime::currentDateTimeUtc();
	IssuanceSpec spec;
	spec.name = cn;
	spec.subject.addEntryByNid(NID_commonName, cn);
	spec.key = Database.model<db_key>()->newKey(keyjob("EC:prime256v1"),
			cn + " key");
	spec.notBefore = a1time(now.addDays(-1));
	spec.notAfter = a1time(now.addYears(5));
	spec.hashAlgo = digest(NID_sha256);
	spec.extensions.basicCA = ExtensionSpec::bc_ca;
	spec.extensions.basicCritical = true;
	spec.extensions.keyUsage << "keyCertSign" << "cRLSign";
	try {
		return certs()->newCert(cli, spec);
	} catch (errorEx &err) {
		qWarning() << "newCert failed:" << err.getString();
		return nullptr;
	}
}

pki_temp *test_service_ca_properties::newTemplate(const QString &name)
{
	TemplateSpec t;
	t.name = name;
	t.extensions.basicCA = ExtensionSpec::bc_not_ca;
	return Database.model<db_temp>()->newTemplate(cli, t);
}

bool test_service_ca_properties::sql(const QString &statement)
{
	QSqlQuery q(QSqlDatabase::database());
	if (q.exec(statement))
		return true;
	qWarning() << statement << q.lastError().text();
	return false;
}

QString test_service_ca_properties::storedPolicy(pki_x509 *ca)
{
	QSqlQuery q(QSqlDatabase::database());
	q.prepare("SELECT value FROM settings WHERE key_=?");
	q.addBindValue(QString("crlpolicy_%1").arg(
			ca->getSqlItemId().toLongLong()));
	return q.exec() && q.first() ? q.value(0).toString() : QString();
}

int test_service_ca_properties::storedCrlDays(pki_x509 *ca)
{
	QSqlQuery q(QSqlDatabase::database());
	q.prepare("SELECT crlDays FROM authority WHERE item=?");
	q.addBindValue(ca->getSqlItemId());
	return q.exec() && q.first() ? q.value(0).toInt() : -1;
}

QVariant test_service_ca_properties::storedTemplate(pki_x509 *ca)
{
	QSqlQuery q(QSqlDatabase::database());
	q.prepare("SELECT template FROM authority WHERE item=?");
	q.addBindValue(ca->getSqlItemId());
	return q.exec() && q.first() ? q.value(0) : QVariant();
}

void test_service_ca_properties::setProperties(pki_x509 *ca, int days,
		pki_temp *temp)
{
	certs()->setCaProperties(gui, ca, days,
			temp ? temp->getSqlItemId() : QVariant());
}

/* The command line's setting of the CA follows the GUI's CRL days, with
 * one ca.crl_settings entry of channel gui */
void test_service_ca_properties::crlDaysUpdateTheCrlSetting()
{
	pki_x509 *ca = rootCa("Properties Root CA");
	QVERIFY(ca);
	CrlPolicy p = CrlPolicy::of(ca);
	p.validity = IsoDuration::parse("P7D");
	p.sizeBudget = 8192;
	p.store(cli, ca);
	QCOMPARE(CrlPolicy::of(ca).validity.toString(), QString("P7D"));
	int entries = AuditLog::entries().size();

	setProperties(ca, 15, nullptr);

	CrlPolicy now = CrlPolicy::of(ca);
	QCOMPARE(now.validity.toString(), QString("P15D"));
	QCOMPARE(now.sizeBudget, (qint64)8192);
	QVERIFY2(storedPolicy(ca).contains("\"P15D\""),
		CCHAR(storedPolicy(ca)));
	QCOMPARE(storedCrlDays(ca), 15);
	QCOMPARE(AuditLog::entries().size(), entries + 1);
	AuditEntry e = AuditLog::entries().last();
	QCOMPARE(e.action, QString(CrlPolicy::actionSettings));
	QCOMPARE(e.channel, QString("gui"));
	QCOMPARE(e.result, QString("success"));
	QCOMPARE(e.params["crl_validity"].toString(), QString("P15D"));
	QCOMPARE(e.params["size_budget"].toLongLong(), 8192);
	AuditVerifyResult v = AuditLog::verify();
	QVERIFY2(v.ok(), v.toJson().constData());
}

/* A template change writes its own entry; unchanged CRL days none */
void test_service_ca_properties::templateChangeIsAudited()
{
	pki_x509 *ca = rootCa("Template Root CA");
	pki_temp *temp = newTemplate("Device template");
	QVERIFY(ca && temp);
	int days = ca->getCrlDays();
	int entries = AuditLog::entries().size();

	setProperties(ca, days, temp);

	QCOMPARE(storedTemplate(ca), temp->getSqlItemId());
	QCOMPARE(AuditLog::entries().size(), entries + 1);
	AuditEntry e = AuditLog::entries().last();
	QCOMPARE(e.action, QString("ca.set_template"));
	QCOMPARE(e.channel, QString("gui"));
	QCOMPARE(e.result, QString("success"));
	QCOMPARE(e.params["template"].toString(), QString("Device template"));
	AuditVerifyResult v = AuditLog::verify();
	QVERIFY2(v.ok(), v.toJson().constData());
}

/* A store the database refuses: typed error, one failure entry, crlDays,
 * setting row and template unchanged in the database and in memory */
void test_service_ca_properties::failedStoreKeepsEverything()
{
	pki_x509 *ca = rootCa("Readonly Root CA");
	pki_temp *temp = newTemplate("Readonly template");
	QVERIFY(ca && temp);
	CrlPolicy p = CrlPolicy::of(ca);
	p.validity = IsoDuration::parse("P7D");
	p.store(cli, ca);
	QString policy = storedPolicy(ca);
	int days = storedCrlDays(ca);
	QVariant tmpl = storedTemplate(ca);
	/* in memory "no template" is an invalid QVariant, in SQL a null string */
	QVariant memTmpl = ca->getTemplateSqlId();
	QCOMPARE(ca->getCrlDays(), days);
	int entries = AuditLog::entries().size();

	QVERIFY(sql("CREATE TRIGGER btd219_fault BEFORE UPDATE ON authority "
		"BEGIN SELECT RAISE(ABORT, 'read-only'); END"));
	QString code;
	try {
		setProperties(ca, 30, temp);
	} catch (serviceError &err) {
		code = err.code;
	} catch (errorEx &err) {
		code = "untyped: " + err.getString();
	}
	QVERIFY(sql("DROP TRIGGER btd219_fault"));

	QCOMPARE(code, QString("database_error"));
	QCOMPARE(storedPolicy(ca), policy);
	QCOMPARE(storedCrlDays(ca), days);
	QCOMPARE(storedTemplate(ca), tmpl);
	QCOMPARE(ca->getCrlDays(), days);
	QCOMPARE(ca->getTemplateSqlId(), memTmpl);
	QCOMPARE(AuditLog::entries().size(), entries + 1);
	AuditEntry e = AuditLog::entries().last();
	QCOMPARE(e.result, QString("failure"));
	QCOMPARE(e.errorCode, QString("database_error"));
	AuditVerifyResult v = AuditLog::verify();
	QVERIFY2(v.ok(), v.toJson().constData());
}

XCA_SERVICE_TEST_MAIN(test_service_ca_properties)
#include "test_service_ca_properties.moc"
