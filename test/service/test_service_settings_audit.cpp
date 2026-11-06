/* vi: set sw=4 ts=4:
 *
 * settings::update() (BTD-224): one settings.update entry per changed
 * setting, in the transaction of the write; values in clear only for
 * the options of the Options dialog, never for a password or its hash;
 * a failed write leaves neither setting nor entry.
 */

#include <QJsonDocument>
#include <QJsonObject>
#include <QSqlError>
#include <QSqlQuery>

#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/exception.h"
#include "lib/settings.h"

#include "ServiceTestCase.h"

class test_service_settings_audit : public ServiceTestCase
{
	Q_OBJECT

	ServiceContext ctx{ ServiceContext::gui, "os:service-test" };

	static QString sql(const QString &stmt)
	{
		QSqlQuery q;
		return q.exec(stmt) ? QString() : q.lastError().text();
	}
	static QList<AuditEntry> updates(int first)
	{
		QList<AuditEntry> list, all = AuditLog::entries();
		for (int i = first; i < all.size(); i++)
			if (all[i].action == "settings.update")
				list << all[i];
		return list;
	}

  private slots:
	void clearAndRedacted();
	void passwordHashNeverInClear();
	void readOnlyWritesNothing();
};

/* an Options key in clear, any other key redacted without a value, a
 * host-specific one named with its host id */
void test_service_settings_audit::clearAndRedacted()
{
	int first = AuditLog::entries().size();
	Settings.update(ctx, {
		{ "serial_len", "96" },
		{ "mw_geometry", "BTD-224 geometry" },
	});
	QList<AuditEntry> e = updates(first);
	QCOMPARE(e.size(), 2);
	for (const AuditEntry &u : e) {
		QString key = u.params.value("setting").toString();
		if (key == "serial_len") {
			QCOMPARE(u.params.value("new_value").toString(),
				QString("96"));
			QVERIFY(u.params.contains("old_value"));
			QVERIFY(!u.params.contains("redacted"));
		} else {
			/* host-specific: the stored key with its host id */
			QVERIFY2(key.startsWith("mw_geometry:"), CCHAR(key));
			QCOMPARE(u.params.value("redacted").toBool(), true);
			QVERIFY(!u.params.contains("old_value"));
			QVERIFY(!u.params.contains("new_value"));
		}
		QCOMPARE(u.channel, QString("gui"));
	}
	/* unchanged: nothing */
	first = AuditLog::entries().size();
	Settings.update(ctx, { { "serial_len", "96" } });
	QCOMPARE(updates(first).size(), 0);
	QVERIFY(AuditLog::verify().ok());
}

/* pwhash and a password-like key are redacted, and no entry of the
 * whole log holds the hash */
void test_service_settings_audit::passwordHashNeverInClear()
{
	QString hash = Settings["pwhash"];
	QVERIFY(!hash.isEmpty());
	int first = AuditLog::entries().size();
	Settings.update(ctx, {
		{ "pwhash", hash + "x" },
		{ "token_password", "secret-224" },
	});
	QList<AuditEntry> e = updates(first);
	QCOMPARE(e.size(), 2);
	for (const AuditEntry &u : e) {
		QCOMPARE(u.params.value("redacted").toBool(), true);
		QVERIFY(!u.params.contains("new_value"));
	}
	for (const AuditEntry &a : AuditLog::entries()) {
		QByteArray json = QJsonDocument(QJsonObject::fromVariantMap(
					a.params)).toJson();
		QVERIFY2(!json.contains(hash.toUtf8()), json.constData());
		QVERIFY2(!json.contains("secret-224"), json.constData());
	}
	Settings.update(ctx, { { "pwhash", hash } });
}

/* a write that fails stores neither the setting nor an entry */
void test_service_settings_audit::readOnlyWritesNothing()
{
	QString before = Settings["serial_len"];
	int first = AuditLog::entries().size();
	QCOMPARE(sql("PRAGMA query_only = ON"), QString());
	try {
		Settings.update(ctx, { { "serial_len", "128" } });
		sql("PRAGMA query_only = OFF");
		QFAIL("update() did not throw");
	} catch (errorEx &) {
	}
	QCOMPARE(sql("PRAGMA query_only = OFF"), QString());
	QCOMPARE(QString(Settings["serial_len"]), before);
	QCOMPARE(updates(first).size(), 0);
	QSqlQuery q;
	QVERIFY(q.exec("SELECT value FROM settings WHERE key_='serial_len'"));
	if (q.next())
		QCOMPARE(q.value(0).toString(), before);
}

XCA_SERVICE_TEST_MAIN(test_service_settings_audit)
#include "test_service_settings_audit.moc"
