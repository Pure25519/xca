/* vi: set sw=4 ts=4:
 *
 * Assignments to a setting (BTD-173): a string literal is stored as its
 * text. Without an overload for const char * the literal took the standard
 * pointer-to-bool conversion and was stored as "yes"; the command line,
 * bootstrap and the REST server write settings from literals.
 */

#include <type_traits>
#include <utility>

#include <QSqlQuery>

#include "lib/settings.h"

#include "ServiceTestCase.h"

/* the assignment of a literal resolves to the const char * overload, not
 * to the bool one */
static_assert(std::is_same_v<decltype(std::declval<svalue &>() = "x"),
		const char *>, "a literal must not be assigned as bool");

class test_service_settings : public ServiceTestCase
{
	Q_OBJECT

	static QString stored(const QString &key);

  private slots:
	void literalIsStoredAsText();
	void boolStillYesNo();
};

/* the value in the settings table, as another process reads it */
QString test_service_settings::stored(const QString &key)
{
	QSqlQuery q;
	q.prepare("SELECT value FROM settings WHERE key_=?");
	q.addBindValue(key);
	if (!q.exec() || !q.first())
		return QString("<none>");
	return q.value(0).toString();
}

void test_service_settings::literalIsStoredAsText()
{
	Settings["pkcs12_enc_algo"] = "AES-256-CBC";
	QCOMPARE(QString(Settings["pkcs12_enc_algo"]), QString("AES-256-CBC"));
	QCOMPARE(stored("pkcs12_enc_algo"), QString("AES-256-CBC"));

	const char *value = "3DES-CBC";
	Settings["pkcs12_enc_algo"] = value;
	QCOMPARE(stored("pkcs12_enc_algo"), QString("3DES-CBC"));
}

void test_service_settings::boolStillYesNo()
{
	Settings["hide_unusable"] = true;
	QCOMPARE(stored("hide_unusable"), QString("yes"));
	QVERIFY((bool)Settings["hide_unusable"]);
	Settings["hide_unusable"] = false;
	QCOMPARE(stored("hide_unusable"), QString("no"));
	QVERIFY(!(bool)Settings["hide_unusable"]);
}

XCA_SERVICE_TEST_MAIN(test_service_settings)
#include "test_service_settings.moc"
