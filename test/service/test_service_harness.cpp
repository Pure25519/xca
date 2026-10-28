/* vi: set sw=4 ts=4:
 *
 * Self-tests of the service test harness (ServiceTestCase).
 */

#include <QDir>
#include <QFileInfo>

#include "lib/database_model.h"
#include "lib/db_key.h"
#include "lib/settings.h"

#include "ServiceTestCase.h"

class test_service_harness : public ServiceTestCase
{
	Q_OBJECT

	QString previousDbFile{};

  private slots:
	void freshDatabase();
	void freshDatabaseAgain();
	void reopenAsksForPassword();
	void expectedMessageIsConsumed();
	void unexpectedPromptIsRecorded();
	void selfcheckUnexpectedPrompt();
};

void test_service_harness::freshDatabase()
{
	QVERIFY(QFileInfo::exists(dbFile));
	QVERIFY(!dbFile.startsWith(QDir::currentPath() + "/"));
	QVERIFY(Database.model<db_key>());
	QCOMPARE(Store.getAll<pki_key>().size(), 0);

	QVERIFY(Database.model<db_key>()->newKey(keyjob("RSA:2048"), "left"));
	QCOMPARE(Store.getAll<pki_key>().size(), 1);
	previousDbFile = dbFile;
}

void test_service_harness::freshDatabaseAgain()
{
	/* The database of the previous test is gone, this one is empty */
	QVERIFY(!previousDbFile.isEmpty());
	QVERIFY(dbFile != previousDbFile);
	QVERIFY(!QFileInfo::exists(previousDbFile));
	QVERIFY(!QFileInfo::exists(QFileInfo(previousDbFile).path()));
	QCOMPARE(Store.getAll<pki_key>().size(), 0);
}

void test_service_harness::reopenAsksForPassword()
{
	reopenDatabase();
	QVERIFY(Database.isOpen());
	QCOMPARE(Database.name(), dbFile);
}

void test_service_harness::expectedMessageIsConsumed()
{
	Settings["suppress_messages"] = false;
	warning->expectMessage("Successfully created");
	QVERIFY(Database.model<db_key>()->newKey(keyjob("EC:prime256v1"), "shown"));
}

void test_service_harness::unexpectedPromptIsRecorded()
{
	pass_info p("Harness", "harness probe");
	Passwd pass;

	QCOMPARE(PwDialogCore::execute(&p, &pass), pw_cancel);
	QVERIFY(pass.isEmpty());
	QCOMPARE(XCA_YESNO("harness.question", "harness question"), false);
	XCA_INFO("harness information");

	QStringList v = ServiceViolations::take();
	QCOMPARE(v.size(), 3);
	QVERIFY(v[0].startsWith("unexpected password prompt"));
	QVERIFY(v[0].contains("harness probe"));
	QVERIFY(v[1].startsWith("unexpected question"));
	QVERIFY(v[2].startsWith("unexpected information"));
}

void test_service_harness::selfcheckUnexpectedPrompt()
{
	/* Run by the ctest "test_service_harness_selfcheck", which expects
	 * this test function to FAIL in cleanup() */
	if (!qEnvironmentVariableIsSet("XCA_SERVICE_SELFCHECK"))
		QSKIP("only run by test_service_harness_selfcheck");

	pass_info p("Harness", "selfcheck probe");
	Passwd pass;
	PwDialogCore::execute(&p, &pass);
}

XCA_SERVICE_TEST_MAIN(test_service_harness)
#include "test_service_harness.moc"
