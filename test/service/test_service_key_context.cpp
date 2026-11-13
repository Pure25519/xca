/* vi: set sw=4 ts=4:
 *
 * The key context of a database session (BTD-72). The database password
 * and its hash belong to the open database, not to the process: closing
 * the database leaves nothing of them behind, and a second database
 * opened afterwards in the same process works only with its own
 * password. One session at a time (boss decision 2026-11-13: xca-server
 * owns one database on one worker thread). lib/ declares no static
 * password or password hash.
 */

#include <QDirIterator>
#include <QFile>
#include <QRegularExpression>
#include <QSqlDatabase>
#include <QTemporaryDir>

#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/db_key.h"
#include "lib/Passwd.h"
#include "lib/pki_evp.h"
#include "lib/test_seams.h"

#include "ServiceTestCase.h"

class test_service_key_context : public ServiceTestCase
{
	Q_OBJECT

	ServiceContext ctx{ ServiceContext::cli, "os:service-test" };
	QTemporaryDir dir{};

	void open(const QString &file, const QByteArray &pass)
	{
		Database.close();
		pwdialog->expect(pass);
		try {
			Database.open(file);
		} catch (errorEx &err) {
			QFAIL(CCHAR(err.getString()));
		} catch (enum open_result r) {
			QFAIL(CCHAR(QString("Database.open aborted: %1").arg(r)));
		}
		QVERIFY(Database.isOpen());
		Settings["suppress_messages"] = true;
	}
	bool decrypts(const QString &name)
	{
		for (pki_evp *key : Store.getAll<pki_evp>()) {
			if (key->getIntName() != name)
				continue;
			EVP_PKEY *pkey = key->decryptKey();
			bool ok = pkey != nullptr;
			EVP_PKEY_free(pkey);
			return ok;
		}
		return false;
	}

  private slots:
	void closeForgetsPassword();
	void secondDatabaseOwnPassword();
	void failedOpenLeavesNoContext();
	void failedOpenLeavesNoState();
	void noStaticPasswordInLib();
	void frontEndSecretsStayInFrontEnds();
};

/* After the close, the password of the closed database is not valid any
 * more: neither the password nor its hash survive the session */
void test_service_key_context::closeForgetsPassword()
{
	QVERIFY(pki_evp::validateDatabasePassword(Passwd(dbPassword)));
	Database.close();
	QVERIFY2(!pki_evp::validateDatabasePassword(Passwd(dbPassword)),
		"the closed database's password still validates");
	QVERIFY2(!pki_evp::validateDatabasePassword(Passwd()),
		"an empty password validates without a database");
	openDatabase();
}

/* Database A, closed, then database B with another password in the same
 * process: B validates only its own password and decrypts its own key;
 * A opened again decrypts its key with A's password */
void test_service_key_context::secondDatabaseOwnPassword()
{
	const QByteArray passA("key-context-A"), passB("key-context-B");
	QString fileA = dir.filePath("a.xdb"), fileB = dir.filePath("b.xdb");

	open(fileA, passA);
	QVERIFY(Database.model<db_key>()->newKey(ctx,
		keyjob("EC:prime256v1"), "key-a"));
	QVERIFY(decrypts("key-a"));
	Database.close();

	open(fileB, passB);
	QVERIFY(pki_evp::validateDatabasePassword(Passwd(passB)));
	QVERIFY2(!pki_evp::validateDatabasePassword(Passwd(passA)),
		"database B accepts the password of database A");
	QVERIFY(Database.model<db_key>()->newKey(ctx,
		keyjob("EC:prime256v1"), "key-b"));
	QVERIFY(decrypts("key-b"));
	Database.close();

	open(fileA, passA);
	QVERIFY(pki_evp::validateDatabasePassword(Passwd(passA)));
	QVERIFY(!pki_evp::validateDatabasePassword(Passwd(passB)));
	QVERIFY(decrypts("key-a"));
	Database.close();
	QVERIFY(!pki_evp::validateDatabasePassword(Passwd(passA)));
	openDatabase();
}

/* An open that fails after the unlock, outside the constructor's try
 * block (BTD-296): the constructor ends without the destructor, the member
 * keys is destroyed, and KeyContext::session() must not point at it any
 * more. Before the fix it did, and the next session() was a use-after-free
 * (AddressSanitizer: heap-use-after-free in validateDatabasePassword). */
void test_service_key_context::failedOpenLeavesNoContext()
{
	const QByteArray pass("key-context-failed");
	Database.close();
	QVERIFY(!KeyContext::session());
	TestSeams::failNextOpenAfterUnlock();
	pwdialog->expect(pass);
	bool thrown = false;
	try {
		Database.open(dir.filePath("failed.xdb"));
	} catch (errorEx &) {
		thrown = true;
	}
	QVERIFY(thrown);
	QVERIFY(!Database.isOpen());
	QVERIFY2(!KeyContext::session(),
		"KeyContext::session() points at the destroyed context");
	QVERIFY(!pki_evp::validateDatabasePassword(Passwd(pass)));
	/* the constructor left its connection open (BTD-296 side finding):
	 * close it, so the harness can open its database again */
	QString conn = QSqlDatabase::database().connectionName();
	QSqlDatabase::database().close();
	QSqlDatabase::removeDatabase(conn);
	Settings.clear();
	openDatabase();
}

/* An open that fails at the end of the constructor, after the models are
 * created and have loaded the objects (BTD-299): nothing of it stays. The
 * connection is closed and removed, the models and their objects are gone,
 * the settings are cleared, there is no session context, and the next
 * open works without any manual cleanup. Before the fix only the try
 * block around the unlock cleaned up: the connection stayed open and the
 * models and their objects stayed allocated (LeakSanitizer). */
void test_service_key_context::failedOpenLeavesNoState()
{
	const QByteArray pass("key-context-late");
	QString file = dir.filePath("late.xdb");
	open(file, pass);
	QVERIFY(Database.model<db_key>()->newKey(ctx,
		keyjob("EC:prime256v1"), "key-late"));
	Database.close();

	TestSeams::failNextOpenAfterModels();
	pwdialog->expect(pass);
	bool thrown = false;
	try {
		Database.open(file);
	} catch (errorEx &) {
		thrown = true;
	}
	QVERIFY(thrown);
	QVERIFY(!Database.isOpen());
	QVERIFY(!KeyContext::session());
	QVERIFY2(QSqlDatabase::connectionNames().isEmpty(), CCHAR(
		"connections left: " + QSqlDatabase::connectionNames().join(", ")));
	QVERIFY2(Store.getAll<pki_base>().isEmpty(),
		"objects of the failed open are still in the store");
	openDatabase();
}

/* No static Passwd data member and no static password hash in lib/: the
 * database password lives in the key context of the session (AC 1 of
 * BTD-72, instead of a grep in the review). Functions returning a Passwd
 * are no storage. One named exception: PwDialogCore::cmdline_passwd, the
 * one-shot answer of the CLI and GUI front ends to the next prompt
 * (--password, a drop), consumed and cleansed by that prompt and never set
 * by a service caller; listed for the static-state review of BTD-154. */
void test_service_key_context::noStaticPasswordInLib()
{
	QRegularExpression re("^\\s*(?:static\\s+(?:const\\s+)?Passwd\\s+"
		"(\\w+)\\s*[;={]|"
		"static\\s+QString\\s+(passHash|pwhash)\\s*[;={]|"
		"(?:Passwd|QString)\\s+\\w+::(\\w+)\\s*[;={])");
	const QStringList allowed{ "cmdline_passwd" };
	QStringList found;
	QDirIterator it(QString(XCA_SOURCE_DIR "/lib"),
		{ "*.h", "*.cpp" }, QDir::Files);
	while (it.hasNext()) {
		QString path = it.next();
		QFile f(path);
		QVERIFY(f.open(QIODevice::ReadOnly));
		int line = 0;
		while (!f.atEnd()) {
			line++;
			QString text = QString::fromUtf8(f.readLine());
			QRegularExpressionMatch m = re.match(text);
			if (!m.hasMatch())
				continue;
			QString name = m.captured(1) + m.captured(2) +
				m.captured(3);
			/* a QString definition is only storage of a hash */
			if (!m.captured(3).isEmpty() &&
			    text.trimmed().startsWith("QString") &&
			    name != "passHash" && name != "pwhash")
				continue;
			if (!allowed.contains(name))
				found << QString("%1:%2: %3").arg(path).arg(line)
					.arg(text.trimmed());
		}
	}
	QVERIFY2(found.isEmpty(), CCHAR(found.join("\n")));
}

/* The two process-global secret holders the static check allows are input
 * of the CLI and GUI front ends only (boss decision 2026-11-13):
 * PwDialogCore::cmdline_passwd and the headless secret sources behind
 * PwDialogCore::headless(). A service caller such as xca-server takes its
 * secrets per request through PasswordSourceScope. A source check instead
 * of a runtime assert, because no server code path exists yet to assert
 * on, and it catches any new file outside the front ends whatever the
 * server's directory will be called. */
void test_service_key_context::frontEndSecretsStayInFrontEnds()
{
	const QStringList allowedPrefixes{ "lib/PwDialogCore.", "lib/cmdline.cpp",
		"lib/test_takey.cpp", "widgets/", "cli/", "test/" };
	QRegularExpression re("\\bcmdline_passwd\\b|"
		"\\bPwDialogCore::headless\\s*\\(");
	QString root = QString(XCA_SOURCE_DIR "/");
	QStringList found;
	QDirIterator it(root, { "*.h", "*.cpp" }, QDir::Files,
		QDirIterator::Subdirectories);
	while (it.hasNext()) {
		QString path = it.next();
		QString rel = path.mid(root.size());
		if (rel.startsWith(".git/"))
			continue;
		bool allowed = false;
		for (const QString &prefix : allowedPrefixes)
			allowed = allowed || rel.startsWith(prefix);
		if (allowed)
			continue;
		QFile f(path);
		QVERIFY(f.open(QIODevice::ReadOnly));
		if (re.match(QString::fromUtf8(f.readAll())).hasMatch())
			found << rel;
	}
	QVERIFY2(found.isEmpty(), CCHAR("front-end secret holder used "
		"outside the CLI and GUI front ends: " + found.join(", ")));
}

XCA_SERVICE_TEST_MAIN(test_service_key_context)
#include "test_service_key_context.moc"
