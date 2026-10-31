/* vi: set sw=4 ts=4:
 *
 * Headless secrets (BTD-30): passwords from pass:/env:/file:/fd:
 * sources through PwDialogHeadless, a typed secretError instead of
 * a prompt when no source is given, and no dialog at any time.
 */

#include <QFile>
#include <QSqlQuery>
#include <QTemporaryDir>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#if !defined(Q_OS_WIN32)
#include <fcntl.h>
#include <unistd.h>
#endif

#include "lib/arguments.h"
#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/db_key.h"
#include "lib/pki_evp.h"
#include "lib/pki_scard.h"
#include "lib/settings.h"
#include "lib/xfile.h"
#include "lib/audit.h"
#include "lib/importexport.h"
#include "lib/pki_export.h"

#include "ServiceTestCase.h"

/* Records whether the PIN pad login was started */
class LoginThread : public QThread
{
  public:
	bool ran{};
	void run() override
	{
		ran = true;
	}
};

static const char envVar[] = "XCA_SERVICE_TEST_SECRET";
static const char keySecret[] = "service-test-key-pass";

class test_service_secrets : public ServiceTestCase
{
	Q_OBJECT

	QTemporaryDir secretDir;

	/* A source of the given kind ("env" or "file") that yields secret */
	QString makeSource(const QString &kind, const QByteArray &secret)
	{
		if (kind == "env") {
			qputenv(envVar, secret);
			return QString("env:%1").arg(envVar);
		}
		QString name = secretDir.filePath("secret.txt");
		QFile f(name);
		if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate))
			return QString();
		f.write(secret + "\n");
		return QString("file:%1").arg(name);
	}

	/* Hands the password requests of this test function to a
	 * headless implementation without sources */
	PwDialogHeadless *useHeadless()
	{
		PwDialogHeadless *h = new PwDialogHeadless();
		pwdialog->delegateTo(h);
		return h;
	}

	/* A file with exactly these bytes, as file: source */
	QString rawFile(const QByteArray &content)
	{
		QString name = secretDir.filePath("secret.txt");
		QFile f(name);
		if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate))
			return QString();
		f.write(content);
		return QString("file:%1").arg(name);
	}

	static secretError::reason readError(const QString &source)
	{
		try {
			PwDialogHeadless::readSource(source);
		} catch (secretError &e) {
			return e.why;
		}
		return secretError::reason(-1);
	}

	pki_evp *newKey()
	{
		pki_key *key = Database.model<db_key>()->newKey(
					keyjob("EC:prime256v1"), "secret-key");
		return dynamic_cast<pki_evp *>(key);
	}

	static void checkDecrypts(pki_evp *key)
	{
		EVP_PKEY *pkey = key->decryptKey();
		QVERIFY(pkey);
		EVP_PKEY_free(pkey);
	}

  private slots:
	void cleanup();

	void readSource_data();
	void readSource();
	void readSourceFails_data();
	void readSourceFails();

	void databasePassword_data();
	void databasePassword();
	void databasePasswordMissing();
	void databasePasswordRejected();
	void passwordCheckInAuditContext();
	void keyUpdateNeedsVerifiedOpen();

	void keyPassword_data();
	void keyPassword();
	void keyPasswordMissing();
	void exportPasswordMissing();

	void readSourceLineEnd();
	void readSourceEmptyOrTooLong();
	void sourceReadOnce();
	void pinPadNeedsInteractive();
	void selectTokenNeedsInteractive();
	void keySlotNeedsInteractive();
	void keySlotSelected();
	void importDerPassword();
	void callbackSecretTooLong();

	void loggableMasksSecrets_data();
	void loggableMasksSecrets();
};

void test_service_secrets::cleanup()
{
	qunsetenv(envVar);
	QFile::remove(secretDir.filePath("secret.txt"));
	ServiceTestCase::cleanup();
}

void test_service_secrets::readSource_data()
{
	QTest::addColumn<QString>("kind");

	QTest::newRow("env") << "env";
	QTest::newRow("file") << "file";
}

void test_service_secrets::readSource()
{
	QFETCH(QString, kind);

	QCOMPARE(QByteArray(PwDialogHeadless::readSource("pass:abc")),
		QByteArray("abc"));
	QString source = makeSource(kind, "s3cret");
	QCOMPARE(QByteArray(PwDialogHeadless::readSource(source)),
		QByteArray("s3cret"));
#if !defined(Q_OS_WIN32)
	/* fd: reads the first line from an open descriptor */
	int fd = ::open(CCHAR(makeSource("file", "from-fd").mid(5)), O_RDONLY);
	QVERIFY(fd >= 0);
	QByteArray pass = PwDialogHeadless::readSource(QString("fd:%1").arg(fd));
	::close(fd);
	QCOMPARE(pass, QByteArray("from-fd"));
#endif
}

void test_service_secrets::readSourceFails_data()
{
	QTest::addColumn<QString>("source");

	QTest::newRow("unset env") << QString("env:%1").arg(envVar);
	QTest::newRow("empty env name") << "env:";
	QTest::newRow("missing file") << "file:/nonexistent/xca-secret";
	QTest::newRow("bad fd") << "fd:x";
	QTest::newRow("no prefix") << "my-literal-secret";
}

void test_service_secrets::readSourceFails()
{
	QFETCH(QString, source);

	try {
		PwDialogHeadless::readSource(source);
		QFAIL("readSource() did not throw");
	} catch (secretError &e) {
		QCOMPARE(e.why, secretError::unreadable);
		QVERIFY(!e.getString().contains("my-literal-secret"));
	}
	/* Messages never show a pass: value */
	QCOMPARE(PwDialogHeadless::sourceName("pass:hidden"), QString("pass:***"));
	QVERIFY(!PwDialogHeadless::sourceName(source).contains("my-literal-secret"));
}

void test_service_secrets::databasePassword_data()
{
	readSource_data();
}

void test_service_secrets::databasePassword()
{
	QFETCH(QString, kind);

	Database.close();
	PwDialogHeadless *h = useHeadless();
	h->setSource(pass_info::DatabasePassword, makeSource(kind, dbPassword));
	try {
		Database.open(dbFile);
	} catch (errorEx &err) {
		QFAIL(CCHAR(err.getString()));
	}
	QVERIFY(Database.isOpen());

	/* The database password really unlocks the keys */
	pki_evp *key = newKey();
	QVERIFY(key);
	checkDecrypts(key);
}

void test_service_secrets::databasePasswordMissing()
{
	Database.close();
	useHeadless();
	try {
		Database.open(dbFile);
		QFAIL("Database.open() did not throw");
	} catch (secretError &e) {
		QCOMPARE(e.why, secretError::missing);
		QVERIFY(e.getString().contains("no source"));
	}
	QVERIFY(!Database.isOpen());
}

void test_service_secrets::databasePasswordRejected()
{
	Database.close();
	PwDialogHeadless *h = useHeadless();
	h->setSource(pass_info::DatabasePassword,
				makeSource("env", "wrong-db-password"));
	warning->expectMessage("Password verify error");
	try {
		Database.open(dbFile);
		QFAIL("Database.open() did not throw");
	} catch (secretError &e) {
		QCOMPARE(e.why, secretError::rejected);
		QVERIFY(e.getString().contains(QString("env:%1").arg(envVar)));
		QVERIFY(!e.getString().contains("wrong-db-password"));
	}
	QVERIFY(!Database.isOpen());
}

/* BTD-78: the audit context says whether the database password was
 * checked against pwhash on open */
void test_service_secrets::passwordCheckInAuditContext()
{
	/* The harness opened the database with its password */
	QVERIFY(ServiceContext::processPasswordVerified);
	AuditLog::append(ServiceContext::localUser(ServiceContext::cli),
			"test.checked", "key", "1");
	QCOMPARE(AuditLog::entries().last().params["db_unlock_verified"],
			QVariant(true));

	/* xca --no-gui without a password source opens unchecked */
	Database.close();
	database_model::open_without_password = true;
	Database.open(dbFile);
	QVERIFY(Database.isOpen());
	QVERIFY(!database_model::open_without_password);
	QVERIFY(!ServiceContext::processPasswordVerified);
	AuditLog::append(ServiceContext::localUser(ServiceContext::cli),
			"test.unchecked", "key", "1");
	QCOMPARE(AuditLog::entries().last().params["db_unlock_verified"],
			QVariant(false));

	/* Any other caller has to prove it itself */
	QVERIFY(!ServiceContext(ServiceContext::rest,
			"apikey:test").passwordVerified());
	QVERIFY(AuditLog::verify().ok());
}

/* BTD-246: the key encryption update of an open writes (re-encrypted
 * keys, the marker legacy-keys-updated), so it needs the verified open,
 * not only a password that validates. Before, it ran on any open. */
void test_service_secrets::keyUpdateNeedsVerifiedOpen()
{
	QSqlQuery q(QSqlDatabase::database());
	QVERIFY(q.exec("DELETE FROM settings WHERE key_='legacy-keys-updated'"));
	Settings.clear();
	QVERIFY(pki_evp::validateDatabasePassword(pki_evp::passwd));
	auto marker = []() {
		QSqlQuery c(QSqlDatabase::database());
		c.exec("SELECT COUNT(*) FROM settings "
			"WHERE key_='legacy-keys-updated'");
		return c.next() ? c.value(0).toInt() : -1;
	};

	ServiceContext::processPasswordVerified = false;
	Database.model<db_key>()->updateKeyEncryptionScheme();
	ServiceContext::processPasswordVerified = true;
	QCOMPARE(marker(), 0);

	Database.model<db_key>()->updateKeyEncryptionScheme();
	QCOMPARE(marker(), 1);
}

void test_service_secrets::keyPassword_data()
{
	readSource_data();
}

void test_service_secrets::keyPassword()
{
	QFETCH(QString, kind);

	pki_evp *key = newKey();
	QVERIFY(key);
	PwDialogHeadless *h = useHeadless();
	h->setSource(pass_info::KeyPassword, makeSource(kind, keySecret));

	/* Encrypt with its own password, then decrypt with it */
	key->setOwnPass(pki_key::ptPrivate);
	QCOMPARE(key->getOwnPass(), pki_key::ptPrivate);
	checkDecrypts(key);

	/* Another password from the source does not decrypt it */
	h->setSource(pass_info::KeyPassword, "pass:not-the-key-password");
	EVP_PKEY *pkey = nullptr;
	try {
		pkey = key->decryptKey();
	} catch (errorEx &) {
	}
	QVERIFY(!pkey);
}

void test_service_secrets::keyPasswordMissing()
{
	pki_evp *key = newKey();
	QVERIFY(key);
	PwDialogHeadless *h = useHeadless();

	/* No source: setting an own password fails, the key is unchanged */
	try {
		key->setOwnPass(pki_key::ptPrivate);
		QFAIL("setOwnPass() did not throw");
	} catch (secretError &e) {
		QCOMPARE(e.why, secretError::missing);
	}
	QCOMPARE(key->getOwnPass(), pki_key::ptCommon);
	checkDecrypts(key);

	/* Own password set, source gone: decrypting fails typed */
	h->setSource(pass_info::KeyPassword, "pass:temporary");
	key->setOwnPass(pki_key::ptPrivate);
	h->clearSources();
	try {
		EVP_PKEY_free(key->decryptKey());
		QFAIL("decryptKey() did not throw");
	} catch (secretError &e) {
		QCOMPARE(e.why, secretError::missing);
	}
}

void test_service_secrets::exportPasswordMissing()
{
	/* The export password comes from the headless source of the
	 * purpose ExportPassword (BTD-34: asked by the export service,
	 * no longer in OpenSSL's callback): no source is a typed error */
	pki_evp *key = newKey();
	QVERIFY(key);
	PwDialogHeadless *h = useHeadless();
	QString fname = secretDir.filePath("export.pem");
	ExportSpec spec;
	spec.items << key;
	spec.format = pki_export::by_id(21);	/* PEM encrypted */
	spec.fileName = fname;
	ServiceContext ctx = ServiceContext::localUser(ServiceContext::cli);

	try {
		Database.model<db_key>()->exportItems(ctx, spec);
		QFAIL("exportItems() did not throw");
	} catch (serviceError &e) {
		QCOMPARE(e.code, QString("missing_password"));
	}
	QVERIFY(!QFile::exists(fname));

	h->setSource(pass_info::ExportPassword, makeSource("env", "export-pass"));
	Database.model<db_key>()->exportItems(ctx, spec);
	QFile f(fname);
	QVERIFY(f.open(QIODevice::ReadOnly));
	QByteArray pem = f.readAll();
	QVERIFY(pem.contains("ENCRYPTED"));
	QVERIFY(!pem.contains("export-pass"));
	QFile::remove(fname);
}

void test_service_secrets::readSourceLineEnd()
{
	/* Only the line end goes, spaces belong to the secret */
	QCOMPARE(QByteArray(PwDialogHeadless::readSource(
			rawFile("  sp ace  \r\nsecond line\n"))),
		QByteArray("  sp ace  "));
	qputenv(envVar, "env-secret\n");
	QCOMPARE(QByteArray(PwDialogHeadless::readSource(
			QString("env:%1").arg(envVar))),
		QByteArray("env-secret"));
	QByteArray longest(PwDialogHeadless::maxLength, 'x');
	QCOMPARE(QByteArray(PwDialogHeadless::readSource(rawFile(longest))),
		longest);
}

void test_service_secrets::readSourceEmptyOrTooLong()
{
	QCOMPARE(readError("pass:"), secretError::unreadable);
	qputenv(envVar, "");
	QCOMPARE(readError(QString("env:%1").arg(envVar)),
		secretError::unreadable);
	QCOMPARE(readError(rawFile("")), secretError::unreadable);
	QCOMPARE(readError(rawFile("\nsecond line\n")), secretError::unreadable);
	/* No silent cut: one byte too many is an error */
	QByteArray tooLong(PwDialogHeadless::maxLength + 1, 'x');
	QCOMPARE(readError(rawFile(tooLong + "\n")), secretError::unreadable);
	QCOMPARE(readError(QString("pass:") + tooLong), secretError::unreadable);
}

void test_service_secrets::sourceReadOnce()
{
#if !defined(Q_OS_WIN32)
	/* fd: can be read only once: the secret is kept for later requests */
	PwDialogHeadless h;
	int fd = ::open(CCHAR(rawFile("from-fd\n").mid(5)), O_RDONLY);
	QVERIFY(fd >= 0);
	h.setSource(pass_info::DatabasePassword, QString("fd:%1").arg(fd));
	QCOMPARE(QByteArray(h.secret(pass_info::DatabasePassword)),
		QByteArray("from-fd"));
	QCOMPARE(QByteArray(h.secret(pass_info::DatabasePassword)),
		QByteArray("from-fd"));
	::close(fd);
#endif
}

void test_service_secrets::pinPadNeedsInteractive()
{
	PwDialogHeadless h;
	pass_info p(XCA_TITLE, "PIN pad token");
	p.setPin();
	LoginThread login;
	try {
		h.pinPadLogin(&p, &login);
		QFAIL("pinPadLogin() did not throw");
	} catch (secretError &e) {
		QCOMPARE(e.why, secretError::missing);
	}
	/* Nothing waits for the reader */
	QVERIFY(!login.isRunning());
	QVERIFY(!login.ran);
}

void test_service_secrets::selectTokenNeedsInteractive()
{
	PwDialogHeadless h;
	try {
		h.selectToken(QStringList() << "token A" << "token B");
		QFAIL("selectToken() did not throw");
	} catch (secretError &e) {
		QCOMPARE(e.why, secretError::missing);
	}
}

/* A token with fixed key slots (YubiKey) asks for the slot on key
 * generation. Without a GUI and without interactive input the generation
 * stops with secretError (BTD-36); the QInputDialog used before crashed
 * without a QApplication. */
void test_service_secrets::keySlotNeedsInteractive()
{
	QList<QStringList> ids {
		{ "9a: PIV Authentication", "1" },
		{ "9c: Digital Signature", "2" },
	};
	useHeadless();
	try {
		pki_scard::fixedSlotId("YubiKey NEO", ids);
		QFAIL("fixedSlotId() did not throw");
	} catch (secretError &e) {
		QCOMPARE(e.why, secretError::missing);
		QVERIFY(e.getString().contains("YubiKey NEO"));
	}
}

/* The chosen slot gives the CKA_ID of its entry. No valid choice (an
 * empty, non-numeric or out-of-range answer on the terminal is -1) stops
 * with a typed error naming the token and the range, before select_id()
 * hands an empty CKA_ID to generateKey() or store_token() (BTD-176). */
void test_service_secrets::keySlotSelected()
{
	class Answer : public PwDialogUI_i
	{
	  public:
		int answer{};
		QString label{};
		QStringList names{};
		enum open_result execute(pass_info *, Passwd *, bool, bool)
		{
			return pw_cancel;
		}
		int selectToken(const QStringList &)
		{
			return -1;
		}
		int selectKeySlot(const QString &l, const QStringList &n)
		{
			label = l;
			names = n;
			return answer;
		}
		void pinPadLogin(pass_info *, QThread *) { }
	};
	QList<QStringList> ids {
		{ "9a: PIV Authentication", "1" },
		{ "9c: Digital Signature", "2" },
		{ "9d: Key Management", "3" },
	};
	/* The harness owns it from here */
	Answer *a = new Answer();
	pwdialog->delegateTo(a);

	a->answer = 2;
	pk11_attr_data id = pki_scard::fixedSlotId("YubiKey YK5", ids);
	QCOMPARE(a->label, QString("YubiKey YK5"));
	QCOMPARE(a->names, QStringList() << "9a: PIV Authentication"
			<< "9c: Digital Signature" << "9d: Key Management");
	QVERIFY(id == pk11_attr_data(CKA_ID, 3UL));

	for (int answer : { -1, 3 }) {
		a->answer = answer;
		try {
			id = pki_scard::fixedSlotId("YubiKey YK5", ids);
			const unsigned char *value;
			QFAIL(qPrintable(QString("answer %1: no error, CKA_ID "
				"of %2 bytes").arg(answer)
				.arg(id.getValue(&value))));
		} catch (secretError &e) {
			QCOMPARE(e.why, secretError::rejected);
			QVERIFY2(e.getString().contains("YubiKey YK5") &&
				 e.getString().contains("1-3"),
				 CCHAR(e.getString()));
		}
	}
}

void test_service_secrets::importDerPassword()
{
	/* An encrypted PKCS#8 DER file: the password is asked in the
	 * callback of d2i_PKCS8PrivateKey_bio, not in the PEM loop */
	EVP_PKEY *pkey = EVP_EC_gen("P-256");
	QVERIFY(pkey);
	QString fname = secretDir.filePath("key.der");
	BIO *bio = BIO_new_file(CCHAR(fname), "wb");
	QVERIFY(bio);
	char pw[] = "import-pass";
	QVERIFY(i2d_PKCS8PrivateKey_bio(bio, pkey, EVP_aes_256_cbc(),
					pw, strlen(pw), NULL, NULL) > 0);
	BIO_free(bio);
	EVP_PKEY_free(pkey);

	PwDialogHeadless *h = useHeadless();
	try {
		pki_evp key;
		key.fload(fname);
		QFAIL("fload() did not throw");
	} catch (secretError &e) {
		QCOMPARE(e.why, secretError::missing);
	}

	h->setSource(pass_info::ImportPassword, "pass:import-pass");
	pki_evp key;
	key.fload(fname);
	QVERIFY(key.isPrivKey());
	QFile::remove(fname);
}

void test_service_secrets::callbackSecretTooLong()
{
	/* A secret that does not fit into OpenSSL's buffer is an error,
	 * not cut silently, also from the GUI */
	pki_evp *key = newKey();
	QVERIFY(key);
	QString fname = secretDir.filePath("export.pem");
	{
		XFile file(fname);
		file.open_key();
		key->writeKey(file, EVP_aes_256_cbc(), Passwd() = "short", true);
	}
	/* Reading it asks in OpenSSL's callback (BTD-34: the export
	 * password no longer goes through it) */
	pwdialog->expect(QByteArray(2000, 'a'));
	try {
		pki_evp imported;
		imported.fload(fname);
		QFAIL("fload() did not throw");
	} catch (secretError &e) {
		QCOMPARE(e.why, secretError::unreadable);
	}
	QFile::remove(fname);
}

void test_service_secrets::loggableMasksSecrets_data()
{
	QTest::addColumn<QString>("value");
	QTest::addColumn<QString>("logged");

	/* Values that carry the secret are masked */
	QTest::newRow("pass") << "pass:Leak-1" << "pass:***";
	QTest::newRow("no prefix") << "Leak-2" << "***";
	QTest::newRow("unknown prefix") << "op:Leak-3" << "***";
	QTest::newRow("empty") << "" << "***";
	/* Sources only name where the secret is */
	QTest::newRow("env") << "env:XCA_PW" << "env:XCA_PW";
	QTest::newRow("file") << "file:/run/xca/pw" << "file:/run/xca/pw";
	QTest::newRow("fd") << "fd:3" << "fd:3";
	QTest::newRow("stdin") << "stdin" << "stdin";
}

/* The debug dump of the command line in main() (BTD-68) */
void test_service_secrets::loggableMasksSecrets()
{
	QFETCH(QString, value);
	QFETCH(QString, logged);

	QVERIFY(arguments::secret_opts.contains("password"));
	QVERIFY(arguments::secret_opts.contains("sqlpass"));
	for (const QString &opt : arguments::secret_opts) {
		/* --opt value, --opt=value; a non-secret option stays */
		QList<QByteArray> args { "xca", "--no-gui",
			"--" + opt.toUtf8(), value.toUtf8(),
			"--" + opt.toUtf8() + "=" + value.toUtf8(),
			"--name", "pass:visible-name" };
		QList<char *> argv;
		for (QByteArray &a : args)
			argv << a.data();

		QStringList out = arguments::loggable(argv.size(), argv.data());
		QCOMPARE(out, QStringList({ "xca", "--no-gui", "--" + opt,
			logged, "--" + opt + "=" + logged,
			"--name", "pass:visible-name" }));
		QVERIFY2(!out.join(" ").contains("Leak-"), CCHAR(opt));
	}
}

XCA_SERVICE_TEST_MAIN(test_service_secrets)
#include "test_service_secrets.moc"
