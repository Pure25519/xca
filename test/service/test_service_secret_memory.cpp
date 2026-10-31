/* vi: set sw=4 ts=4:
 *
 * Secrets in memory (BTD-74). A Passwd owns its bytes: a copy never shares
 * the buffer of another Passwd, so cleanse() zeroes the bytes that were
 * really used and not a fresh copy that data() detached first. The
 * helpers secretWipe() and secretCleanse() zero a byte array or a string
 * in place. The headless password sources hand out copies and cleanse
 * their cache when the sources are cleared, and the parsed command line
 * forgets the values of its secret options once they were used.
 */

#include <QByteArray>
#include <QString>

#include "lib/Passwd.h"
#include "lib/PwDialogCore.h"
#include "lib/arguments.h"
#include "lib/pass_info.h"

#include "ServiceTestCase.h"

static const char SECRET[] = "Sekret-BTD-74";

class test_service_secret_memory : public ServiceTestCase
{
	Q_OBJECT

	static bool allZero(const QByteArray &b)
	{
		for (char c : b)
			if (c)
				return false;
		return !b.isEmpty();
	}

  private slots:
	void passwdCopyOwnsItsBytes();
	void passwdFromByteArrayOwnsItsBytes();
	void passwdCleanseKeepsTheCopy();
	void wipeZeroesInPlace();
	void wipeStringZeroesInPlace();
	void cleanseClears();
	void headlessHandsOutCopies();
	void headlessClearSourcesForgets();
	void sourcesReadAsBefore_data();
	void sourcesReadAsBefore();
	void argumentsForgetSecrets();
};

/* Two Passwd never share a buffer: the copy constructor and the
 * assignment copy the bytes */
void test_service_secret_memory::passwdCopyOwnsItsBytes()
{
	Passwd a;
	a = SECRET;
	Passwd b(a);
	Passwd c;
	c = a;
	QCOMPARE(b, a);
	QCOMPARE(c, a);
	QVERIFY(b.constData() != a.constData());
	QVERIFY(c.constData() != a.constData());
}

/* Assigning a plain QByteArray copies its bytes too: the caller cleanses
 * its own array, the Passwd its own */
void test_service_secret_memory::passwdFromByteArrayOwnsItsBytes()
{
	QByteArray plain(SECRET);
	Passwd p;
	p = plain;
	QCOMPARE(QByteArray(p), plain);
	QVERIFY(p.constData() != plain.constData());
	Passwd q(plain);
	QVERIFY(q.constData() != plain.constData());
}

/* cleanse() of one Passwd leaves another one intact and zeroes its own
 * bytes, not a detached copy */
void test_service_secret_memory::passwdCleanseKeepsTheCopy()
{
	Passwd a;
	a = SECRET;
	Passwd b(a);
	b.wipe();
	QVERIFY(allZero(b));
	QCOMPARE(QByteArray(a), QByteArray(SECRET));
	a.cleanse();
	QVERIFY(a.isEmpty());
}

void test_service_secret_memory::wipeZeroesInPlace()
{
	QByteArray b(SECRET);
	const char *data = b.constData();
	secretWipe(b);
	QCOMPARE(b.constData(), data);
	QCOMPARE(b.size(), (int)strlen(SECRET));
	QVERIFY(allZero(b));
}

void test_service_secret_memory::wipeStringZeroesInPlace()
{
	QString s = QString("pass:") + SECRET;
	const QChar *data = s.constData();
	secretWipe(s);
	QCOMPARE(s.constData(), data);
	for (QChar c : s)
		QCOMPARE(c.unicode(), (ushort)0);
}

void test_service_secret_memory::cleanseClears()
{
	QByteArray b(SECRET);
	secretCleanse(b);
	QVERIFY(b.isEmpty());
	QString s(SECRET);
	secretCleanse(s);
	QVERIFY(s.isEmpty());
}

/* Each request gets its own copy of the cached secret */
void test_service_secret_memory::headlessHandsOutCopies()
{
	PwDialogHeadless h;
	h.setSource(pass_info::KeyPassword, QString("pass:") + SECRET);
	Passwd one = h.secret(pass_info::KeyPassword);
	Passwd two = h.secret(pass_info::KeyPassword);
	QCOMPARE(QByteArray(one), QByteArray(SECRET));
	QCOMPARE(two, one);
	QVERIFY(one.constData() != two.constData());
}

/* clearSources() ends the session: the sources are gone and a copy
 * handed out before stays valid */
void test_service_secret_memory::headlessClearSourcesForgets()
{
	PwDialogHeadless h;
	h.setSource(pass_info::KeyPassword, QString("pass:") + SECRET);
	Passwd copy = h.secret(pass_info::KeyPassword);
	h.clearSources();
	QVERIFY(!h.hasSource(pass_info::KeyPassword));
	QCOMPARE(QByteArray(copy), QByteArray(SECRET));
	try {
		h.secret(pass_info::KeyPassword);
		QFAIL("secret() of a cleared source did not throw");
	} catch (secretError &err) {
		QCOMPARE(err.why, secretError::missing);
	}
}

/* No behaviour change: every source still yields the same secret */
void test_service_secret_memory::sourcesReadAsBefore_data()
{
	QTest::addColumn<QString>("source");
	QTest::newRow("pass") << QString("pass:") + SECRET;
	QTest::newRow("env") << QString("env:BTD74_SECRET");
	QTest::newRow("env line end") << QString("env:BTD74_SECRET_NL");
}

void test_service_secret_memory::sourcesReadAsBefore()
{
	QFETCH(QString, source);
	qputenv("BTD74_SECRET", SECRET);
	qputenv("BTD74_SECRET_NL", QByteArray(SECRET) + "\n");
	Passwd p = PwDialogHeadless::readSource(source);
	QCOMPARE(QByteArray(p), QByteArray(SECRET));
	qunsetenv("BTD74_SECRET");
	qunsetenv("BTD74_SECRET_NL");
}

/* The parsed command line keeps --password and --sqlpass only until the
 * sources are set: forgetSecrets() wipes their values, the option stays
 * known and the other options keep theirs */
void test_service_secret_memory::argumentsForgetSecrets()
{
	QByteArray pw = QByteArray("pass:") + SECRET;
	char *argv[] = { (char *)"xca", (char *)"--password", pw.data(),
		(char *)"--sqlpass", (char *)"env:BTD74_SQL",
		(char *)"--verbose=all", nullptr };
	arguments a(6, argv);
	QCOMPARE(a["password"], QString(pw));
	a.forgetSecrets();
	QVERIFY(a.has("password"));
	QVERIFY(a["password"].isEmpty());
	QVERIFY(a.has("sqlpass"));
	QVERIFY(a["sqlpass"].isEmpty());
	QCOMPARE(a["verbose"], QString("all"));
}

XCA_SERVICE_TEST_MAIN(test_service_secret_memory)
#include "test_service_secret_memory.moc"
