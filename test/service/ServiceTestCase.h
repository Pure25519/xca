/* vi: set sw=4 ts=4:
 *
 * Test harness for service-layer functions (label "service").
 * How to add tests: test/service/README.md
 */

#ifndef __SERVICETESTCASE_H
#define __SERVICETESTCASE_H

#include <QCoreApplication>
#include <QList>
#include <QObject>
#include <QPair>
#include <QStringList>
#include <QTemporaryDir>
#include <QTest>

#include "lib/PwDialogCore.h"
#include "lib/XcaWarningCore.h"
#include "test/TestEnv.h"

class Entropy;

/* Collects every prompt or message that no test asked for.
 * ServiceTestCase::cleanup() fails the test if the list is not empty. */
class ServiceViolations
{
	static QStringList list;

  public:
	static void add(const QString &msg);
	static QStringList take();
};

/* Password and PIN source: answers only the prompts a test expects,
 * in order. Any other prompt is a violation and is aborted.
 * delegateTo() hands all requests of the current test function to
 * another implementation, e.g. PwDialogHeadless; reset() ends that. */
class StrictPwDialog : public PwDialogUI_i
{
	QList<QPair<Passwd, enum open_result> > expected{};
	PwDialogUI_i *delegate{};

  public:
	~StrictPwDialog();
	void expect(const QByteArray &pass, enum open_result result = pw_ok);
	void delegateTo(PwDialogUI_i *d);
	void reset();
	enum open_result execute(pass_info *p, Passwd *passwd,
				bool write = false, bool abort = false) override;
	int selectToken(const QStringList &names) override;
	int selectKeySlot(const QString &label,
			const QStringList &names) override;
	void pinPadLogin(pass_info *p, QThread *login) override;
};

/* Replaces the message boxes of xcaWarning: questions are answered from
 * the expected answers, messages must match an expected substring.
 * delegateTo() hands the questions of the current test function to
 * another implementation, e.g. the headless xcaWarningCore; reset()
 * ends that and clears the confirmations of xcaWarningCore. */
class StrictWarning : public xcaWarning_i
{
	QList<bool> answers{};
	QStringList messages{};
	xcaWarning_i *delegate{};

	void message(const char *kind, const QString &msg);
	bool question(const char *kind, const QString &id,
			const QString &msg);

  public:
	~StrictWarning();
	void expectQuestion(bool answer);
	void expectMessage(const QString &substring);
	void delegateTo(xcaWarning_i *d);
	void reset();

	void information(const QString &msg) override;
	void warning(const QString &msg) override;
	void warningv3(const QString &msg, const extList &el) override;
	bool yesno(const QString &id, const QString &msg) override;
	bool okcancel(const QString &id, const QString &msg) override;
	void sqlerror(QSqlError err) override;
	void error(const QString &msg) override;
	QString answerSource(const QString &id) const override;
};

/* Base class of every service test: a fresh XCA database in its own
 * temporary directory per test function, opened with dbPassword. */
class ServiceTestCase : public QObject
{
	Q_OBJECT

	Entropy *entropy{};
	QTemporaryDir *dbDir{};

  protected:
	static const char dbPassword[];
	StrictPwDialog *pwdialog{};
	StrictWarning *warning{};
	QString dbFile{};

	void openDatabase();
	void reopenDatabase();

  protected slots:
	void initTestCase();
	void cleanupTestCase();
	void init();
	void cleanup();
};

#define XCA_SERVICE_TEST_MAIN(TestClass) \
int main(int argc, char *argv[]) \
{ \
	TestEnv env; \
	QCoreApplication app(argc, argv); \
	TestClass tc; \
	QTEST_SET_MAIN_SOURCE_PATH \
	return QTest::qExec(&tc, argc, argv); \
}

#endif
