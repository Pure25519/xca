/* vi: set sw=4 ts=4:
 *
 * Test harness for service-layer functions (label "service").
 * How to add tests: test/service/README.md
 */

#include <QDir>
#include <QFileInfo>
#include <QSqlError>
#include <QSqlQuery>
#include <QThread>

#include <openssl/provider.h>
#include <openssl/ui.h>

#include "lib/database_model.h"
#include "lib/entropy.h"
#include "lib/exception.h"
#include "lib/func.h"
#include "lib/oid.h"
#include "lib/pki_export.h"
#include "lib/settings.h"

#include "ServiceTestCase.h"

/* Referenced by lib/pkcs11.h, normally defined in lib/main.cpp */
char segv_data[1024];

const char ServiceTestCase::dbPassword[] = "service-test-db-pass";

QStringList ServiceViolations::list;

void ServiceViolations::add(const QString &msg)
{
	qWarning() << "VIOLATION:" << msg;
	list << msg;
}

QStringList ServiceViolations::take()
{
	QStringList l = list;
	list.clear();
	return l;
}

void StrictPwDialog::expect(const QByteArray &pass, enum open_result result)
{
	Passwd p;
	p = pass;
	expected << qMakePair(p, result);
}

StrictPwDialog::~StrictPwDialog()
{
	delete delegate;
}

void StrictPwDialog::delegateTo(PwDialogUI_i *d)
{
	delete delegate;
	delegate = d;
}

void StrictPwDialog::reset()
{
	if (!expected.isEmpty())
		ServiceViolations::add(QString("%1 expected password prompt(s) "
				"not shown").arg(expected.size()));
	expected.clear();
	delegateTo(nullptr);
}

enum open_result StrictPwDialog::execute(pass_info *p, Passwd *passwd,
					bool write, bool abort)
{
	if (delegate)
		return delegate->execute(p, passwd, write, abort);
	if (expected.isEmpty()) {
		ServiceViolations::add(QString("unexpected password prompt "
				"(%1): %2 / %3").arg(write ? "write" : "read")
				.arg(p->getTitle()).arg(p->getDescription()));
		return pw_cancel;
	}
	QPair<Passwd, enum open_result> e = expected.takeFirst();
	*passwd = e.first;
	return e.second;
}

int StrictPwDialog::selectToken(const QStringList &names, QWidget *w)
{
	if (delegate)
		return delegate->selectToken(names, w);
	ServiceViolations::add(QString("unexpected token selection: %1")
				.arg(names.join(", ")));
	return -1;
}

void StrictPwDialog::pinPadLogin(pass_info *p, QThread *login)
{
	if (delegate) {
		delegate->pinPadLogin(p, login);
		return;
	}
	ServiceViolations::add(QString("unexpected PIN pad login: %1")
				.arg(p->getDescription()));
	login->start();
	login->wait();
}

StrictWarning::~StrictWarning()
{
	delete delegate;
}

void StrictWarning::delegateTo(xcaWarning_i *d)
{
	delete delegate;
	delegate = d;
}

void StrictWarning::expectQuestion(bool answer)
{
	answers << answer;
}

void StrictWarning::expectMessage(const QString &substring)
{
	messages << substring;
}

void StrictWarning::reset()
{
	if (!answers.isEmpty())
		ServiceViolations::add(QString("%1 expected question(s) not "
				"asked").arg(answers.size()));
	for (const QString &m : messages)
		ServiceViolations::add(QString("expected message not shown: %1")
				.arg(m));
	answers.clear();
	messages.clear();
	delegateTo(nullptr);
	xcaWarningCore::setConfirmations(false, QStringList());
}

void StrictWarning::message(const char *kind, const QString &msg)
{
	for (int i = 0; i < messages.size(); i++) {
		if (msg.contains(messages[i])) {
			messages.removeAt(i);
			return;
		}
	}
	ServiceViolations::add(QString("unexpected %1: %2").arg(kind).arg(msg));
}

bool StrictWarning::question(const char *kind, const QString &id,
			const QString &msg)
{
	if (delegate)
		return QString(kind) == "yesno" ? delegate->yesno(id, msg) :
				delegate->okcancel(id, msg);
	if (answers.isEmpty()) {
		ServiceViolations::add(QString("unexpected question (%1 %2): %3")
				.arg(kind).arg(id).arg(msg));
		return false;
	}
	return answers.takeFirst();
}

void StrictWarning::information(const QString &msg)
{
	message("information", msg);
}

void StrictWarning::warning(const QString &msg)
{
	message("warning", msg);
}

void StrictWarning::warningv3(const QString &msg, const extList &)
{
	message("warning", msg);
}

bool StrictWarning::yesno(const QString &id, const QString &msg)
{
	return question("yesno", id, msg);
}

bool StrictWarning::okcancel(const QString &id, const QString &msg)
{
	return question("okcancel", id, msg);
}

QString StrictWarning::answerSource(const QString &id) const
{
	return delegate ? delegate->answerSource(id) : QString("dialog");
}

void StrictWarning::sqlerror(QSqlError err)
{
	message("sqlerror", err.text());
}

void StrictWarning::error(const QString &msg)
{
	message("error", msg);
}

/* OpenSSL's own UI (terminal prompt) must never be reached either */
static int ui_writer(UI *, UI_STRING *uis)
{
	ServiceViolations::add(QString("unexpected OpenSSL UI prompt: %1")
				.arg(UI_get0_output_string(uis)));
	return 0;
}

void ServiceTestCase::initTestCase()
{
	static UI_METHOD *uimeth = nullptr;

	OSSL_PROVIDER_try_load(0, "legacy", 1);
	if (!uimeth) {
		uimeth = UI_create_method("xca-service-test");
		UI_method_set_writer(uimeth, ui_writer);
		UI_set_default_method(uimeth);
	}
	QCoreApplication::setApplicationName("de.hohnstaedt.xca");
	QCoreApplication::setOrganizationDomain("hohnstaedt.de");

	pwdialog = new StrictPwDialog();
	PwDialogCore::setGui(pwdialog);
	warning = new StrictWarning();
	xcaWarning::setGui(warning);

	entropy = new Entropy;
	Settings.clear();
	try {
		initOIDs();
	} catch (errorEx &err) {
		QFAIL(CCHAR(err.getString()));
	}
	QStringList v = ServiceViolations::take();
	QVERIFY2(v.isEmpty(), CCHAR(v.join("; ")));
}

void ServiceTestCase::cleanupTestCase()
{
	Database.close();
	PwDialogCore::setGui(nullptr);
	pwdialog = nullptr;
	xcaWarning::setGui(new xcaWarningCore());
	warning = nullptr;
	delete entropy;
	entropy = nullptr;
	pki_export::free_elements();
}

void ServiceTestCase::openDatabase()
{
	/* A new database asks once for the password that encrypts the
	 * private keys, an existing one asks once to unlock them. */
	pwdialog->expect(dbPassword);
	try {
		Database.open(dbFile);
	} catch (errorEx &err) {
		QFAIL(CCHAR(err.getString()));
	} catch (enum open_result r) {
		QFAIL(CCHAR(QString("Database.open aborted: %1").arg(r)));
	}
	QVERIFY(Database.isOpen());
	/* A throwaway database needs no fsync per transaction: durability
	 * after a power loss is not under test, and the waits made the 1000
	 * issuances of test_service_issuance::serials() take 20 s instead
	 * of 6 s (BTD-82). Transactions, rollback and the audited path stay
	 * the same. */
	QSqlQuery q("PRAGMA synchronous = OFF");
	QVERIFY2(!q.lastError().isValid(), CCHAR(q.lastError().text()));
	/* Success notifications ("Successfully created ...") are GUI feedback,
	 * not part of a service result: off, like the option in the GUI */
	Settings["suppress_messages"] = true;
}

void ServiceTestCase::reopenDatabase()
{
	Database.close();
	openDatabase();
}

void ServiceTestCase::init()
{
	pwdialog->reset();
	warning->reset();
	ServiceViolations::take();

	dbDir = new QTemporaryDir(QDir::tempPath() + "/xca-service-XXXXXX");
	QVERIFY(dbDir->isValid());
	dbFile = dbDir->filePath("service.xdb");
	openDatabase();
}

void ServiceTestCase::cleanup()
{
	QString dir = dbDir ? dbDir->path() : QString();

	Database.close();
	delete dbDir;
	dbDir = nullptr;
	dbFile.clear();
	pwdialog->reset();
	warning->reset();

	QStringList v = ServiceViolations::take();
	QVERIFY2(dir.isEmpty() || !QFileInfo::exists(dir),
		CCHAR(QString("temporary database directory left: %1").arg(dir)));
	QVERIFY2(v.isEmpty(), CCHAR(v.join("; ")));
}
