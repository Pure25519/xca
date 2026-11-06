/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "lib/func.h"
#include "lib/base.h"
#include "lib/Passwd.h"
#include "lib/exception.h"
#include "XcaWarningCore.h"
#include "PwDialogCore.h"
#include <QFile>
#include <QTextStream>
#include <QThread>
#if !defined(Q_OS_WIN32)
#include <unistd.h>
#endif

PwDialogUI_i *PwDialogCore::pwdialog;
PwDialogHeadless PwDialogCore::headlessUI;
PasswordSourceScope *PwDialogCore::scope;
Passwd PwDialogCore::cmdline_passwd;

PwDialogUI_i *PwDialogCore::ui()
{
	return pwdialog ? pwdialog : &headlessUI;
}

enum open_result PwDialogCore::execute(pass_info *p, Passwd *passwd,
					bool write, bool abort)
{
	p->newAttempt();
	PwDialogUI_i *source = PasswordSourceScope::answering(p->getPurpose());
	if (source)
		return source->execute(p, passwd, write, abort);
	if (!cmdline_passwd.isEmpty()) {
		*passwd = cmdline_passwd;
		cmdline_passwd.cleanse();
		return pw_ok;
	}
	return ui()->execute(p, passwd, write, abort);
}

bool PwDialogCore::hasSource(enum pass_info::purpose p)
{
	if (PasswordSourceScope::answering(p) || !cmdline_passwd.isEmpty())
		return true;
	return ui() == &headlessUI && headlessUI.hasSource(p);
}

PasswordSourceScope::PasswordSourceScope(enum pass_info::purpose p,
					const QString &source)
	: purpose(p), active(!source.isEmpty())
{
	if (!active)
		return;
	headless.setSource(p, source);
	outer = PwDialogCore::scope;
	PwDialogCore::scope = this;
}

PasswordSourceScope::~PasswordSourceScope()
{
	if (active)
		PwDialogCore::scope = outer;
}

PwDialogUI_i *PasswordSourceScope::answering(enum pass_info::purpose p)
{
	for (PasswordSourceScope *s = PwDialogCore::scope; s; s = s->outer) {
		if (s->purpose == p)
			return &s->headless;
	}
	return nullptr;
}

int PwDialogCore::selectToken(const QStringList &names)
{
	return ui()->selectToken(names);
}

int PwDialogCore::selectKeySlot(const QString &label, const QStringList &names)
{
	return ui()->selectKeySlot(label, names);
}

void PwDialogCore::pinPadLogin(pass_info *p, QThread *login)
{
	ui()->pinPadLogin(p, login);
}

int PwDialogCore::pwCallback(char *buf, int size, int rwflag, void *userdata)
{
	Passwd passwd;
	enum open_result result;
	pass_info *p = static_cast<pass_info *>(userdata);

	try {
		result = execute(p, &passwd, rwflag, false);
		if (result == pw_ok && passwd.size() > size)
			throw secretError(secretError::unreadable,
				QObject::tr("The %1 is longer than %2 bytes: %3")
					.arg(p->getType()).arg(size)
					.arg(p->getDescription()));
	} catch (secretError &err) {
		/* Never throw through OpenSSL: the caller throws it
		 * with pass_info::throwError() once OpenSSL returned */
		p->setError(err);
		result = pw_cancel;
	}

	if (result != pw_ok)
		size = 0;
	size = MIN(size, passwd.size());
	memcpy(buf, passwd.constData(), size);
	p->setResult(result);
	return size;
}

void PwDialogCore::setGui(PwDialogUI_i *p)
{
	delete pwdialog;
	pwdialog = p;
}

void PwDialogHeadless::setSource(enum pass_info::purpose purpose,
				const QString &name)
{
	if (name.isEmpty()) {
		sources.remove(purpose);
		return;
	}
	entry s;
	s.name = name;
	sources[purpose] = s;
}

void PwDialogHeadless::clearSources()
{
	sources.clear();
}

Passwd PwDialogHeadless::secret(enum pass_info::purpose purpose)
{
	if (!sources.contains(purpose))
		throw secretError(secretError::missing,
			QObject::tr("No password source given"), purpose);
	entry &s = sources[purpose];
	if (!s.read) {
		try {
			s.secret = readSource(s.name);
		} catch (secretError &err) {
			err.purpose = purpose;
			throw;
		}
		s.read = true;
	}
	return s.secret;
}

bool PwDialogHeadless::isSource(const QString &source)
{
	return source == "stdin" || source.startsWith("pass:") ||
		source.startsWith("env:") || source.startsWith("file:") ||
		source.startsWith("fd:");
}

/* For messages: the source without the secret */
QString PwDialogHeadless::sourceName(const QString &source)
{
	if (source.startsWith("pass:"))
		return QString("pass:***");
	if (!isSource(source))
		return QObject::tr("unknown source");
	return source;
}

/* The first line without its line end. Nothing else is trimmed:
 * spaces are part of the secret */
static void chompLine(Passwd &pass)
{
	while (pass.endsWith('\n') || pass.endsWith('\r'))
		pass.chop(1);
}

static Passwd readFirstLine(QFile &f, const QString &source)
{
	if (!f.isOpen())
		throw secretError(secretError::unreadable,
			QObject::tr("Cannot read the password from %1: %2")
				.arg(source).arg(f.errorString()));
	/* One byte more than allowed, plus the line end, to detect
	 * an over-long secret instead of cutting it silently */
	char buf[PwDialogHeadless::maxLength + 3];
	qint64 len = f.readLine(buf, sizeof buf);
	Passwd pass;
	if (len > 0)
		pass = QByteArray(buf, len);
	memset(buf, 0, sizeof buf);
	chompLine(pass);
	return pass;
}

Passwd PwDialogHeadless::readSource(const QString &source)
{
	Passwd pass;

	if (source.startsWith("pass:")) {
		pass = source.mid(5).toLatin1();
	} else if (source.startsWith("env:")) {
		QString var = source.mid(4);
		const char *value = getenv(var.toLocal8Bit());
		if (var.isEmpty() || !value)
			throw secretError(secretError::unreadable,
				QObject::tr("The environment variable '%1' is not set")
					.arg(var));
		pass = value;
		chompLine(pass);
	} else if (source.startsWith("file:")) {
		QFile f(source.mid(5));
		/* a failed open is reported by readFirstLine() (isOpen) */
		(void)f.open(QIODevice::ReadOnly | QIODevice::Unbuffered);
		pass = readFirstLine(f, source);
	} else if (source.startsWith("fd:") || source == "stdin") {
		bool ok = true;
		int fd = source == "stdin" ? 0 : source.mid(3).toInt(&ok);
		QFile f;
		if (ok)
			(void)f.open(fd, QIODevice::ReadOnly |
					QIODevice::Unbuffered);
		pass = readFirstLine(f, source);
	} else {
		throw secretError(secretError::unreadable,
			QObject::tr("Unknown password source. Use pass:, env:, "
				"file:, fd: or stdin"));
	}
	if (pass.isEmpty())
		throw secretError(secretError::unreadable,
			QObject::tr("The password from %1 is empty")
				.arg(sourceName(source)));
	if (pass.size() > maxLength)
		throw secretError(secretError::unreadable,
			QObject::tr("The password from %1 is longer than %2 bytes")
				.arg(sourceName(source)).arg(maxLength));
	return pass;
}

/* How the secret of a purpose can be given: the option of the program
 * that serves the purpose, or that none does (BTD-196) */
QString PwDialogHeadless::howToGive(enum pass_info::purpose purpose) const
{
	QString option = options.value(purpose);
	if (!option.isEmpty())
		return QObject::tr("Give it with %1 (pass:, env:, file:, fd: "
				"or stdin)").arg(option);
#if defined(Q_OS_WIN32)
	return QObject::tr("No option of this program gives it");
#else
	return interactive ?
		QObject::tr("No option of this program gives it: type it on "
			"a terminal") :
		QObject::tr("No option of this program gives it: type it on "
			"a terminal with --interactive");
#endif
}

/* Why no terminal prompt is possible */
static QString noInput()
{
#if defined(Q_OS_WIN32)
	return QObject::tr("interactive input is not available on Windows");
#else
	return QObject::tr("interactive input is off");
#endif
}

enum open_result PwDialogHeadless::execute(pass_info *p, Passwd *passwd,
					bool write, bool abort)
{
	(void)write;
	(void)abort;
	bool hasSource = sources.contains(p->getPurpose());

	/* A source is used once per request: a second request means
	 * its secret was wrong, and asking again would loop forever */
	if (hasSource && p->getAttempts() <= 1) {
		*passwd = secret(p->getPurpose());
		return pw_ok;
	}
#if !defined(Q_OS_WIN32)
	/* Prompts go to stderr, stdout carries only results (BTD-41) */
	if (interactive) {
		/* Without a terminal readPass() refuses (BTD-145): no
		 * prompt then, and the error names the request and how
		 * its secret can be given (BTD-196) */
		if (!isatty(0))
			throw secretError(secretError::missing,
				QObject::tr("%1 required, but --interactive has "
					"no terminal on standard input: %2. %3")
					.arg(p->getType())
					.arg(p->getDescription())
					.arg(howToGive(p->getPurpose())),
				p->getPurpose());
		console_write(stderr, QString(COL_CYAN "%1\n" COL_LRED "%2:" COL_RESET)
				.arg(p->getDescription())
				.arg(p->getType()).toUtf8());
		try {
			*passwd = readPass();
			/* a new secret (write): not empty, typed twice
			 * (review of xca#62) */
			if (write && passwd->isEmpty())
				throw secretError(secretError::missing,
					QObject::tr("The %1 must not be empty: %2")
					.arg(p->getType())
					.arg(p->getDescription()));
			if (write) {
				console_write(stderr, QString(COL_LRED "%1:"
					COL_RESET).arg(QObject::tr("Repeat %1")
					.arg(p->getType())).toUtf8());
				if (readPass() != *passwd)
					throw secretError(secretError::rejected,
						QObject::tr("The two entries of "
						"the %1 differ").arg(
						p->getType()));
			}
		} catch (secretError &err) {
			err.purpose = p->getPurpose();
			throw;
		}
		return pw_ok;
	}
#endif
	if (p->getAttempts() > 1)
		throw secretError(secretError::rejected,
			QObject::tr("The %1 from %2 was not accepted: %3")
				.arg(p->getType())
				.arg(hasSource ?
					sourceName(sources[p->getPurpose()].name) :
					QObject::tr("the command line"))
				.arg(p->getDescription()), p->getPurpose());
	throw secretError(secretError::missing,
		QObject::tr("%1 required, but no source is given and %2: %3. %4")
			.arg(p->getType()).arg(noInput()).arg(p->getDescription())
			.arg(howToGive(p->getPurpose())),
		p->getPurpose());
}

int PwDialogHeadless::selectToken(const QStringList &names)
{
#if !defined(Q_OS_WIN32)
	if (interactive) {
		QString s = QObject::tr("Several security tokens are present:")
				+ "\n";
		for (int i = 0; i < names.size(); i++)
			s += QString("  %1: %2\n").arg(i + 1).arg(names[i]);
		s += QObject::tr("Select a token (1-%1): ").arg(names.size());
		console_write(stderr, s.toUtf8());
		QTextStream in(stdin);
		bool ok;
		int i = in.readLine().trimmed().toInt(&ok);
		return ok && i >= 1 && i <= names.size() ? i - 1 : -1;
	}
#endif
	throw secretError(secretError::missing,
		QObject::tr("Several security tokens are present and %1: %2")
			.arg(noInput()).arg(names.join(", ")));
}

/* Without a GUI the slot is chosen on the terminal only (BTD-36); the
 * input dialog used before crashed in a command line process */
int PwDialogHeadless::selectKeySlot(const QString &label,
				const QStringList &names)
{
#if !defined(Q_OS_WIN32)
	if (interactive) {
		QString s = QObject::tr("Key slots of %1:").arg(label) + "\n";
		for (int i = 0; i < names.size(); i++)
			s += QString("  %1: %2\n").arg(i + 1).arg(names[i]);
		s += QObject::tr("Select a key slot (1-%1): ").arg(names.size());
		console_write(stderr, s.toUtf8());
		QTextStream in(stdin);
		bool ok;
		int i = in.readLine().trimmed().toInt(&ok);
		return ok && i >= 1 && i <= names.size() ? i - 1 : -1;
	}
#endif
	throw secretError(secretError::missing,
		QObject::tr("The token %1 has fixed key slots and %2: %3")
			.arg(label).arg(noInput()).arg(names.join(", ")));
}

void PwDialogHeadless::pinPadLogin(pass_info *p, QThread *login)
{
	/* Waiting for someone at the reader blocks a service forever:
	 * only with interactive input */
#if !defined(Q_OS_WIN32)
	if (interactive) {
		console_write(stderr, QString(COL_CYAN "%1\n" COL_RESET "%2\n")
				.arg(p->getDescription())
				.arg(QObject::tr("Please enter the PIN on the PinPad"))
				.toUtf8());
		login->start();
		login->wait();
		return;
	}
#endif
	throw secretError(secretError::missing,
		QObject::tr("The token expects the PIN on its PIN pad and %1: %2")
			.arg(noInput()).arg(p->getDescription()));
}
