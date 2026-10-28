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

PwDialogUI_i *PwDialogCore::pwdialog;
PwDialogHeadless PwDialogCore::headlessUI;
Passwd PwDialogCore::cmdline_passwd;

PwDialogUI_i *PwDialogCore::ui()
{
	return pwdialog ? pwdialog : &headlessUI;
}

enum open_result PwDialogCore::execute(pass_info *p, Passwd *passwd,
					bool write, bool abort)
{
	p->newAttempt();
	if (!cmdline_passwd.isEmpty()) {
		*passwd = cmdline_passwd;
		cmdline_passwd.cleanse();
		return pw_ok;
	}
	return ui()->execute(p, passwd, write, abort);
}

int PwDialogCore::selectToken(const QStringList &names, QWidget *w)
{
	return ui()->selectToken(names, w);
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
	} catch (secretError &err) {
		/* Never throw through OpenSSL: the caller throws it
		 * with pass_info::throwError() once OpenSSL returned */
		p->setError(err);
		result = pw_cancel;
	}

	size = MIN(size, passwd.size());
	memcpy(buf, passwd.constData(), size);
	p->setResult(result);
	return result == pw_ok ? size : 0;
}

void PwDialogCore::setGui(PwDialogUI_i *p)
{
	delete pwdialog;
	pwdialog = p;
}

void PwDialogHeadless::setSource(enum pass_info::purpose purpose,
				const QString &source)
{
	if (source.isEmpty())
		sources.remove(purpose);
	else
		sources[purpose] = source;
}

void PwDialogHeadless::clearSources()
{
	sources.clear();
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

static Passwd readFirstLine(QFile &f, const QString &source)
{
	if (!f.isOpen())
		throw secretError(secretError::unreadable,
			QObject::tr("Cannot read the password from %1: %2")
				.arg(source).arg(f.errorString()));
	Passwd pass;
	pass = f.readLine(128).trimmed();
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
	} else if (source.startsWith("file:")) {
		QFile f(source.mid(5));
		f.open(QIODevice::ReadOnly);
		pass = readFirstLine(f, source);
	} else if (source.startsWith("fd:") || source == "stdin") {
		bool ok = true;
		int fd = source == "stdin" ? 0 : source.mid(3).toInt(&ok);
		QFile f;
		if (ok)
			f.open(fd, QIODevice::ReadOnly);
		pass = readFirstLine(f, source);
	} else {
		throw secretError(secretError::unreadable,
			QObject::tr("Unknown password source. Use pass:, env:, "
				"file:, fd: or stdin"));
	}
	return pass;
}

enum open_result PwDialogHeadless::execute(pass_info *p, Passwd *passwd,
					bool write, bool abort)
{
	(void)write;
	(void)abort;
	QString source = sources.value(p->getPurpose());

	/* A source is used once per request: a second request means
	 * its secret was wrong, and asking again would loop forever */
	if (!source.isEmpty() && p->getAttempts() <= 1) {
		*passwd = readSource(source);
		return pw_ok;
	}
#if !defined(Q_OS_WIN32)
	if (interactive) {
		console_write(stdout, QString(COL_CYAN "%1\n" COL_LRED "%2:" COL_RESET)
				.arg(p->getDescription())
				.arg(p->getType()).toUtf8());
		*passwd = readPass();
		return pw_ok;
	}
#endif
	if (p->getAttempts() > 1)
		throw secretError(secretError::rejected,
			QObject::tr("The %1 from %2 was not accepted: %3")
				.arg(p->getType())
				.arg(source.isEmpty() ? QObject::tr("the command line")
					: sourceName(source))
				.arg(p->getDescription()));
	throw secretError(secretError::missing,
		QObject::tr("%1 required, but no source is given and "
			"interactive input is off: %2")
			.arg(p->getType()).arg(p->getDescription()));
}

int PwDialogHeadless::selectToken(const QStringList &names, QWidget *w)
{
	(void)w;
#if !defined(Q_OS_WIN32)
	if (interactive) {
		QString s = QObject::tr("Several security tokens are present:")
				+ "\n";
		for (int i = 0; i < names.size(); i++)
			s += QString("  %1: %2\n").arg(i + 1).arg(names[i]);
		s += QObject::tr("Select a token (1-%1): ").arg(names.size());
		console_write(stdout, s.toUtf8());
		QTextStream in(stdin);
		bool ok;
		int i = in.readLine().trimmed().toInt(&ok);
		return ok && i >= 1 && i <= names.size() ? i - 1 : -1;
	}
#endif
	throw secretError(secretError::missing,
		QObject::tr("Several security tokens are present and interactive "
			"input is off: %1").arg(names.join(", ")));
}

void PwDialogHeadless::pinPadLogin(pass_info *p, QThread *login)
{
	console_write(stdout, QString(COL_CYAN "%1\n" COL_RESET "%2\n")
			.arg(p->getDescription())
			.arg(QObject::tr("Please enter the PIN on the PinPad"))
			.toUtf8());
	login->start();
	login->wait();
}
