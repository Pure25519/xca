/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2018 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "XcaWarningCore.h"
#include "lib/func.h"
#include "lib/audit.h"
#include "lib/json_report.h"
#include <QDebug>
#include <QSqlDatabase>

class xcaWarning_i *xcaWarning::gui;

bool xcaWarning::confirm(ServiceContext &ctx, const QString &id,
			const QString &msg)
{
	if (!gui->yesno(id, msg))
		return false;
	ctx.confirm(id, gui->answerSource(id));
	return true;
}

bool xcaWarning::confirmOkCancel(ServiceContext &ctx, const QString &id,
			const QString &msg)
{
	if (!gui->okcancel(id, msg))
		return false;
	ctx.confirm(id, gui->answerSource(id));
	return true;
}

/* stdout carries only results, with and without --json (BTD-39,
 * BTD-41): information, warnings, questions and errors go to stderr */
bool xcaWarningCore::print_cmdline(const char *color, const QString &msg)
{
	console_write(stderr,
			QString("%1:" COL_RESET " %2\n")
				.arg(color).arg(msg).toUtf8());
	return true;
}

void xcaWarningCore::information(const QString &msg)
{
	print_cmdline(COL_CYAN "Information", msg);
}

void xcaWarningCore::warning(const QString &msg)
{
	print_cmdline(COL_RED "Warning", msg);
}

void xcaWarningCore::notice(const QString &msg)
{
	print_cmdline(COL_YELL "Notice", msg);
}

bool xcaWarningCore::confirmAll = false;
QStringList xcaWarningCore::confirmed{};

void xcaWarningCore::setConfirmations(bool all, const QStringList &ids)
{
	confirmAll = all;
	confirmed = ids;
	confirmed.removeAll(QString());
}

QString xcaWarningCore::answerSource(const QString &id) const
{
	if (confirmed.contains(id))
		return QString("--confirm");
	return confirmAll ? QString("--yes") : QString();
}

bool xcaWarningCore::confirm(const QString &id, const QString &msg)
{
	QString source = answerSource(id);

	if (source.isEmpty())
		throw confirmationError(id, QObject::tr("The question '%1' "
			"was not confirmed: %2\nConfirm it with --confirm %1 "
			"or all questions with --yes").arg(id).arg(msg));
	return print_cmdline(COL_BLUE "Question",
			QString("[%1] %2 yes (%3)").arg(id).arg(msg).arg(source));
}

bool xcaWarningCore::yesno(const QString &id, const QString &msg)
{
	return confirm(id, msg);
}

bool xcaWarningCore::okcancel(const QString &id, const QString &msg)
{
	return confirm(id, msg);
}

void xcaWarningCore::sqlerror(QSqlError err)
{
	warning(err.text());
}

void xcaWarningCore::error(const QString &msg)
{
	/* An error without code: the error object of internal_error */
	if (JsonReport::active())
		JsonReport::write(stderr,
			JsonReport::error("internal_error", msg));
	else
		print_cmdline(COL_RED "Error", msg);
}

void xcaWarningCore::warningv3(const QString &msg, const extList &el)
{
	warning(QString("  " COL_CYAN "%1" COL_RESET "\n%2")
		.arg(msg).arg(el.getConsole(QString("    "))));
}
