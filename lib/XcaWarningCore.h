/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2018 - 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __XCAWARNINGCORE_H
#define __XCAWARNINGCORE_H

#include "base.h"
#include "exception.h"
#include "x509v3ext.h"
#include <QSqlError>
#include <QSqlDatabase>
#include <QStringList>

class ServiceContext;

#define XCA_INFO(msg) xcaWarning::information(msg)
#define XCA_WARN(msg) xcaWarning::warning(msg)
/* id: stable name of the question, e.g. "key.size"; xca --no-gui
 * answers it with "yes" only if --yes or --confirm <id> was given */
#define XCA_YESNO(id, msg) xcaWarning::yesno(id, msg)
#define XCA_OKCANCEL(id, msg) xcaWarning::okcancel(id, msg)
#define XCA_ERROR(err) xcaWarning::error(err)
#define XCA_SQLERROR(err) xcaWarning::sqlerror(err)
#define XCA_PASSWD_ERROR() XCA_WARN(QObject::tr("Password verify error, please try again"))

class xcaWarning_i
{
  public:
	virtual void information(const QString &msg) = 0;
	virtual void warning(const QString &msg) = 0;
	virtual void warningv3(const QString &msg, const extList &el) = 0;
	virtual bool yesno(const QString &id, const QString &msg) = 0;
	virtual bool okcancel(const QString &id, const QString &msg) = 0;
	virtual void sqlerror(QSqlError err) = 0;
	virtual void error(const QString &msg) = 0;
	/* Who answered question id with "yes", for the audit entry */
	virtual QString answerSource(const QString &id) const
	{
		(void)id;
		return QString("dialog");
	}
	virtual ~xcaWarning_i() { };
};

/* Without a GUI nobody can answer a question (BTD-71): it is "yes" only
 * if the command line confirmed it, all questions with --yes or single
 * ones with --confirm <id,...>; any other question throws
 * confirmationError and the operation stops. */
class xcaWarningCore : public QObject, public xcaWarning_i
{
	Q_OBJECT

	static bool confirmAll;
	static QStringList confirmed;

	bool confirm(const QString &id, const QString &msg);

  protected:
	virtual bool print_cmdline(const char *color, const QString &msg);

  public:
	static void setConfirmations(bool all, const QStringList &ids);

	void information(const QString &msg);
	void warning(const QString &msg);
	bool yesno(const QString &id, const QString &msg);
	bool okcancel(const QString &id, const QString &msg);
	void sqlerror(QSqlError err);
	void warningv3(const QString &msg, const extList &el);
	void error(const QString &msg);
	QString answerSource(const QString &id) const;
};

class xcaWarning
{
	static class xcaWarning_i *gui;

  public:
	xcaWarning() = delete;
	xcaWarning(const xcaWarningCore &) = delete;
	~xcaWarning() = delete;

	static void information(const QString &msg)
	{
		gui->information(msg);
	}
	static void warning(const QString &msg)
	{
		gui->warning(msg);
	}
	static void warningv3(const QString &msg, const extList &el)
	{
		gui->warningv3(msg, el);
	}
	static bool yesno(const QString &id, const QString &msg)
	{
		return gui->yesno(id, msg);
	}
	static bool okcancel(const QString &id, const QString &msg)
	{
		return gui->okcancel(id, msg);
	}
	/* yesno() for a question a service call depends on: a "yes" is
	 * recorded in ctx, so its audit entry names question and source */
	static bool confirm(ServiceContext &ctx, const QString &id,
				const QString &msg);
	/* The same with OK and Cancel, e.g. item.delete */
	static bool confirmOkCancel(ServiceContext &ctx, const QString &id,
				const QString &msg);
	static void sqlerror(QSqlError err)
	{
		if (!err.isValid())
			err = QSqlDatabase::database().lastError();
		if (err.isValid())
			gui->sqlerror(err);
	}
	static void error(const errorEx &err)
	{
		if (err.isEmpty())
			return;
		QString msg = QObject::tr("The following error occurred:") +
			"\n" + err.getString();
		gui->error(msg);
	}
	static void setGui(class xcaWarning_i *g)
	{
		delete gui;
		gui = g;
	}
};
#endif
