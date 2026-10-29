/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2012 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __PKI_EXCEPTION_H
#define __PKI_EXCEPTION_H

#include <QString>
#include <QObject>
#include <QSqlError>

#include "base.h"

enum open_result {
	pw_cancel,
	pw_ok,
	pw_exit,
	open_abort
};

class errorEx
{
	protected:
		QString msg{};

	public:
		errorEx(QString txt = "", QString className = "")
		{
			msg = txt;
			if (!className.isEmpty())
				msg += " (" + className + ")";
		}
		errorEx(const QSqlError &e)
		{
			msg = e.text();
		}
		/* Polymorphic, so that a caught errorEx can be asked for its
		 * code (JsonReport::error(), BTD-39) */
		virtual ~errorEx() = default;
		void appendString(QString s)
		{
			msg = msg + " " + s;
		}
		QString getString() const
		{
			return msg;
		}
		const char *getCString() const
		{
			return msg.toLatin1();
		}
		bool isEmpty() const
		{
			return msg.isEmpty();
		}
};

/* A password or PIN that the headless secret source could not provide.
 * The message names the request and the source, never the secret. */
class secretError: public errorEx
{
	public:
		enum reason {
			missing,	/* no source and no interactive input */
			unreadable,	/* the source exists but yields nothing */
			rejected	/* the secret from the source was wrong */
		};
		enum reason why;

		secretError(enum reason r = missing, QString txt = "")
			: errorEx(txt), why(r)
		{
		}
};

/* A question (XCA_YESNO, XCA_OKCANCEL) that nobody answered "yes"
 * without a GUI (BTD-71): the operation stops instead of going on.
 * question is the stable id of the question, e.g. "key.size". */
class confirmationError: public errorEx
{
	public:
		QString question;

		confirmationError(const QString &id, const QString &txt)
			: errorEx(txt), question(id)
		{
		}
};

/* A rejected service call (BTD-31, pattern for BTD-32..35).
 * code is the stable snake_case reason that also goes into the
 * error_code of the audit entry, e.g. "no_private_signing_key";
 * the message is for humans. */
class serviceError: public errorEx
{
	public:
		QString code;

		serviceError(const QString &c, const QString &txt)
			: errorEx(txt), code(c)
		{
		}
};
#endif
