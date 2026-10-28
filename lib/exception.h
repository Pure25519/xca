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
#endif
