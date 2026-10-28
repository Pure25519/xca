/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __PASS_INFO_H
#define __PASS_INFO_H

#include <QString>
#include <QObject>
#include <QApplication>

#include "lib/exception.h"

class QWidget;

class pass_info: public QObject
{
	Q_OBJECT

  public:
	/* What the secret is for: the headless source is chosen by it */
	enum purpose {
		Other,
		DatabasePassword,	/* unlock or create the database */
		KeyPassword,		/* a key with its own password */
		ImportPassword,		/* decrypt a file being imported */
		ExportPassword,		/* encrypt a file being exported */
		SqlPassword,		/* the remote SQL server */
		TokenPin,
		TokenSoPin
	};

  private:
	QString title{};
	QString description{};
	QWidget *widget{};
	QString type{};
	QString pixmap{};
	enum open_result result{};
	enum purpose purpose{ Other };
	int attempts{};
	secretError error{};

  public:
	pass_info(const QString &t, const QString &d, QWidget *w = nullptr);
	QString getTitle() const
	{
		return title;
	}
	QString getDescription() const
	{
		return description;
	}
	QWidget *getWidget()
	{
		if (!widget)
			widget = qApp->activeWindow();
		return widget;
	}
	QString getType() const
	{
		return type;
	}
	QString getImage() const
	{
		return pixmap;
	}
	enum open_result getResult() const
	{
		return result;
	}
	enum purpose getPurpose() const
	{
		return purpose;
	}
	/* How often this request has been answered, the current one included */
	int getAttempts() const
	{
		return attempts;
	}
	void setTitle(QString t)
	{
		title = t;
	}
	void setDescription(QString d)
	{
		description = d;
	}
	void setWidget(QWidget *w)
	{
		widget = w;
	}
	void setResult(enum open_result r)
	{
		result = r;
	}
	void setPurpose(enum purpose p)
	{
		purpose = p;
	}
	void newAttempt()
	{
		attempts++;
	}
	/* An error raised inside an OpenSSL password callback is kept here
	 * and thrown by throwError() once OpenSSL has returned */
	void setError(const secretError &e)
	{
		error = e;
	}
	void throwError() const;
	void setPin(bool so = false);
};

#endif
