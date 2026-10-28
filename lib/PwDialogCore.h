/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2011 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __PWDIALOGCORE_H
#define __PWDIALOGCORE_H

#include <QByteArray>
#include <QMap>
#include <QStringList>
#include "Passwd.h"
#include "pass_info.h"

class QThread;
class QWidget;

/* Everything the core asks the user for: passwords, PINs and the
 * token to use. Implementations: PwDialogUI (widgets/, dialogs),
 * PwDialogHeadless (below, sources instead of prompts), test mocks. */
class PwDialogUI_i
{
  public:
	virtual enum open_result execute(pass_info *p, Passwd *passwd,
			bool write = false, bool abort = false) = 0;
	/* Several tokens are present: returns the index of the selected
	 * name or -1 if the selection was cancelled */
	virtual int selectToken(const QStringList &names, QWidget *w) = 0;
	/* The PIN is entered on the PIN pad of the reader: starts the
	 * login thread and returns when it has finished */
	virtual void pinPadLogin(pass_info *p, QThread *login) = 0;
	virtual ~PwDialogUI_i() { };
};

/* Headless implementation: answers from the sources configured per
 * purpose (pass:, env:, file:, fd:, stdin) and never opens a dialog.
 * A missing or rejected secret throws secretError, unless interactive
 * input on the terminal was enabled explicitly (not on Windows).
 * Each source is read once, on first use; fd: and stdin can only be
 * read once anyway. */
class PwDialogHeadless: public PwDialogUI_i
{
	class entry
	{
	  public:
		QString name{};
		Passwd secret{};
		bool read{};
	};
	QMap<enum pass_info::purpose, entry> sources{};
	bool interactive{};

  public:
	/* Longest secret accepted: OpenSSL's password callbacks get
	 * a buffer of PEM_BUFSIZE (1024) bytes */
	static const int maxLength = 1024;

	void setSource(enum pass_info::purpose purpose, const QString &source);
	void clearSources();
	/* The secret of the source for purpose; throws secretError if
	 * there is none or it cannot be read */
	Passwd secret(enum pass_info::purpose purpose);
	void setInteractive(bool i)
	{
		interactive = i;
	}
	bool isInteractive() const
	{
		return interactive;
	}
	static bool isSource(const QString &source);
	static Passwd readSource(const QString &source);
	static QString sourceName(const QString &source);

	enum open_result execute(pass_info *p, Passwd *passwd,
			bool write = false, bool abort = false) override;
	int selectToken(const QStringList &names, QWidget *w) override;
	void pinPadLogin(pass_info *p, QThread *login) override;
};

class PwDialogCore
{
  private:
	static PwDialogUI_i *pwdialog;
	static PwDialogHeadless headlessUI;
	static PwDialogUI_i *ui();

  public:
	static Passwd cmdline_passwd;
	static enum open_result execute(pass_info *p, Passwd *passwd,
			bool write = false, bool abort = false);
	static int selectToken(const QStringList &names, QWidget *w);
	static void pinPadLogin(pass_info *p, QThread *login);
	static int pwCallback(char *buf, int size, int rwflag, void *userdata);
	static void setGui(PwDialogUI_i *p);
	/* Used whenever no GUI is set */
	static PwDialogHeadless *headless()
	{
		return &headlessUI;
	}
};
#endif
