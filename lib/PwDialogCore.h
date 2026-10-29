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

/* Everything the core asks the user for: passwords, PINs and the
 * token to use. Implementations: PwDialogUI (the GUI dialogs),
 * PwDialogHeadless (below, sources instead of prompts), test mocks. */
class PwDialogUI_i
{
  public:
	virtual enum open_result execute(pass_info *p, Passwd *passwd,
			bool write = false, bool abort = false) = 0;
	/* Several tokens are present: returns the index of the selected
	 * name or -1 if the selection was cancelled */
	virtual int selectToken(const QStringList &names) = 0;
	/* The token has a fixed set of key slots (label: its model):
	 * returns the index of the selected name or -1 */
	virtual int selectKeySlot(const QString &label,
			const QStringList &names) = 0;
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
	bool hasSource(enum pass_info::purpose purpose) const
	{
		return sources.contains(purpose);
	}
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
	int selectToken(const QStringList &names) override;
	int selectKeySlot(const QString &label,
			const QStringList &names) override;
	void pinPadLogin(pass_info *p, QThread *login) override;
};

class PasswordSourceScope;

class PwDialogCore
{
	friend class PasswordSourceScope;
  private:
	static PwDialogUI_i *pwdialog;
	static PwDialogHeadless headlessUI;
	static PasswordSourceScope *scope;
	static PwDialogUI_i *ui();

  public:
	static Passwd cmdline_passwd;
	static enum open_result execute(pass_info *p, Passwd *passwd,
			bool write = false, bool abort = false);
	/* A request of purpose p is answered from a given password (service
	 * scope, --password without GUI, the GUI's command line password)
	 * instead of a dialog: the caller must ask even if the current
	 * password already fits, or the given one is never checked */
	static bool hasSource(enum pass_info::purpose p);
	static int selectToken(const QStringList &names);
	static int selectKeySlot(const QString &label,
			const QStringList &names);
	static void pinPadLogin(pass_info *p, QThread *login);
	static int pwCallback(char *buf, int size, int rwflag, void *userdata);
	static void setGui(PwDialogUI_i *p);
	/* Used whenever no GUI is set */
	static PwDialogHeadless *headless()
	{
		return &headlessUI;
	}
};

/* The password source of one service call (BTD-34: import and export):
 * while the object lives, every request of its purpose is answered from
 * the source, like PwDialogHeadless does (read once, a second request
 * means the secret was rejected and throws secretError), whatever GUI
 * or headless configuration is set. An empty source changes nothing.
 * Scopes nest; create them on the stack only. */
class PasswordSourceScope
{
	PwDialogHeadless headless{};
	enum pass_info::purpose purpose{};
	bool active{};
	PasswordSourceScope *outer{};

  public:
	PasswordSourceScope(enum pass_info::purpose p, const QString &source);
	~PasswordSourceScope();
	PasswordSourceScope(const PasswordSourceScope &) = delete;
	PasswordSourceScope &operator=(const PasswordSourceScope &) = delete;
	/* The headless UI answering requests of purpose p, or nullptr */
	static PwDialogUI_i *answering(enum pass_info::purpose p);
};
#endif
