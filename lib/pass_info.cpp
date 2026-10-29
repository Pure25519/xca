/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "pass_info.h"
#include "func_base.h"

pass_info::pass_info(const QString &t, const QString &d)
	: title(t), description(d),
	type(tr("Password")), pixmap(QString(":keyImg")), result(pw_ok)
{
}

void pass_info::setPin(bool so)
{
	type = tr("PIN");
	pixmap = QString(":scardImg");
	purpose = so ? TokenSoPin : TokenPin;
}

void pass_info::throwError() const
{
	if (error.isEmpty())
		return;
	/* The OpenSSL call that ran the callback failed because of it */
	ign_openssl_error();
	throw error;
}
