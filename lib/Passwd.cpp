/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2012 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QByteArray>
#include <openssl/crypto.h>
#include "Passwd.h"

void secretWipe(QByteArray &b)
{
	if (!b.isEmpty())
		OPENSSL_cleanse(b.data(), b.size());
}

void secretWipe(QString &s)
{
	if (!s.isEmpty())
		OPENSSL_cleanse(s.data(), s.size() * sizeof(QChar));
}

void secretCleanse(QByteArray &b)
{
	secretWipe(b);
	b.clear();
}

void secretCleanse(QString &s)
{
	secretWipe(s);
	s.clear();
}

void Passwd::wipe()
{
	secretWipe(*this);
}

void Passwd::cleanse()
{
	secretCleanse(*this);
}

Passwd::~Passwd()
{
	Passwd::cleanse();
}
unsigned char *Passwd::constUchar() const
{
	return (unsigned char *)(size() ? constData() : "");
}
