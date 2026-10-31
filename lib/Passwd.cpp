/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2012 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QByteArray>
#include <cstring>
#include <utility>
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

Passwd::Passwd(const Passwd &other) : QByteArray()
{
	assign(other.constData(), other.size());
}

Passwd::Passwd(const QByteArray &other) : QByteArray()
{
	assign(other.constData(), other.size());
}

/* The bytes are copied into a buffer of its own: append() to an empty
 * array allocates, it never shares */
void Passwd::assign(const char *data, qsizetype size)
{
	cleanse();
	if (data && size > 0)
		append(data, size);
}

Passwd &Passwd::operator= (const Passwd &other)
{
	if (this != &other)
		assign(other.constData(), other.size());
	return *this;
}

Passwd &Passwd::operator= (Passwd &&other) noexcept
{
	if (this != &other) {
		cleanse();
		QByteArray::operator=(std::move(other));
	}
	return *this;
}

Passwd &Passwd::operator= (const QByteArray &other)
{
	if (other.constData() != constData())
		assign(other.constData(), other.size());
	return *this;
}

Passwd &Passwd::operator= (const char *p)
{
	if (p != constData())
		assign(p, p ? (qsizetype)strlen(p) : 0);
	return *this;
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
