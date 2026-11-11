/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2011 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __PASSWD_H
#define __PASSWD_H

#include <QByteArray>
#include <QString>

/* Zero the bytes of a secret in place (BTD-74). A buffer shared with
 * another QByteArray or QString is detached first, so only this copy is
 * zeroed: whoever holds the other one must wipe it too */
void secretWipe(QByteArray &b);
void secretWipe(QString &s);
/* secretWipe() and clear() */
void secretCleanse(QByteArray &b);
void secretCleanse(QString &s);

/* A secret that owns its bytes (BTD-74): copies and assignments copy the
 * bytes instead of sharing the buffer, so cleanse() and the destructor
 * zero the bytes this Passwd used and not a copy that data() detached.
 * Whoever converts it to a plain QByteArray owns that copy. */
class Passwd: public QByteArray
{
	void assign(const char *data, qsizetype size);

  public:
	Passwd() = default;
	Passwd(const Passwd &other);
	Passwd(const QByteArray &other);
	Passwd(Passwd &&other) noexcept = default;
	/* zero the bytes, keep the size */
	void wipe();
	void cleanse();
	~Passwd();
	unsigned char *constUchar() const;
	Passwd &operator= (const Passwd &other);
	Passwd &operator= (Passwd &&other) noexcept;
	Passwd &operator= (const QByteArray &other);
	Passwd &operator= (const char *p);
};

/* Wipes a string with a secret, for example a pass: source, when the
 * scope ends */
class SecretGuard
{
	QString &str;

  public:
	explicit SecretGuard(QString &s) : str(s) { }
	~SecretGuard()
	{
		secretCleanse(str);
	}
	SecretGuard(const SecretGuard &) = delete;
	SecretGuard &operator=(const SecretGuard &) = delete;
};
#endif
