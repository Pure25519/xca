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

class Passwd: public QByteArray
{
  public:
	Passwd() = default;
	Passwd(const QByteArray &other) : QByteArray(other) { }
	/* zero the bytes, keep the size */
	void wipe();
	void cleanse();
	~Passwd();
	unsigned char *constUchar() const;
	Passwd & operator= (const char *p)
	{
		return (Passwd&)QByteArray::operator=(p);
	}
	Passwd & operator= (const QByteArray &other)
	{
		return (Passwd&)QByteArray::operator=(other);
	}
};
#endif
