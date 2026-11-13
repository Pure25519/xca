/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2026 BxC Security.
 *
 * All rights reserved.
 */

#ifndef __KEY_CONTEXT_H
#define __KEY_CONTEXT_H

#include <QString>

#include "lib/Passwd.h"

/* The key context of the open database session (BTD-72): the database
 * password that encrypts the private keys and its hash (setting pwhash).
 * database_model owns it from the open to the close and cleanses it then,
 * also when the open fails; lib/ reaches it through session() instead of
 * process-global members, so nothing of a closed database stays behind.
 * One session at a time: lib/ works on one database (Qt's default SQL
 * connection, Store, Settings), and xca-server owns one database on one
 * worker thread (boss decision 2026-11-13). */
class KeyContext
{
	friend class database_model;
	/* the context of the open database_model, nullptr without one */
	static KeyContext *current;

  public:
	Passwd password{};
	QString passHash{};

	KeyContext() = default;
	KeyContext(const KeyContext &) = delete;
	KeyContext &operator=(const KeyContext &) = delete;
	/* A context that ends while it is the session's (also when the
	 * database_model constructor throws after its try block, BTD-296)
	 * leaves no pointer to itself behind */
	~KeyContext()
	{
		cleanse();
		if (current == this)
			current = nullptr;
	}
	void cleanse()
	{
		password.cleanse();
		secretCleanse(passHash);
		passHash.clear();
	}
	/* The context of the open database session, nullptr if no
	 * database is open */
	static KeyContext *session()
	{
		return current;
	}
};

#endif
