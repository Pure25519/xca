/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __DB_KEY_H
#define __DB_KEY_H

#include "pki_export.h"
#include "db_base.h"
#include "pki_key.h"
#include "xfile.h"

class QModelIndex;
class QContextMenuEvent;
class AuditParams;
class ServiceContext;

class db_key: public db_base
{
	Q_OBJECT

		pki_key *generate(const keyjob &task, const QString &name,
				AuditParams &params, const ServiceContext &ctx);
	protected:
		virtual dbheaderList getHeaders();
	public:
		db_key();
		QList<pki_key*> getUnusedKeys();
		QList<pki_key*> getAllKeys();
		pki_base *newPKI(enum pki_type type = none);
		void inToCont(pki_base *pki);
		void remFromCont(const QModelIndex &idx);
		pki_base* insert(pki_base *item);
		void setOwnPass(QModelIndex idx, enum pki_key::passType);
		void loadContainer();
		/* Generates one key pair (BTD-32). Throws serviceError for a
		 * rejected job and errorEx for anything else; writes exactly
		 * one audit entry key.generate either way (error code
		 * internal_error for anything but a serviceError). No question
		 * or message; call it outside a transaction. */
		pki_key *newKey(const ServiceContext &ctx, const keyjob &task,
				const QString &name);
		/* GUI and command line: asks before an unusual RSA/DSA size,
		 * reports success or the error, returns NULL on failure */
		pki_key *newKey(const keyjob &task, const QString &name);
		/* Audit parameters key_type, key_size, curve of a key */
		static void keyParams(AuditParams &params, pki_key *key);
		int exportFlags(const QModelIndex &index) const;
		void exportItem(const QModelIndex &index,
			const pki_export *xport, XFile &file) const;
		void updateKeyEncryptionScheme();

	signals:
		void delKey(pki_key *delkey);
		void newKey(pki_key *newkey);
		void keyDone(pki_key *nkey);
};

#endif
