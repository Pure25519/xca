/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __DB_TOKEN_H
#define __DB_TOKEN_H

#include "pkcs11_lib.h"
#include "db_base.h"

class pki_scard;
class db_token: public db_base
{
		Q_OBJECT
	private:
		slotid slot{};

	public:
		db_token();
		/* object.rename of an object on the token of the slot
		 * (BTD-35): the label on the token, then the name of the
		 * matching keys in the database; parameter on_token. The
		 * token login may ask for the PIN (PwDialogCore). */
		void rename(const ServiceContext &ctx, pki_base *pki,
				const QString &name) override;
		void setSlot(const slotid &s)
		{
			slot = s;
		}
		void saveHeaderState();
		void rename_token_in_database(pki_scard *token);
};

#endif
