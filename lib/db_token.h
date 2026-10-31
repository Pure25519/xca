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
		 * (BTD-35): the matching keys in the database first, the
		 * label on the token last, so a failure leaves both as they
		 * were; parameter on_token, object_id the CKA_ID of a key or
		 * the SHA-256 fingerprint of a certificate (BTD-128). The
		 * token login may ask for the PIN (PwDialogCore). */
		void rename(const ServiceContext &ctx, pki_base *pki,
				const QString &name) override;
		void setSlot(const slotid &s)
		{
			slot = s;
		}
		/* Deletes an object on a token only, the database stays
		 * (Delete from token, the import dialog): one object.delete
		 * with on_token and object_id the CKA_ID or the fingerprint;
		 * nothing deleted (declined, not found) is the failure
		 * nothing_deleted, a token error token_error (BTD-248).
		 * slot: the slot to use, or the object finds its token. */
		static void deleteOnToken(const ServiceContext &ctx,
				pki_base *pki, const slotid *slot = nullptr);
		void saveHeaderState();
		void rename_token_in_database(pki_scard *token);
		/* Tests only (BTD-128): replaces pki_base::renameOnToken() in
		 * rename(); false or an exception is a failure on the token */
		static std::function<bool(pki_base *, const QString &)>
			tokenRenameHook;
};

#endif
