/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __DB_CRL_H
#define __DB_CRL_H

#include "db_x509super.h"
#include "pki_crl.h"

class ServiceContext;

class db_crl: public db_x509name
{
		Q_OBJECT
	protected:
		dbheaderList getHeaders();
	public:
		db_crl();
		pki_base *newPKI(enum pki_type type);
		void revokeCerts(pki_crl *crl);
		void inToCont(pki_base *pki);
		pki_base *insert(pki_base *item);
		void removeSigner(pki_base *signer);
		void updateCertView();
		/* Generates and stores a CRL of task.issuer (BTD-33): v2,
		 * signed with task.hashAlgo (never MD5, RIPEMD-160 or SHA-1),
		 * always with CRL number and an authority key identifier
		 * that holds a key identifier (for a CA without subject key
		 * identifier the SHA-1 hash of its public key),
		 * without delta, indirect or partitioned CRL extensions; an
		 * empty CRL has no revokedCertificates field. The entry of
		 * an expired certificate is left out once a stored CRL
		 * issued after its notAfter listed it. Writes exactly one
		 * audit entry crl.generate (CA, CRL number, this and next
		 * update, count, der_size); throws serviceError
		 * (missing_issuer, not_a_ca, no_private_signing_key,
		 * insecure_hash, crl_number_not_increasing,
		 * invalid_crl_number, database_error) or errorEx (audited
		 * as internal_error). The DER size for size budgets is
		 * the result's i2d().size(). Call it outside a transaction. */
		pki_crl *newCrl(const ServiceContext &ctx, const crljob &task,
				QString name = QString());
		void exportItems(const QModelIndexList &indexes,
			const pki_export *xport, XFile &file) const;
};
#endif
