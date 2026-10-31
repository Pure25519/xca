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
		 * (missing_issuer, no_private_signing_key, the issuer codes
		 * of IssuanceChecks::crlIssuer(), crl_number_not_increasing,
		 * invalid_crl_number, database_error) or errorEx (audited
		 * as internal_error). The DER size for size budgets is
		 * the result's i2d().size(). Call it outside a transaction. */
		pki_crl *newCrl(const ServiceContext &ctx, const crljob &task,
				QString name = QString());
		/* A stored CRL of a CA of the database whose CRL number
		 * exceeds the CA's last one becomes the CA's last CRL:
		 * authority.crlNo and crlExpire follow it (BTD-49). The
		 * highest CRL number counts, not the latest nextUpdate, so
		 * a lower or equal number changes nothing. Updates the
		 * database only; the caller raises the CA object after the
		 * commit (pki_x509::setCrlNumber, setCrlExpire). Returns
		 * whether it did; throws serviceError (database_error).
		 * Call it inside a transaction. A number above
		 * maxCrlNumber is never adopted; outOfRange tells (BTD-123). */
		bool raiseCrlNumber(pki_crl *crl, bool *outOfRange = nullptr);
		/* The highest CRL number import and newCrl() keep: the audit
		 * parameters are JSON integers within the safe range of RFC
		 * 8785 (BTD-123); authority.crlNo is 64 bit */
		static const qint64 maxCrlNumber = (Q_INT64_C(1) << 53) - 1;
		/* The number as qint64 if it is within 0..maxCrlNumber */
		static bool crlNumberValue(const a1int &num, qint64 *number);
		void writeItems(const QList<pki_base *> &items,
			const pki_export *xport, QIODevice &file,
			const Passwd &pass, const ExportOptions &opts) const;
};
#endif
