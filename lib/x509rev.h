/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __X509REV_H
#define __X509REV_H

#include <QStringList>
#include <QSqlRecord>
#include <QSqlQuery>
#include <QSqlError>
#include <openssl/x509.h>
#include "asn1time.h"
#include "asn1int.h"
#include "pki_base.h"

/* Test hook of the CRL build (BTD-198): the step named in injected is
 * skipped as if its OpenSSL call had failed. Empty in production, set by
 * tests only. Steps: version, issuer, serial, revocation_date,
 * invalidity_date, reason, revoked, aki, ian, crl_number, last_update,
 * next_update; drop_entry leaves a revocation out without a failure. */
namespace crlBuild
{
	extern QString injected;
	bool fail(const char *step);
	/* serviceError("crl_build_failed") naming the step, a detail such
	 * as the serial, and the OpenSSL reason */
	[[noreturn]] void failed(const char *step,
				const QString &detail = QString());
}

class x509rev
{
	private:
		a1int serial{};
		a1time date{}, ivalDate{};
		/* the reasonCode of the entry, noReason without the extension
		 * (BTD-170); an unknown code is kept as its number */
		int reason{ noReason };
		/* the CRL number of the first CRL that listed it (BTD-123:
		 * 64 bit, as authority.crlNo) */
		qint64 crlNo{};
		/* setReason() got a name that is not in crlreasons() */
		bool reasonInvalid{};
		void set(const x509rev &x);

		X509_REVOKED *toREVOKED(bool withReason=true) const;
		void fromREVOKED(const X509_REVOKED *rev);

	public:
		static const int noReason = -1;
		operator QString() const;
		static QStringList crlreasons();
		void d2i(QByteArray &ba);
		QByteArray i2d() const;
		/* the name of crlreasons() for a known code, the number for
		 * an unknown one, empty without a reason */
		QString getReason() const;
		/* the reasonCode, noReason without the extension */
		int getReasonCode() const
		{
			return reason;
		}
		bool hasReason() const
		{
			return reason != noReason;
		}
		/* the stored value (revocations.reasonBit, audit reason_bit):
		 * 0 without a reason, the code otherwise; -1 if setReason()
		 * got an unknown name */
		int getReasonBit() const;
		/* as a revocation of the CA: an explicit unspecified (0) is
		 * "no reason", which RFC 5280 5.3.1 asks for (BTD-170) */
		x509rev adopted() const;
		bool identical(const x509rev &x) const;

		x509rev()
		{
			date.setUndefined();
		}
		x509rev(X509_REVOKED *n)
		{
			fromREVOKED(n);
		}
		x509rev(const x509rev &n)
		{
			set(n);
		}
		x509rev(QSqlRecord rec, int offset = 0);
		void executeQuery(XSqlQuery &q);
		bool isValid() const
		{
			return serial != a1int(0L) && !date.isUndefined();
		}
		x509rev &set(const X509_REVOKED *r)
		{
			fromREVOKED(r);
			return *this;
		}
		bool operator == (const x509rev &x) const
		{
			return serial == x.serial;
		}
		x509rev &operator = (const x509rev &x)
		{
			set(x);
			return *this;
		}
		void setSerial(const a1int &i)
		{
			serial = i;
		}
		void setDate(const a1time &t)
		{
			date = t;
		}
		void setInvalDate(const a1time &t)
		{
			ivalDate = t;
		}
		/* "Unspecified" of the dialog and the command line is no
		 * reason: XCA writes no extension for it */
		void setReason(const QString &name);
		void setCrlNo(qint64 n)
		{
			crlNo = n;
		}
		a1int getSerial() const
		{
			return serial;
		}
		a1time getDate() const
		{
			return date;
		}
		a1time getInvalDate() const
		{
			return ivalDate;
		}
		qint64 getCrlNo() const
		{
			return crlNo;
		}
		X509_REVOKED *get(bool withReason=true) const
		{
			return toREVOKED(withReason);
		}
};

class x509revList : public QList<x509rev>
{
	public:
		static x509revList fromSql(QVariant caId);
		bool merged;
		void merge(const x509revList &other);
		bool identical(const x509revList &other) const;
		x509revList() : QList<x509rev>()
		{
			merged = false;
		}
		x509revList(const x509revList &r) : QList<x509rev>(r)
		{
			merged = r.merged;
		}
		x509revList(const x509rev &r) : QList<x509rev>()
		{
			if (r.isValid()) {
				merged = false;
				append(r);
			}
		}
		x509revList &operator = (const x509revList &r)
		{
			QList<x509rev>::operator=(r);
			merged = r.merged;
			return *this;
		}
		/* Replaces the revocations of caId; a failed write throws
		 * (throwSqlError(), BTD-50) */
		void sqlUpdate(QVariant caId);
};
#endif
