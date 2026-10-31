/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2012 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "x509rev.h"
#include "pki_base.h"
#include "func.h"
#include "exception.h"
#include <openssl/x509v3.h>
#include <QStringList>
#include <QVariant>
#include <QSqlQuery>

#define CRL_REASON_UNSPECIFIED                  0
#define CRL_REASON_KEY_COMPROMISE               1
#define CRL_REASON_CA_COMPROMISE                2
#define CRL_REASON_AFFILIATION_CHANGED          3
#define CRL_REASON_SUPERSEDED                   4
#define CRL_REASON_CESSATION_OF_OPERATION       5
#define CRL_REASON_CERTIFICATE_HOLD             6
#define CRL_REASON_REMOVE_FROM_CRL              8
#define CRL_REASON_PRIVILEGE_WITHDRAWN          9
#define CRL_REASON_AA_COMPROMISE                10

static ENUMERATED_NAMES crl_reasons[] = {
{CRL_REASON_UNSPECIFIED,         "Unspecified", "unspecified"},
{CRL_REASON_KEY_COMPROMISE,      "Key Compromise", "keyCompromise"},
{CRL_REASON_CA_COMPROMISE,       "CA Compromise", "CACompromise"},
{CRL_REASON_AFFILIATION_CHANGED, "Affiliation Changed", "affiliationChanged"},
{CRL_REASON_SUPERSEDED,          "Superseded", "superseded"},
{CRL_REASON_CESSATION_OF_OPERATION,
                        "Cessation Of Operation", "cessationOfOperation"},
{CRL_REASON_CERTIFICATE_HOLD,    "Certificate Hold", "certificateHold"},
{CRL_REASON_REMOVE_FROM_CRL,     "Remove From CRL", "removeFromCRL"},
{CRL_REASON_PRIVILEGE_WITHDRAWN, "Privilege Withdrawn", "privilegeWithdrawn"},
{CRL_REASON_AA_COMPROMISE,       "AA Compromise", "AACompromise"},
{-1, NULL, NULL}
};

QStringList x509rev::crlreasons()
{
	QStringList l;
	for (int i=0; crl_reasons[i].lname; i++)
		l << crl_reasons[i].lname;
	return l;
}

QString x509rev::getReason() const
{
	if (reason == noReason)
		return QString();
	for (int i=0; crl_reasons[i].lname; i++) {
		if (reason == crl_reasons[i].bitnum)
			return crl_reasons[i].lname;
	}
	return QString::number(reason);
}

int x509rev::getReasonBit() const
{
	if (reasonInvalid)
		return -1;
	return reason == noReason ? 0 : reason;
}

void x509rev::setReason(const QString &name)
{
	int i = crlreasons().indexOf(name);
	reasonInvalid = i < 0;
	reason = i <= 0 ? noReason : crl_reasons[i].bitnum;
}

x509rev x509rev::adopted() const
{
	x509rev r(*this);
	if (r.reason == CRL_REASON_UNSPECIFIED)
		r.reason = noReason;
	return r;
}

void x509rev::fromREVOKED(const X509_REVOKED *rev)
{
	ASN1_ENUMERATED *reason;
	ASN1_TIME *at;
	int j = -1, r;

	if (!rev)
		return;
	serial = a1int(X509_REVOKED_get0_serialNumber(rev));
	date = a1time(X509_REVOKED_get0_revocationDate(rev));

	reason = (ASN1_ENUMERATED *)X509_REVOKED_get_ext_d2i(
			(X509_REVOKED *)rev, NID_crl_reason, &j, NULL);
	openssl_error();
	/* absent, an explicit unspecified and an unknown code are kept
	 * apart (BTD-170) */
	this->reason = noReason;
	reasonInvalid = false;
	if (reason) {
		r = ASN1_ENUMERATED_get(reason);
		openssl_error();
		this->reason = r;
		ASN1_ENUMERATED_free(reason);
	}
	ivalDate.setUndefined();
	at = (ASN1_TIME *)X509_REVOKED_get_ext_d2i((X509_REVOKED *)rev,
			NID_invalidity_date, &j, NULL);
	openssl_error();
	if (at) {
		ivalDate = a1time(at);
		ASN1_GENERALIZEDTIME_free(at);
	}
	qDebug() << *this;
}

QString crlBuild::injected;

bool crlBuild::fail(const char *step)
{
	return !injected.isEmpty() && injected == step;
}

void crlBuild::failed(const char *step, const QString &detail)
{
	QString reason = take_openssl_errors();
	throw serviceError("crl_build_failed", QString("%1\n%2").arg(
		QObject::tr("The revocation list cannot be built: %1 %2")
			.arg(step, detail).trimmed(), reason));
}

/* Every step checked: unchecked, a CRL could be signed without the
 * serial, the date, the reason or the invalidity date (BTD-198) */
X509_REVOKED *x509rev::toREVOKED(bool withReason) const
{
	X509_REVOKED *rev = X509_REVOKED_new();
	Q_CHECK_PTR(rev);
	QString sn = serial.toHex();
	auto fail = [&](const char *step) {
		X509_REVOKED_free(rev);
		crlBuild::failed(step, sn);
	};
	ASN1_INTEGER *s = serial.get();
	bool ok = !crlBuild::fail("serial") &&
		X509_REVOKED_set_serialNumber(rev, s);
	ASN1_INTEGER_free(s);
	if (!ok)
		fail("serial");
	if (crlBuild::fail("revocation_date") ||
	    !X509_REVOKED_set_revocationDate(rev, (ASN1_TIME*)date.get_utc()))
		fail("revocation_date");
	/* RFC 5280 5.3.2: only add the extension if the date is known */
	if (!ivalDate.isUndefined() && (crlBuild::fail("invalidity_date") ||
	    X509_REVOKED_add1_ext_i2d(rev, NID_invalidity_date,
				(ASN1_TIME*)ivalDate.get(), 0, 0) != 1))
		fail("invalidity_date");

	/* no extension without a reason (RFC 5280 5.3.1); an explicit or
	 * unknown code read from a CRL is written as it was (BTD-170) */
	if (reason != noReason && withReason) {
		ASN1_ENUMERATED *a = ASN1_ENUMERATED_new();
		ok = !crlBuild::fail("reason") && a &&
			ASN1_ENUMERATED_set(a, reason) &&
			X509_REVOKED_add1_ext_i2d(rev, NID_crl_reason, a,
						0, 0) == 1;
		ASN1_ENUMERATED_free(a);
		if (!ok)
			fail("reason");
	}
	ign_openssl_error();
	qDebug() << *this;
	return rev;
}

void x509rev::d2i(QByteArray &ba)
{
	X509_REVOKED *r;
	r = (X509_REVOKED *)d2i_bytearray(D2I_VOID(d2i_X509_REVOKED), ba);
	if (!r)
		return;
	fromREVOKED(r);
	X509_REVOKED_free(r);
}

QByteArray x509rev::i2d() const
{
	QByteArray ba;
	X509_REVOKED *r = toREVOKED();
	ba = i2d_bytearray(I2D_VOID(i2d_X509_REVOKED), r);
	X509_REVOKED_free(r);
	return ba;
}

void x509rev::set(const x509rev &x)
{
	serial = x.serial;
	date = x.date;
	ivalDate = x.ivalDate;
	reason = x.reason;
	reasonInvalid = x.reasonInvalid;
	crlNo = x.crlNo;
}

bool x509rev::identical(const x509rev &x) const
{
	return	serial == x.serial &&
		date == x.date &&
		ivalDate == x.ivalDate &&
		reason == x.reason;
}

x509rev::operator QString() const
{
	return QString("Rev: %1 D:%2 I:%3 Reason: %4 '%5'\n")
		.arg(serial.toHex(), date.toSortable(), ivalDate.toSortable())
		.arg(reason).arg(getReason());
}

x509rev::x509rev(QSqlRecord rec, int offset)
{
	serial.setHex(rec.value(offset).toString());
	date.fromPlain(rec.value(offset +1).toString());
	ivalDate.fromPlain(rec.value(offset +2).toString());
	crlNo = rec.value(offset +3).toInt();
	/* a stored 0 (or NULL) is no reason: XCA never stores an explicit
	 * unspecified (adopted()), and rows older than BTD-170 used 0 for
	 * it; an unknown code is kept */
	int bit = rec.value(offset +4).toInt();
	reason = bit == 0 ? noReason : bit;
	qDebug() << *this;
}

void x509rev::executeQuery(XSqlQuery &q)
{
	// 0 is the caId
	q.bindValue(1, serial.toHex());
	q.bindValue(2, date.toPlain());
	q.bindValue(3, ivalDate.toPlain());
	q.bindValue(4, crlNo ? QVariant(crlNo) : QVariant());
	q.bindValue(5, getReasonBit());
	q.exec();
}

void x509revList::merge(const x509revList &other)
{
	foreach(x509rev r, other) {
		if (r.isValid() && !contains(r)) {
			merged = true;
			append(r);
		}
	}
}

bool x509revList::identical(const x509revList &other) const
{
	if (size() != other.size())
		return false;
	for (int i=0; i<size(); i++) {
		x509rev r = at(i);
		int c = other.indexOf(r);
		if (c == -1)
			return false;
		if (!r.identical(other.at(c)))
			return false;
	}
	return true;
}

x509revList x509revList::fromSql(QVariant caId)
{
	XSqlQuery q;
	x509revList list;

	SQL_PREPARE(q, "SELECT serial, date, invaldate, crlNo, reasonBit "
			"FROM revocations WHERE caId=?");
	q.bindValue(0, caId);
	q.exec();
	if (q.lastError().isValid())
		return list;
	while (q.next()) {
		x509rev r(q.record());
		list.append(r);
	}
	list.merged = false;
	return list;
}

void x509revList::sqlUpdate(QVariant caId)
{
	XSqlQuery q;
	Transaction;
	TransThrow();

	x509revList oldList = fromSql(caId);

	SQL_PREPARE(q, "DELETE FROM revocations WHERE caId=?");
	q.bindValue(0, caId);
	execOrThrow(q, QObject::tr("The revocations could not be stored"));

	SQL_PREPARE(q, "INSERT INTO revocations "
			"(caId, serial, date, invaldate, crlNo, reasonBit) "
			"VALUES (?,?,?,?,?,?)");
	q.bindValue(0, caId);
	foreach(x509rev r, *this) {
		if (r.getCrlNo() == 0) {
			int idx = oldList.indexOf(r);
			if (idx != -1) {
				x509rev old = oldList.takeAt(idx);
				r.setCrlNo(old.getCrlNo());
				qDebug() << "RECOVER OLD CRL NO" << r ;
			}
		}
		r.executeQuery(q);
		if (q.lastError().isValid())
			throwSqlError(q.lastError(), QObject::tr("The revocation "
				"of %1 could not be stored")
				.arg(r.getSerial().toHex()));
	}

	TransCommitThrow();
	merged = false;
}
