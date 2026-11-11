/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "x509name.h"
#include <QMap>
#include "base.h"
#include "func_base.h"
#include "openssl_compat.h"
#include "BioByteArray.h"
#include <openssl/asn1.h>
#include <openssl/err.h>
#include "exception.h"

static const QSharedPointer<X509_NAME> x509init(const X509_NAME *other)
{
	X509_NAME *xname = other ? X509_NAME_dup((X509_NAME *)other)
	                         : X509_NAME_new();
	Q_CHECK_PTR(xname);
	QSharedPointer<X509_NAME> r(xname, X509_NAME_free);
	openssl_error();
	return r;
}

x509name::x509name() : xn(x509init(nullptr))
{
}

x509name::x509name(const X509_NAME *n) : xn(x509init(n))
{
}

x509name::x509name(STACK_OF(X509_NAME_ENTRY) *entries) : xn(x509init(nullptr))
{
	set(entries);
}

x509name::x509name(const x509name &n) : xn(x509init(n.get0()))
{
}

x509name &x509name::set(const X509_NAME *n)
{
	xn = x509init(n);
	return *this;
}

x509name &x509name::set(const STACK_OF(X509_NAME_ENTRY) *entries)
{
	xn = x509init(nullptr);
	if (entries) {
		int count = sk_X509_NAME_ENTRY_num(entries);
		for (int i = 0; i < count; i++) {
			X509_NAME_ENTRY *entry = sk_X509_NAME_ENTRY_value(entries, i);
			X509_NAME_add_entry(xn.data(), entry, -1, 0);
		}
	}
	return *this;
}

QString x509name::oneLine(unsigned long flags) const
{
	BioByteArray bba;
	X509_NAME_print_ex(bba, get0(), 0, flags);
	return bba.qstring();
}

QString x509name::rfc4514() const
{
	BioByteArray bba;
	/* RFC 2253 escaping without ESC_MSB: RFC 4514 allows UTF-8 */
	X509_NAME_print_ex(bba, get0(), 0,
			XN_FLAG_RFC2253 & ~ASN1_STRFLGS_ESC_MSB);
	ign_openssl_error();
	return QString::fromUtf8(bba.byteArray());
}

QString x509name::getEntryByNid(int nid) const
{
	int i = X509_NAME_get_index_by_NID(_get(), nid, -1);
	return i < 0 ? QString() : getEntry(i);
}

QString x509name::getMostPopular() const
{
	static const int nids[] = { NID_commonName, NID_pkcs9_emailAddress,
			NID_organizationalUnitName, NID_organizationName };
	int pos = -1;

	for (unsigned i = 0; i < ARRAY_SIZE(nids) && pos < 0; i++) {
		pos = X509_NAME_get_index_by_NID(xn.data(), nids[i], -1);
	}
	if (pos < 0)
		pos = 0;
	return getEntry(pos);
}

QString x509name::getEntry(int i) const
{
	QString ret;
	const ASN1_STRING *d;

	if ( i<0 || i>entryCount() )
		return ret;

	d = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(get0(), i));

	return asn1ToQString(d);
}

QString x509name::getEntryTag(int i) const
{
	QString s = QObject::tr("Invalid");
	const ASN1_STRING *d;

	if (i<0 || i>=entryCount())
		i = entryCount() - 1;
	d = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(get0(),i));

	if (!d)
		return s;

	s = ASN1_tag2str(ASN1_STRING_type(d));
	return s;
}

QString x509name::popEntryByNid(int nid)
{
	int i = X509_NAME_get_index_by_NID(_get(), nid, -1);
	if (i < 0)
		return QString();
	QString n = getEntry(i);
	X509_NAME_ENTRY *del = X509_NAME_delete_entry(xn.data(), i);
	if (del)
		X509_NAME_ENTRY_free(del);
	return n;
}

QString x509name::hash() const
{
	return QString("%1").arg(X509_NAME_hash(_get()), 8, 16, QChar('0'));
}

/* 32 bit signed integer */
unsigned x509name::hashNum() const
{
	return X509_NAME_hash(_get()) & 0x7fffffffL;
}

QStringList x509name::entryList(int i) const
{
	QStringList sl;
	int n = nid(i);
	if (n == NID_undef) {
		QString oid = getOid(i);
		sl << oid << oid;
	} else {
		sl << OBJ_nid2sn(n) << OBJ_nid2ln(n);
	}
	sl << getEntry(i) << getEntryTag(i);
	return sl;
}

int x509name::nid(int i) const
{
	const X509_NAME_ENTRY *ne = X509_NAME_get_entry(get0(), i);
	return ne ? OBJ_obj2nid(X509_NAME_ENTRY_get_object(ne)) : NID_undef;
}

QString x509name::getOid(int i) const
{
	const X509_NAME_ENTRY *ne = X509_NAME_get_entry(_get(), i);
	return ne ? OBJ_obj2QString(X509_NAME_ENTRY_get_object(ne), 1) : QString();
}

void x509name::d2i(QByteArray &ba)
{
	X509_NAME *n = (X509_NAME*)d2i_bytearray(D2I_VOID(d2i_X509_NAME), ba);
	xn = x509init(n);
	X509_NAME_free(n);
}

QByteArray x509name::i2d() const
{
	 return i2d_bytearray(I2D_VOID(i2d_X509_NAME), get0());
}

bool x509name::operator == (const x509name &x) const
{
	return X509_NAME_cmp(get0(), x.get0()) == 0;
}

bool x509name::operator != (const x509name &x) const
{
	return X509_NAME_cmp(get0(), x.get0()) != 0;
}

x509name &x509name::operator = (const x509name &x)
{
	set(x.get0());
	return *this;
}

int x509name::entryCount() const
{
	return  X509_NAME_entry_count(get0());
}

int x509name::getNidByName(const QString &nid_name)
{
	return OBJ_txt2nid(nid_name.toLatin1());
}

std::pair<int, int> x509name::valueBounds(int nid)
{
	static const QMap<int, std::pair<int, int>> rfc5280 {
		{ NID_countryName, { 2, 2 } },
		{ NID_commonName, { 1, 64 } },
		{ NID_organizationName, { 1, 64 } },
		{ NID_organizationalUnitName, { 1, 64 } },
		{ NID_title, { 1, 64 } },
		{ NID_serialNumber, { 1, 64 } },
		{ NID_localityName, { 1, 128 } },
		{ NID_stateOrProvinceName, { 1, 128 } },
		{ NID_pseudonym, { 1, 128 } },
		{ NID_pkcs9_emailAddress, { 1, 255 } },
	};
	if (rfc5280.contains(nid))
		return rfc5280[nid];
	if (ASN1_STRING_TABLE *tab = ASN1_STRING_TABLE_get(nid))
		return { tab->minsize, tab->maxsize };
	return { -1, -1 };
}

void x509name::checkValue(int nid, const QString &value)
{
	auto [min, max] = valueBounds(nid);
	/* characters, not UTF-8 bytes */
	int len = value.toUcs4().size();
	if ((min < 0 || len >= min) && (max < 0 || len <= max))
		return;
	QString limit = min == max ? QObject::tr("exactly %1").arg(max) :
			max >= 0 && len > max ? QObject::tr("at most %1").arg(max) :
			QObject::tr("at least %1").arg(min);
	throw serviceError("invalid_dn_value", QObject::tr("The %1 '%2' has %3 characters; RFC 5280 allows %4")
		.arg(OBJ_nid2ln(nid)).arg(value).arg(len).arg(limit));
}

void x509name::checkUpperBounds() const
{
	for (int i = 0; i < entryCount(); i++)
		checkValue(nid(i), getEntry(i));
}

bool x509name::search(const QRegularExpression &pattern) const
{
	int i, max = entryCount();
	for (i=0; i<max; i++) {
		if (getEntry(i).contains(pattern))
			return true;
	}
	return false;
}

QString x509name::taggedValues() const
{
	int i, max = entryCount();
	QString ret;

	for (i=0; i<max; i++) {
		int n = nid(i);
		ret += QString("%1.%2=%3\n").
			arg(i).arg(OBJ_nid2sn(n)).arg(getEntry(i));
	}
	return ret;
}

void x509name::addEntryByNid(int nid, const QString &entry)
{
	if (entry.isEmpty())
		return;
	/* the string table's size limits apply only to MBSTRING_* input,
	 * not to the fixed type passed below (BTD-202) */
	checkValue(nid, entry.simplified());
	ASN1_STRING *a = QStringToAsn1(entry.simplified(), nid);
	/* unchecked, a refused entry was left out (BTD-95) */
	int ok = X509_NAME_add_entry_by_NID(_get(), nid,
                               ASN1_STRING_type(a),
                               ASN1_STRING_get0_data(a),
							   (int)ASN1_STRING_get_length(a), -1, 0);
	ASN1_STRING_free(a);
	if (!ok)
		throwInvalidString(entry, nid);
}

X509_NAME *x509name::get() const
{
	return X509_NAME_dup(_get());
}

const X509_NAME *x509name::get0() const
{
	return xn.data();
}

X509_NAME *x509name::_get() const
{
	return xn.data();
}

