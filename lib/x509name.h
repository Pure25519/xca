/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __X509NAME_H
#define __X509NAME_H

#include <QString>
#include <QStringList>
#include <QSharedPointer>
#include <QRegularExpression>
#include <openssl/x509.h>

class x509name
{
	private:
		QSharedPointer<X509_NAME> xn{};
		X509_NAME *_get() const;
	public:
		x509name();
		x509name(const X509_NAME *n);
		x509name(const x509name &n);
		x509name(STACK_OF(X509_NAME_ENTRY) *entries);
		x509name &set(const X509_NAME *n);
		x509name &set(const STACK_OF(X509_NAME_ENTRY) *entries);
		QString oneLine(unsigned long flags = XN_FLAG_ONELINE) const;
		int nid(int i) const;
		QString getOid(int i) const;
		QByteArray i2d() const;
		void d2i(QByteArray &ba);
		QStringList entryList(int i) const;
		QString getEntryByNid(int nid) const;
		QString getEntry(int i) const;
		QString getEntryTag(int i) const;
		int entryCount() const;
		x509name &operator = (const x509name &x);
		bool operator == (const x509name &x) const;
		bool operator != (const x509name &x) const;
		static int getNidByName(const QString &nid_name);
		/* Throws invalid_dn_value for a value outside the RFC 5280
		 * upper bounds (BTD-202) */
		void addEntryByNid(int nid, const QString &entry);
		/* The RFC 5280 Appendix A bounds in characters, one table for
		 * every path: C exactly 2; CN, O, OU, title, serialNumber 64;
		 * L, ST, pseudonym 128; emailAddress 255; other attributes
		 * by the string table of OpenSSL. Throws invalid_dn_value
		 * naming attribute, length and limit. */
		static void checkValue(int nid, const QString &value);
		/* the bounds checkValue() applies; -1: none */
		static std::pair<int, int> valueBounds(int nid);
		/* checkValue() for every entry, e.g. a subject copied from a
		 * device CSR */
		void checkUpperBounds() const;
		QString popEntryByNid(int nid);
		X509_NAME *get() const;
		const X509_NAME *get0() const;
		QString getMostPopular() const;
		QString taggedValues() const;
		QString hash() const;
		unsigned hashNum() const;
		bool search(const QRegularExpression &pattern) const;
};

#endif
