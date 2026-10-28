/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#ifndef __PKI_MULTI_H
#define __PKI_MULTI_H

#include <QStringList>
#include <functional>
#include "pki_base.h"

class load_base;

class pki_multi: public pki_base
{
		Q_OBJECT
	protected:
		QList<pki_base*> multi{};
		void probe(const QString &name,
			const std::function<pki_base *(load_base *)> &load);
	public:
		pki_multi(const QString &name = "");
		~pki_multi();
		QStringList failed_files;
		void fromPEMbyteArray(const QByteArray &, const QString &);
		void fromBytes(const QByteArray &ba, const QString &name);
		void probeAnything(const QString &fname);
		/* The same for the content of a file (BTD-34); name
		 * describes the source. Throws secretError for a missing
		 * or rejected password, like probeAnything() */
		void probeData(const QByteArray &ba, const QString &name);
		void append_item(pki_base *pki);
		void print(BioByteArray &b, enum print_opt opt) const;
		void collect_properties(QMap<QString, QString> &prp) const;
		QList<pki_base *> pull();
		QList<pki_base *> get() const;
};
#endif
