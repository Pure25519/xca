/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "pki_multi.h"
#include "pki_x509.h"
#include "pki_key.h"
#include "pki_x509req.h"
#include "pki_pkcs7.h"
#include "pki_pkcs12.h"
#include "pki_crl.h"
#include "pki_temp.h"
#include "pki_evp.h"
#include "load_obj.h"
#include "exception.h"
#include "func.h"
#include "xfile.h"
#include "XcaWarningCore.h"
#include <QList>

pki_multi::pki_multi(const QString &name)
	:pki_base(name)
{
	multi.clear();
	failed_files.clear();
}

pki_multi::~pki_multi()
{
	foreach(pki_base *pki, multi) {
		if (pki->getSqlItemId().toInt() == 0)
			delete pki;
	}
}

void pki_multi::append_item(pki_base *pki)
{
	pki_multi *m = dynamic_cast<pki_multi*>(pki);
	if (m) {
		multi += m->multi;
		m->multi.clear();
		delete m;
	} else {
		multi << pki;
	}
}

#define D5 "-----"
#define BEGIN D5 "BEGIN "
/* General PEM loader */
static pki_base *pkiByPEM(QString text, int *skip)
{
	int pos = text.indexOf(BEGIN);

	if (skip)
		*skip = pos;

	if (pos < 0)
		return NULL;

	text = text.remove(0, pos + sizeof(BEGIN)-1);
	if (text.startsWith(PEM_STRING_X509_OLD D5) ||
				text.startsWith(PEM_STRING_X509 D5) ||
				text.startsWith(PEM_STRING_X509_TRUSTED D5))
		return new pki_x509();

	if (text.startsWith(PEM_STRING_PKCS7 D5))
		return new pki_pkcs7();

	if (text.startsWith(PEM_STRING_X509_REQ_OLD D5) ||
				text.startsWith(PEM_STRING_X509_REQ D5))
		return new pki_x509req();

	if (text.startsWith(PEM_STRING_X509_CRL D5))
		return new pki_crl();

	if (text.startsWith(PEM_STRING_XCA_TEMPLATE D5))
		return new pki_temp();

	if (text.startsWith(PEM_STRING_EVP_PKEY D5) ||
				text.startsWith(PEM_STRING_PUBLIC D5) ||
				text.startsWith(PEM_STRING_RSA D5) ||
				text.startsWith(PEM_STRING_RSA_PUBLIC D5) ||
				text.startsWith(PEM_STRING_DSA D5) ||
				text.startsWith(PEM_STRING_DSA_PUBLIC D5) ||
				text.startsWith(PEM_STRING_ECDSA_PUBLIC D5) ||
				text.startsWith(PEM_STRING_ECPRIVATEKEY D5) ||
				text.startsWith(PEM_STRING_PKCS8 D5) ||
				text.startsWith(PEM_STRING_PKCS8INF D5) ||
				text.startsWith(PEM_STRING_OPENSSH_KEY D5))

		return new pki_evp();

	return NULL;
}

void pki_multi::fromBytes(const QByteArray &ba, const QString &name)
{
	fromPEMbyteArray(ba, name);
}

void pki_multi::fromPEMbyteArray(const QByteArray &_ba, const QString &name)
{
	pki_base *item = NULL;
	int startpos, old_count = multi.size();
	QByteArray ba = _ba;
	for (;;) {
		try {
			item = pkiByPEM(QString::fromLatin1(ba), &startpos);
			if (!item)
				break;
			ba.remove(0, startpos);
			item->fromPEMbyteArray(ba, name);
			item->pkiSource = imported;
			openssl_error();
			append_item(item);
		} catch (secretError &) {
			/* a missing or rejected password from a source is
			 * the caller's error, not a damaged item (BTD-34) */
			delete item;
			throw;
		} catch (errorEx &err) {
			XCA_ERROR(err);
			delete item;
			item = NULL;
		} catch (...) {
			delete item;
			item = NULL;
		}
		ba.remove(0, sizeof BEGIN -1);
	}
	pki_ign_openssl_error();
	if (multi.size() == old_count)
		throw errorEx(tr("No known PEM encoded items found"));
}

void pki_multi::probeAnything(const QString &fname)
{
	/* Check for file accessibility to report
	 * a reasonable error early thrown by file.open_read() */
	XFile file(fname);
	file.open_read();
	file.close();

	probe(fname, [&fname](load_base *lb) {
		return lb->loadItem(fname);
	});
}

void pki_multi::probeData(const QByteArray &ba, const QString &name)
{
	probe(name, [&ba, &name](load_base *lb) {
		return lb->loadData(ba, name);
	});
}

void pki_multi::probe(const QString &name,
		const std::function<pki_base *(load_base *)> &load)
{
	pki_base *item = NULL;
	int old_count = multi.size();
	QList<load_base*> lbs;

	lbs <<  new load_pem() <<
		new load_cert() << new load_pkcs7() << new load_pkcs12() <<
		new load_crl() <<  new load_req() <<   new load_key() <<
		new load_temp();

	foreach(load_base *lb, lbs) {
		try {
			item = load(lb);
			if (item) {
				append_item(item);
				break;
			}
		} catch (secretError &) {
			/* the password from a source is missing or wrong:
			 * report that instead of "no PKI data" (BTD-34) */
			qDeleteAll(lbs);
			throw;
		} catch (errorEx &) {
			continue;
		} catch (enum open_result r) {
			if (r == pw_cancel)
				break;
		}
	}
	if (multi.count() == old_count && !name.isEmpty())
		failed_files << name;

	qDeleteAll(lbs);
}

void pki_multi::print(BioByteArray &bba, enum print_opt opt) const
{
	pki_base::print(bba, opt);
	foreach(pki_base *pki, multi)
		pki->print(bba, opt);
}

void pki_multi::collect_properties(QMap<QString, QString> &) const
{
}

QList<pki_base *> pki_multi::pull()
{
	QList<pki_base*> temp = multi;
	multi.clear();
	return temp;
}

QList<pki_base *> pki_multi::get() const
{
	return multi;
}
