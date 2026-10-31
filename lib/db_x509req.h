/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#ifndef __DB_X509REQ_H
#define __DB_X509REQ_H

#include "db_x509super.h"

class pki_temp;
class pki_x509req;
class AuditParams;
class RequestSpec;
class ServiceContext;

class db_x509req: public db_x509super
{
	Q_OBJECT

		pki_x509req *create(const RequestSpec &spec, AuditParams &params,
				const ServiceContext &ctx);
	protected:
		dbheaderList getHeaders();
	public:
		db_x509req();
		pki_base* insert(pki_base *item);
		pki_base *newPKI(enum pki_type type = none);
		QList<pki_x509req*> getAllRequests();
		void resetX509count();
		/* Creates one certificate signing request (BTD-32). Throws
		 * serviceError for a rejected spec and errorEx for anything
		 * else; writes exactly one audit entry request.create either
		 * way (error code internal_error for anything but a
		 * serviceError). Call it outside a transaction. */
		pki_x509req *newRequest(const ServiceContext &ctx,
				const RequestSpec &spec);
		void setSigned(QModelIndex index, bool signe);
		void writeItem(pki_base *pki, const pki_export *xport,
				QIODevice &file, const Passwd &pass,
				const ExportOptions &opts) const;
};

#endif
