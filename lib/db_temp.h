/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#ifndef __DB_TEMP_H
#define __DB_TEMP_H

#include "db_x509super.h"

class pki_temp;
class ServiceContext;
class TemplateSpec;

class db_temp: public db_x509name
{
	Q_OBJECT
  protected:
	QList<pki_temp*> predefs{};

  public:
	db_temp();
	~db_temp();
	pki_base *newPKI(enum pki_type type = none);
	QList<pki_temp*> getPredefs() const;
	/* Service functions (BTD-35, lib/template.h). No question or
	 * message; call them outside a transaction. Rejections throw
	 * serviceError; one audit entry per call. */
	/* template.create: a new template with the values of spec */
	pki_temp *newTemplate(const ServiceContext &ctx,
				const TemplateSpec &spec);
	/* template.update: replaces name, comment and all values of temp;
	 * temp keeps its old values when the call fails */
	void updateTemplate(const ServiceContext &ctx, pki_temp *temp,
				const TemplateSpec &spec);
	void writeItem(pki_base *pki, const pki_export *xport,
		QIODevice &file, const Passwd &pass) const;
};
#endif
