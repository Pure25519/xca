/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "db_temp.h"
#include "pki_temp.h"
#include "load_obj.h"
#include "func.h"
#include "audit.h"
#include "exception.h"
#include "template.h"
#include "XcaWarningCore.h"
#include <QDir>
#include <QFileInfo>

db_temp::db_temp() : db_x509name("templates")
{
	/* XCA loads templates from private space ($HOME/.local/)
	 * Host specific (/usr/local) and distribution (/usr)
	 * The first <name>.xca found avoids other <name>.xca to be loaded
	 */
	QSet<QString> template_files;
	load_temp l;

	sqlHashTable = "templates";
	pkitype << tmpl;

	updateHeaders();
	loadContainer();

	pki_temp *tmpl = new pki_temp(tr("Empty template"));
	tmpl->setAsPreDefined();
	predefs << tmpl;

	QStringList dirs = QStandardPaths::standardLocations(
	                     QStandardPaths::AppDataLocation);
#ifdef INSTALL_DATA_PREFIX
	dirs << QString(INSTALL_DATA_PREFIX);
#endif
	foreach(QString d, dirs)
	{
		qDebug() << "Looking for templates at" << d;
		QFileInfoList list = QDir(d).entryInfoList(
				QStringList("*.xca"),
				QDir::Files | QDir::NoSymLinks |
                                QDir::NoDot | QDir::Readable);

		foreach(QFileInfo fileInfo, list) {
			if (template_files.contains(fileInfo.fileName()))
				continue;

			qDebug() << "Loading template" << fileInfo.fileName()
					<< fileInfo.absoluteFilePath();
			try {
				tmpl = dynamic_cast<pki_temp*>(l.loadItem(
						fileInfo.absoluteFilePath()));
				if (tmpl) {
					tmpl->setAsPreDefined();
					predefs << tmpl;
					template_files << fileInfo.fileName();
				}
			} catch(errorEx &) {
				XCA_WARN(tr("Bad template: %1")
					.arg(nativeSeparator(
						fileInfo.absoluteFilePath())));
			}
		}
	}
}

db_temp::~db_temp()
{
	qDeleteAll(predefs);
}

pki_base *db_temp::newPKI(enum pki_type type)
{
	(void)type;
	return new pki_temp("");
}

QList<pki_temp *> db_temp::getPredefs() const
{
	return predefs;
}

static AuditParams templateParams(const TemplateSpec &spec)
{
	AuditParams p;
	p.set("name", spec.name);
	p.set("subject", spec.subject.oneLine());
	return p;
}

static QString itemId(const pki_base *pki)
{
	return pki && pki->getSqlItemId().isValid() ?
		pki->getSqlItemId().toString() : QString();
}

pki_temp *db_temp::newTemplate(const ServiceContext &ctx,
				const TemplateSpec &spec)
{
	pki_temp *temp = new pki_temp();
	AuditParams params = templateParams(spec);

	spec.toTemplate(temp);
	temp->pkiSource = spec.source;
	try {
		auditedTransaction(ctx, "template.create", "template",
				QString(), params, [&]() {
			QSqlError e = temp->insertSql();
			if (e.isValid())
				throw serviceError("database_error",
					e.text());
			Store.add(temp->getSqlItemId(), temp);
			inToCont(temp);
			AuditLog::append(ctx, "template.create", "template",
					itemId(temp), params);
		});
	} catch (...) {
		/* Known limit until BTD-50: rolled back in the database,
		 * but already in the store and the view */
		if (!isStored(temp))
			delete temp;
		throw;
	}
	restart_timer();
	emit columnsContentChanged();
	return temp;
}

void db_temp::updateTemplate(const ServiceContext &ctx, pki_temp *temp,
				const TemplateSpec &spec)
{
	AuditParams params = templateParams(spec);
	TemplateSpec old;

	if (temp) {
		old = TemplateSpec::fromTemplate(temp);
		if (old.name != spec.name)
			params.set("old_name", old.name);
	}
	try {
		auditedTransaction(ctx, "template.update", "template",
				itemId(temp), params, [&]() {
			if (!isStored(temp))
				throw serviceError("missing_template",
					tr("The template is not in the database"));
			XSqlQuery q;
			spec.toTemplate(temp);
			SQL_PREPARE(q, "UPDATE templates SET version=?, template=? WHERE item=?");
			q.bindValue(0, TMPL_VERSION);
			q.bindValue(1, temp->toB64Data());
			q.bindValue(2, temp->getSqlItemId());
			q.exec();
			QSqlError e = q.lastError();
			if (e.isValid())
				throw serviceError("database_error", e.text());
			writeNameComment(temp);
			AuditLog::append(ctx, "template.update", "template",
					itemId(temp), params);
		});
	} catch (...) {
		if (isStored(temp)) {
			old.toTemplate(temp);
			emitDataChanged(temp);
		}
		throw;
	}
	emitDataChanged(temp);
}

void db_temp::writeItem(pki_base *pki, const pki_export *,
			QIODevice &file, const Passwd &) const
{
	pki_temp *temp = dynamic_cast<pki_temp *>(pki);
	if (temp)
		temp->writeTemp(file);
}
