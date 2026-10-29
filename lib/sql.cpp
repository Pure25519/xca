/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2017 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QString>
#include <QRegularExpression>
#include <QDebug>
#include "base.h"
#include "sql.h"
#include "settings.h"
#include "XcaWarningCore.h"

int DbTransaction::mutex;
int DbTransaction::error;
bool DbTransaction::hasTransaction;
int DbTransaction::injected;
QString DbTransaction::firstRollback;
QList<quint64> DbTransaction::items;
QList<std::function<void()> > DbTransaction::undoActions;
QList<std::function<void()> > DbTransaction::commitActions;

quint64 DbTransaction::DatabaseStamp;

static QString location(const char *file, int line)
{
	return QString("%1(%2)").arg(file + QString(file).lastIndexOf("/") +1)
			.arg(line);
}

void DbTransaction::debug(const char *func, const char *file, int line)
{
	qDebug() << QString("%1 Transaction: %2 Level %3, E:%4 ")
			.arg(location(file, line))
			.arg(func).arg(mutex).arg(error);
}

DbTransaction::~DbTransaction()
{
	if (has_begun)
		rollback("Destructor", 0);
}

bool DbTransaction::begin(const char *file, int line)
{
	mutex++;
	has_begun = true;
	beginFile = file;
	beginLine = line;
	debug("Begin", file, line);
	if (mutex > 1 || !hasTransaction)
		return true;

	QSqlDatabase db = QSqlDatabase::database();
	bool ret = db.transaction();
	if (!ret)
		XCA_SQLERROR(db.lastError());
	return ret;
}

bool DbTransaction::finish(bool commit, const char *file, int line)
{
	const char *oper = commit ? "Commit" : "Rollback";

	if (!has_begun)
		return true;
	if (mutex > 0)
		mutex--;
	else
		qCritical() << "Unbalanced DB Transaction in " << oper;
	debug(oper, file, line);
	has_begun = false;
	if (mutex > 0)
		return true;

	QSqlDatabase db = QSqlDatabase::database();
	if (error) {
		error = 0;
		items.clear();
		bool ret = hasTransaction ? db.rollback() : true;
		commitActions.clear();
		runActions(undoActions, true);
		if (!commit)
			return ret;
		/* An inner transaction rolled back, so everything did: the
		 * commit failed. Before BTD-142 the caller got the result
		 * of the rollback, true, and reported success. */
		qWarning() << "Commit at" << location(file, line)
			<< "rolled back after the rollback at" << firstRollback;
		return false;
	}
	mutex++;
	XSqlQuery q;
	SQL_PREPARE(q, "SELECT MAX(stamp) +1 from items");
	q.exec();
	if (q.first())
		DatabaseStamp = q.value(0).toULongLong();

	SQL_PREPARE(q, "UPDATE items SET stamp=? WHERE stamp=0");
	q.bindValue(0, DatabaseStamp);
	q.exec();

	SQL_PREPARE(q, "UPDATE items SET stamp=? WHERE id=?");
	q.bindValue(0, DatabaseStamp);
	foreach(quint64 id, DbTransaction::items) {
		q.bindValue(1, id);
		q.exec();
	}
	mutex--;
	items.clear();

	bool ret = hasTransaction ? db.commit() : true;
	if (!ret) {
		XCA_SQLERROR(db.lastError());
		/* SQLite keeps the transaction open after a failed COMMIT
		 * (busy, deferred constraint): every later write would end
		 * up in it and be lost on close (BTD-114) */
		db.rollback();
		commitActions.clear();
		runActions(undoActions, true);
		return false;
	}
	undoActions.clear();
	runActions(commitActions, false);
	return true;
}

void DbTransaction::runActions(QList<std::function<void()> > &list,
			bool lastFirst)
{
	/* an action may start a transaction of its own and register more */
	QList<std::function<void()> > run;
	run.swap(list);
	for (qsizetype i = 0; i < run.size(); i++) {
		try {
			run[lastFirst ? run.size() - 1 - i : i]();
		} catch (...) {
			/* may run while an exception unwinds the stack */
			qCritical() << "DbTransaction: a memory action threw";
		}
	}
}

void DbTransaction::onRollback(std::function<void()> undo)
{
	if (mutex > 0)
		undoActions << undo;
}

void DbTransaction::afterCommit(std::function<void()> action)
{
	if (mutex > 0)
		commitActions << action;
	else
		action();
}

bool DbTransaction::commit(const char *file, int line)
{
	if (injected > 0 && has_begun && mutex > 1 && --injected == 0) {
		rollback(file, line);
		return true;
	}
	return finish(true, file, line);
}

bool DbTransaction::rollback(const char *file, int line)
{
	/* A stray rollback after the commit must not fail the next
	 * transaction (BTD-142) */
	if (!has_begun)
		return true;
	/* The first rollback names the cause of a failed outer commit; the
	 * destructor names where its transaction began */
	if (!error++)
		firstRollback = line ? location(file, line) :
			location(beginFile, beginLine) + " (left without commit)";
	return finish(false, file, line);
}

bool DbTransaction::done(QSqlError e, const char *file, int line)
{
	return e.isValid() ? rollback(file, line) : commit(file, line);
}

QString XSqlQuery::table_prefix;

int XSqlQuery::schemaVersion()
{
	qDebug() << "table_prefix:" << table_prefix;;
	return QSqlDatabase::database().tables()
			.contains(table_prefix + "settings") ?
				Settings["schema"] : 0;
}

QString XSqlQuery::rewriteQuery(QString _q)
{
	static const QStringList tables {
		"items" , "crls" , "private_keys" , "public_keys" ,
		"tokens" , "token_mechanism" , "templates" , "certs" ,
		"authority" , "revocations" , "requests" , "x509super" ,
		"settings" , "takeys", "audit_log", "audit_keys",

		"view_public_keys" , "view_certs" , "view_requests" ,
		"view_crls" , "view_templates" , "view_private",
	};

	lastq = query = _q;
	if (table_prefix.isEmpty())
		return query;

	QString m = tables.join("|") + "|i_" + tables.join("|i_");
	m = QString("\\b(%1)").arg(m);
	query = query.replace(QRegularExpression(m), table_prefix + "\\1");

	return query;
}

QString XSqlQuery::query_details()
{
	QString lq = lastq;
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
	QVariantList list = boundValues();
#else
	QVariantList list = boundValues().values();
#endif
	QStringList sl;

	if (query != lastq) {
		lq = QString("%1 (PREFIX[%2]: %3)").arg(lastq)
				.arg(table_prefix).arg(query);
	}
	for (int i = 0; i < list.size(); ++i)
		sl << list.at(i).toString();
	if (sl.size())
		lq += QString("[%1]").arg(sl.join(", "));
	return QString("%1:%2 (%3)").arg(file).arg(line).arg(lq);
}

QSqlError XSqlQuery::lastError()
{
	QSqlError e = QSqlQuery::lastError();
	if (!e.isValid())
		return e;
	return QSqlError(QString("%1 - %2").arg(e.driverText())
					.arg(query_details()),
			 e.databaseText(), e.type(),
			 e.nativeErrorCode()
			);
}

XSqlQuery::XSqlQuery() : QSqlQuery()
{
}

XSqlQuery::XSqlQuery(QString q) : QSqlQuery()
{
	exec(q);
}

bool XSqlQuery::exec(QString q)
{
	q = rewriteQuery(q);
	file = ""; line = 0;
	return QSqlQuery::exec(q);
}

bool XSqlQuery::exec()
{
	QString res;
	setForwardOnly(true);
	bool r = QSqlQuery::exec();
	if (isSelect()) {
		res = QString("Rows selected: %1").arg(size());
	} else {
		res = QString("Rows affected: %1").arg(numRowsAffected());
		if (!DbTransaction::active()) {
			 qCritical("########## MISSING Transaction in %s(%d)",
				file, line);
		}
	}
	qDebug() << QString("QUERY: %1 - %2").arg(query_details()).arg(res);
	return r;
}

bool XSqlQuery::prepare(QString q)
{
	q = rewriteQuery(q);
	setForwardOnly(true);
	return QSqlQuery::prepare(q);
}

void XSqlQuery::location(const char *f, int l)
{
	file = f + QString(f).lastIndexOf("/") +1;
	line = l;
}
