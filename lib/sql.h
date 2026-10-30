/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2017 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __SQL_H
#define __SQL_H

#include <functional>

#include <QtSql>
#include <QList>

#define SQL_PREPARE(q,cmd) do { \
	(q).prepare(cmd); \
	(q).location(__FILE__,__LINE__); \
} while (0)

class DbTransaction
{
	private:
		static int mutex;
		static int error;
		static QList<quint64> items;
		static bool hasTransaction;
		static int injected;
		static QString firstRollback;
		static QSqlError failure;
		static QList<std::function<void()> > undoActions;
		static QList<std::function<void()> > commitActions;
		static void runActions(QList<std::function<void()> > &list,
				bool lastFirst);
		bool has_begun{};
		const char *beginFile{};
		int beginLine{};
		void debug(const char *func, const char *file, int line);
		bool finish(bool commit, const char *file, int line);
		/* Tests only (BTD-142): the nested commit after the next skip
		 * ones rolls back instead and reports success, like an inner
		 * helper that rolls back and returns without throwing */
		static void injectNestedRollback(int skip = 0)
		{
			injected = skip + 1;
		}
		static bool injectionPending()
		{
			return injected > 0;
		}
		friend class test_service_transaction;
		friend class test_service_memory;

	public:
		DbTransaction() { };
		~DbTransaction();
		bool begin(const char *file, int line);
		/* False when the outermost commit fails, and also when an
		 * inner transaction rolled back: then the outermost one rolls
		 * everything back (BTD-142). An inner commit returns true. */
		bool commit(const char *file, int line);
		bool rollback(const char *file, int line);
		bool done(QSqlError e, const char *file, int line);
		static quint64 DatabaseStamp;
		static bool active()
		{
			return mutex > 0;
		}
		/* The SQL error of the last failed BEGIN or COMMIT; invalid if
		 * a commit failed because an inner transaction rolled back */
		static QSqlError lastFailure()
		{
			return failure;
		}
		static void addItems(QVariant v)
		{
			items << v.toULongLong();
		}
		static void setHasTransaction(bool trans)
		{
			hasTransaction = trans;
		}
		/* Memory follows the database (BTD-130). A change of memory
		 * that later steps of the transaction need (a new object in
		 * the store and the view, a link to it) is made at once and
		 * registers how to take it back: the undo runs, last first,
		 * when the outermost transaction ends without a successful
		 * COMMIT, and is dropped after one. It changes memory only,
		 * never the database, and must not throw. Outside a
		 * transaction there is nothing to undo. */
		static void onRollback(std::function<void()> undo);
		/* A change of memory that must wait for the COMMIT, e.g.
		 * freeing a deleted object: runs after the outermost COMMIT
		 * succeeded, never after a rollback; at once outside a
		 * transaction */
		static void afterCommit(std::function<void()> action);
};

#define Transaction DbTransaction __trans
#define TransBegin() __trans.begin(__FILE__, __LINE__)
#define TransThrow() if (!__trans.begin(__FILE__, __LINE__)) { \
	throwSqlError(DbTransaction::lastFailure(), \
		QObject::tr("Failed to start a database transaction")); }
#define TransCommit() __trans.commit(__FILE__, __LINE__)
#define TransCommitThrow() if (!__trans.commit(__FILE__, __LINE__)) { \
	throwSqlError(DbTransaction::lastFailure(), \
		QObject::tr("Failed to commit the database transaction")); }
#define TransRollback() __trans.rollback(__FILE__, __LINE__)
#define TransDone(e) __trans.done(e, __FILE__, __LINE__);
#define AffectedItems(v) (DbTransaction::addItems(v))


/* A failed SQL statement, BEGIN or COMMIT as a typed service error
 * (BTD-50): read_only_database or disk_full where SQLite says so,
 * database_error otherwise. The text is what failed and SQLite's
 * reason, never the statement and its values (they may hold key
 * material); those go to the debug log. */
[[noreturn]] void throwSqlError(const QSqlError &e, const QString &what);
/* The service error code of a native error code of the Qt driver:
 * QSQLITE result codes (the low byte of an extended one), QPSQL
 * SQLSTATEs, QMYSQL/QMARIADB error numbers; database_error otherwise */
QString sqlErrorCode(const QString &driver, const QString &native);

class XSqlQuery: public QSqlQuery
{
	private:
		QString lastq, query;
		const char *file;
		int line;
		QString rewriteQuery(QString query);
		static QString table_prefix;
	public:
		XSqlQuery();
		XSqlQuery(QString q);

		static int schemaVersion();
		static void setTablePrefix(QString p)
		{
			table_prefix = p;
		}
		static void clearTablePrefix()
		{
			table_prefix.clear();
		}
		QString query_details();
		QSqlError lastError();
		bool exec(QString q);
		bool exec();
		bool prepare(QString q);
		void location(const char *f, int l);
};

/* Executes q; a failure is throwSqlError() with what, or "Database
 * error" (BTD-50) */
void execOrThrow(XSqlQuery &q, const QString &what = QString());

#endif
