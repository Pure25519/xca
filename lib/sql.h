/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2017 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __SQL_H
#define __SQL_H

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
		static void addItems(QVariant v)
		{
			items << v.toULongLong();
		}
		static void setHasTransaction(bool trans)
		{
			hasTransaction = trans;
		}
};

#define Transaction DbTransaction __trans
#define TransBegin() __trans.begin(__FILE__, __LINE__)
#define TransThrow() if (!__trans.begin(__FILE__, __LINE__)) { \
	throw errorEx(QObject::tr("Failed to start a database transaction")); }
#define TransCommit() __trans.commit(__FILE__, __LINE__)
#define TransRollback() __trans.rollback(__FILE__, __LINE__)
#define TransDone(e) __trans.done(e, __FILE__, __LINE__);
#define AffectedItems(v) (DbTransaction::addItems(v))


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

#endif
