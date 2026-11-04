/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __DATABASE_MODEL_H
#define __DATABASE_MODEL_H

#include <QList>
#include <QObject>
#include <QDebug>
#include <QStringList>
#include <QSqlDatabase>

#include "sql.h"
#include "db_base.h"
#include "lib/Passwd.h"
#include "importexport.h"

class ServiceContext;

typedef QMap<QString, QString> DbMap;

class database_model: public QObject
{
	Q_OBJECT

	private:
		QList<db_base*> models{};
		int dbTimer{};
		QString dbName{};
		QString db_provider{};
		/* SQLite file change counter at the open, -1 if unknown
		 * (BTD-225) */
		qint64 openChangeCounter{-1};
		void openSqlDB();

		QSqlError initSqlDB();
		void backupBeforeMigration();
		const QString &detect_provider();
		bool checkForOldDbFormat(const QString &dbfile) const;
		enum open_result verifyOldDbPass(const QString &dbname) const;
		void importOldDatabase(const QString &dbfile);
		QString get_default_db() const;
		QString checkPre2Xdatabase() const;
		enum open_result initPass(const QString &dbName,
				const QString &passhash) const;
		void restart_timer();
		static void openDatabase(const QString &descriptor,
					 const Passwd &pass);
		static void openRemoteDatabase(const QString &connName,
						const DbMap &params,
						const Passwd &pass);
		static void openLocalDatabase(const QString &connName,
						const QString &descriptor);
	private slots:
		void pkiChangedSlot(pki_base *pki);

	public:
		static bool open_without_password;
		/* An audit check (--audit-verify, --audit-export) refuses to
		 * migrate an older database: schema_upgrade_required, nothing
		 * written (BTD-70) */
		static bool refuse_schema_upgrade;
		database_model(const QString &dbName,
				const Passwd &pass = Passwd());
		~database_model();
		void timerEvent(QTimerEvent *event);
		db_base *modelForPki(const pki_base *pki) const;

		QString dbname() const
		{
			return dbName;
		}
		void dump_database(const QString &dirname) const;
		QList<db_base*> getModels() const
		{
			return models;
		}
		template <class T> T *model() const
		{
			foreach(db_base *model, models) {
				T *m = dynamic_cast<T*>(model);
				if (m)
					return m;
			}
			return nullptr;
		}
		pki_base *insert(pki_base *pki);
		/* Imports files, data or read objects (BTD-34): one audit
		 * entry object.import per object, created or found in the
		 * database (outcome created, completed or existing), plus
		 * the revocation entries of the rows a CRL or renewed CA
		 * adds; or one object.import failure. All in one
		 * transaction. Throws serviceError (missing_password,
		 * wrong_password, unreadable_input, no_pki_data,
		 * nothing_to_import, unsupported_type, database_error) and
		 * errorEx (internal_error). No question or message, except a
		 * GUI password dialog when spec has no password source;
		 * call it outside a transaction. */
		ImportResult importItems(const ServiceContext &ctx,
				const ImportSpec &spec);

		static DbMap splitRemoteDbName(const QString &db);
		static bool isRemoteDB(const QString &db);
		static void as_default_database(const QString &db);

	signals:
		void pkiChanged(pki_base *pki) const;
};

class xca_db
{
	private:
		database_model *db{};

	public:
		xca_db() { }
		~xca_db()
		{
			close();
		}
		void open(const QString &dbName, const Passwd &pass = Passwd())
		{
			close();
			db = new database_model(dbName, pass);
			qDebug() << "Opening database:" << name();
		}
		void open_default()
		{
			open(QString());
		}
		void close()
		{
			if (db) {
				qDebug() << "Closing database:" << name();
				delete db;
				db = NULL;
			}
		}
		QString name() const
		{
			return db ? db->dbname() : QString();
		}
		bool isOpen()
		{
			return db != NULL;
		}
		template <class T> T *model() const
		{
			return db ? db->model<T>() : NULL;
		}
		void dump(const QString &dirname) const
		{
			if (db)
				db->dump_database(dirname);
		}
		void as_default() const
		{
			database_model::as_default_database(name());
		}
		QList<db_base*> getModels() const
		{
			return db ? db->getModels() : QList<db_base*>();
		}
		pki_base *insert(pki_base *pki)
		{
			return db ? db->insert(pki) : NULL;
		}
		ImportResult importItems(const ServiceContext &ctx,
				const ImportSpec &spec)
		{
			if (db)
				return db->importItems(ctx, spec);
			for (pki_base *pki : spec.items)
				delete pki;
			throw serviceError("no_database",
				QObject::tr("No database is open"));
		}
		db_base *modelForPki(const pki_base *pki) const
		{
			return db ? db->modelForPki(pki) : NULL;
		}
		void connectToDbChangeEvt(QObject *o, const char *slot)
		{
			if (db)
				QObject::connect(
					db, SIGNAL(pkiChanged(pki_base*)),
					o, slot);
		}
};

extern xca_db Database;

#endif
