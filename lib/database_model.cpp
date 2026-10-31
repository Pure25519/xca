/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QDir>
#include <QFile>
#include <QDebug>

#include "XcaWarningCore.h"
#include "PwDialogCore.h"

#include "exception.h"
#include "database_model.h"
#include "pki_temp.h"
#include "pki_x509req.h"
#include "pki_evp.h"
#include "pki_scard.h"
#include "pki_multi.h"
#include "pki_pkcs12.h"
#include "entropy.h"
#include "db_base.h"
#include "sql.h"
#include "func.h"
#include "settings.h"
#include "entropy.h"
#include "pass_info.h"

#include "db_key.h"
#include "db_x509.h"
#include "db_crl.h"
#include "db_x509req.h"
#include "db_temp.h"
#include "audit.h"

xca_db Database;

bool database_model::open_without_password = false;

const QString &database_model::detect_provider()
{
	// Since we may access the database via ODBC, we need to ask
	// the backend engine directly.
	static const QList<QStringList> db_probes {
		{ "SELECT sqlite_version()", "3", "SQLITE" },
		{ "SELECT version()", "postgresql", "POSTGRES" },
		{ "SELECT @@version", "mysql", "MARIADB" },
		{ "SELECT @@version", "mariadb", "MARIADB" },
		{ "SELECT @@version", "microsoft", "MICROSOFT" },
	};
	if (db_provider.isEmpty()) {
		QSqlDatabase db = QSqlDatabase::database();
		if (!db.isOpen())
			return db_provider;

		db_provider = "UNKNOWN";
		XSqlQuery q;
		foreach(QStringList probe, db_probes) {
			qDebug() << probe[0];
			if (q.exec(probe[0]) && !q.lastError().isValid() && q.next()) {
				QString id = q.value(0).toString().simplified();
				qDebug() << probe[1] << id;
				if (id.contains(probe[1], Qt::CaseInsensitive)) {
					db_provider = probe[2];
					break;
				}
			}
		}
	}
	qDebug() << "db_provider:" << db_provider;
	return db_provider;
}

static unsigned bxcSchemaVersion()
{
	XSqlQuery q;

	SQL_PREPARE(q, "SELECT value FROM settings WHERE key_='bxc_schema'");
	q.exec();
	return q.next() ? q.value(0).toUInt() : 0;
}

QSqlError database_model::initSqlDB()
{
#define MAX_SCHEMAS 8
/* The initial SQL creation data creates a version "7"
 * database. Then an update to Version 8 by creating "takeys"
 * is executed.
 */
#define INITIAL_SCHEMA_VERSION "7"
/* Migrations of the bxc-pki fork, counted in settings 'bxc_schema' */
#define BXC_MAX_SCHEMAS 4

	QStringList schemas[MAX_SCHEMAS];
	QStringList bxc_schemas[BXC_MAX_SCHEMAS];

#include "database_schema.cpp"

	XSqlQuery q;
	QSqlDatabase db = QSqlDatabase::database();
	QStringList tables;
	unsigned int i;

	if (!db.isOpen())
		return QSqlError();

	QString b64_blob = "TEXT";
	if (detect_provider() == "MARIADB")
		b64_blob = "LONGTEXT";

	Transaction;
	if (!TransBegin())
		return db.lastError();

	bool existing = XSqlQuery::schemaVersion() > 0;
	bool auditCreated = false;

	for (;;) {
		i = XSqlQuery::schemaVersion();
		if (i >= ARRAY_SIZE(schemas))
			break;
		foreach(QString sql, schemas[i]) {
			sql.replace("_B64_BLOB_", b64_blob);
			qDebug("EXEC[%d]: '%s'", i, CCHAR(sql));
			if (!q.exec(sql) || q.lastError().isValid()) {
				TransRollback();
				return q.lastError();
			}
		}
	}

	if (i < MAX_SCHEMAS)
		throw errorEx(QObject::tr("Failed to update the database schema to the current version"));

	for (;;) {
		i = bxcSchemaVersion();
		if (i >= ARRAY_SIZE(bxc_schemas))
			break;
		foreach(QString sql, bxc_schemas[i]) {
			sql.replace("_B64_BLOB_", b64_blob);
			qDebug("EXEC[bxc %d]: '%s'", i, CCHAR(sql));
			if (!q.exec(sql) || q.lastError().isValid()) {
				TransRollback();
				return q.lastError();
			}
		}
		if (i == 0)
			auditCreated = true;
	}

	if (i < BXC_MAX_SCHEMAS)
		throw errorEx(QObject::tr("Failed to update the database schema to the current version"));

	/* A database that existed before the audit log: record its
	 * revocations, so that rows added later without an entry show */
	if (auditCreated && existing)
		AuditLog::writeBaseline();

	if (!TransCommit())
		return QSqlError(QString(), QObject::tr("Failed to commit "
			"the database schema update"),
			QSqlError::TransactionError);
	return QSqlError();
}

/* An existing database below the current upstream or fork schema: opening
 * it writes the migration (and the audit baseline) */
static bool schemaUpgradeNeeded()
{
	return XSqlQuery::schemaVersion() < MAX_SCHEMAS ||
		bxcSchemaVersion() < BXC_MAX_SCHEMAS;
}

bool database_model::checkForOldDbFormat(const QString &dbfile) const
{
	// 0x ca db 19 69
	static const unsigned char magic[] = { 0xca, 0xdb, 0x19, 0x69 };
	char head[4];

	XFile file(dbfile);
	if (!file.exists())
		return 0;
	if (!file.open(QIODevice::ReadOnly))
		return 0;
	file.read(head, sizeof head);
	file.close();
	return !memcmp(head, magic, sizeof head);
}

/* Until BTD-52 PBE-SHA1-3DES was the compiled PKCS#12 default, and the
 * Options dialog stored it on every OK: in an existing database it is no
 * choice. Once per database, after the unlock, it becomes AES-256-CBC
 * with an audit entry, and the user is told that legacy can be chosen
 * again. pkcs12_keep_legacy is a choice: the user confirmed the legacy
 * algorithm in the warning, so it stays. A new database only gets the
 * marker, so that a legacy algorithm chosen later is kept.
 * Algorithm, audit entry and marker are one transaction: a failure
 * leaves the database and memory as they were, the open goes on and
 * the next one tries again. */
static void migratePkcs12Default(bool existing)
{
	if (Settings["pkcs12_migrated"])
		return;
	QString old = Settings["pkcs12_enc_algo"];
	bool migrate = existing && !Settings["pkcs12_keep_legacy"] &&
		encAlgo(old).getEncAlgoNid() ==
			NID_pbe_WithSHA1And3_Key_TripleDES_CBC;
	QString algo = encAlgo::getBuiltinDefault().name();
	try {
		Transaction;
		if (!TransBegin())
			return;
		if (migrate) {
			Settings["pkcs12_enc_algo"] = algo;
			AuditLog::append(ServiceContext::localUser(
					ServiceContext::processChannel),
				AuditLog::actionSettingsMigrate, "database",
				QString(), AuditParams()
					.set("old_pkcs12_algorithm", old)
					.set("pkcs12_algorithm", algo));
		}
		Settings["pkcs12_migrated"] = true;
		if (!TransCommit()) {
			qWarning() << "PKCS#12 default migration rolled back";
			return;
		}
	} catch (errorEx &err) {
		qWarning() << "PKCS#12 default migration failed:"
			<< err.getString();
		return;
	}
	if (!migrate)
		return;
	QString msg = QObject::tr("The PKCS#12 export algorithm of this "
		"database was the old default PBE-SHA1-3DES and is now %1. "
		"A legacy algorithm can be chosen again in the Options.")
		.arg(algo);
	qInfo().noquote() << msg;
	XCA_INFO(msg);
}

/* Rows the models left out on loading (BTD-95): one message naming
 * each, and after the unlock an audit entry, so that rows that vanish
 * from the views leave a trace in the log (BTD-209). One entry per
 * change of the skipped set, not per open: the newest entry decides,
 * compared as a set, and the first open with every row loaded again
 * closes it with count 0 (BTD-221). The entry is best effort: a
 * failure is logged, the open goes on. */
static void reportSkippedRows(bool unlocked)
{
	QList<db_base::SkippedRow> rows = db_base::takeSkippedRows();
	if (unlocked) {
		QStringList items;
		for (const db_base::SkippedRow &r : rows)
			items << r.type + ":" + r.id;
		items.sort();
		try {
			Transaction;
			TransThrow();
			QStringList last = AuditLog::lastParams(
				AuditLog::actionRowsSkipped)
				.value("skipped_items").toString()
				.split(",", Qt::SkipEmptyParts);
			last.sort();
			if (items != last) {
				AuditParams params;
				params.set("count", (qint64)rows.size())
					.set("skipped_items", items.join(","));
				if (!rows.isEmpty())
					params.warn("rows_skipped");
				AuditLog::append(ServiceContext::localUser(
						ServiceContext::processChannel),
					AuditLog::actionRowsSkipped, "database",
					QString(), params);
				if (!TransCommit())
					qWarning() << "Audit entry of the "
						"skipped rows rolled back";
			}
		} catch (errorEx &err) {
			qWarning() << "Audit entry of the skipped rows failed:"
				<< err.getString();
		}
	}
	if (!rows.isEmpty())
		XCA_WARN(db_base::skippedRowsText(rows));
}

/* The file change counter of an SQLite file (bytes 24 to 27 of its
 * header): every committed write increments it, a read or a rolled-back
 * transaction does not. -1 if the file cannot be read. */
static qint64 fileChangeCounter(const QString &file)
{
	QFile f(file);
	if (!f.open(QIODevice::ReadOnly))
		return -1;
	QByteArray h = f.read(28);
	if (h.size() < 28 || !h.startsWith("SQLite format 3"))
		return -1;
	const uchar *p = reinterpret_cast<const uchar *>(h.constData()) + 24;
	return (qint64(p[0]) << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

database_model::database_model(const QString &name, const Passwd &pass)
{
	enum open_result result;
	QSqlError err;

#ifndef APPSTORE_COMPLIANT
	dbName = name;
#else
	(void)name;
	dbName = "default.xdb";
#endif

	if (dbName.isEmpty())
		dbName = get_default_db();

	if (dbName.isEmpty())
		throw open_abort;

	Passwd passwd(pass);
	pass_info p(XCA_TITLE, QString());
	p.setPurpose(pass_info::SqlPassword);
	do {
		try {
			openDatabase(dbName, passwd);
			break;
		} catch (errorEx &err) {
			if (!isRemoteDB(dbName))
				throw err;
			if (!passwd.isEmpty())
				XCA_ERROR(err);
			DbMap params = splitRemoteDbName(dbName);
			p.setDescription(tr("Please enter the password to access the database server %2 as user '%1'.")
					.arg(params["user"]).arg(params["host"]));
			result = PwDialogCore::execute(&p, &passwd);
			if (result != pw_ok)
				throw result;
		}
	} while (1);
	if (!isRemoteDB(dbName))
		openChangeCounter = fileChangeCounter(dbName);

	/* A failed schema update stops the open (BTD-142) */
	auto initSchema = [this]() {
		QSqlError e = initSqlDB();
		if (e.isValid())
			throw errorEx(tr("Failed to update the database schema: %1")
				.arg(e.text()));
	};
	try {
		Entropy::seed_rng();
		/* An existing database is unlocked before the schema upgrade
		 * and the audit baseline write to it, so a rejected password
		 * leaves it as it was. A new one needs its tables before the
		 * new password can be stored. (BTD-117) */
		bool existing = XSqlQuery::schemaVersion() > 0;
		if (!existing)
			initSchema();
		result = initPass(dbName, Settings["pwhash"]);
		if (result == pw_exit)
			throw pw_exit;
		if (result != pw_ok && Settings["pwhash"].empty())
			throw open_abort;
		/* Nothing is written without the verified password: GUI
		 * Cancel and xca --no-gui without a password source open a
		 * current database read-only, an old one not at all, since
		 * its upgrade and audit baseline would write (BTD-137) */
		bool verified = ServiceContext::processPasswordVerified;
		if (existing && !verified && schemaUpgradeNeeded())
			throw serviceError("schema_upgrade_needs_password", tr(
				"The database %1 has to be upgraded to the current "
				"version, which needs the database password. Open "
				"it with its password.")
				.arg(compressFilename(dbName)));
		if (existing)
			initSchema();
		if (verified) {
			Settings.migrateOptionflags();
			migratePkcs12Default(existing);
		}
	} catch (...) {
		/* No destructor runs for a failed constructor: close the
		 * connection here, or the next open() inherits its state */
		QString connName = QSqlDatabase::database().connectionName();
		QSqlDatabase::database().close();
		pki_evp::passwd.cleanse();
		QSqlDatabase::removeDatabase(connName);
		Settings.clear();
		throw;
	}

	/* Assure initialisation order:
	 * keys first, followed by x509[req], and crls last.
	 * Templates don't care.
	 */
	db_key *dbkey = new db_key();
	models << dbkey;
	models << new db_x509req();
	models << new db_x509();
	models << new db_crl();
	models << new db_temp();

	if (dbkey)
		dbkey->updateKeyEncryptionScheme();
	reportSkippedRows(ServiceContext::processPasswordVerified);

	foreach(db_base *m, models) {
		Q_CHECK_PTR(m);
		connect(m, SIGNAL(pkiChanged(pki_base*)),
			this, SLOT(pkiChangedSlot(pki_base*)));
	}

	pkcs11::libraries.load(Settings["pkcs11path"]);
	restart_timer();
}

db_base *database_model::modelForPki(const pki_base *pki) const
{
	if (dynamic_cast<const pki_x509*>(pki))
		return model<db_x509>();
	if (dynamic_cast<const pki_key*>(pki))
		return model<db_key>();
	if (dynamic_cast<const pki_x509req*>(pki))
		return model<db_x509req>();
	if (dynamic_cast<const pki_crl*>(pki))
		return model<db_crl>();
	if (dynamic_cast<const pki_temp*>(pki))
		return model<db_temp>();
	return NULL;
}

pki_base *database_model::insert(pki_base *pki)
{
	db_base *db = modelForPki(pki);
	if (db)
		return db->insert(pki);
	pki_multi *multi = dynamic_cast<pki_multi*>(pki);
	if (multi) {
		QList<pki_base *> items = multi->pull();
		while (!items.isEmpty()) {
			pki_base *i = items.takeFirst();
			try {
				insert(i);
			} catch (...) {
				/* insert() left it with us (BTD-50); one still
				 * in the store is freed by its unstore() */
				db_base *m = modelForPki(i);
				if (!m || !m->isStored(i))
					delete i;
				qDeleteAll(items);
				delete pki;
				throw;
			}
		}
	}
	delete pki;
	return NULL;
}

void database_model::restart_timer()
{
	if (!IS_GUI_APP)
		return;
	killTimer(dbTimer);
	dbTimer = startTimer(1500);
	foreach(db_base *m, models)
		m->restart_timer();
}

void database_model::timerEvent(QTimerEvent *event)
{
	quint64 stamp;
	if (event->timerId() != dbTimer)
		return;
	XSqlQuery q;
	SQL_PREPARE(q, "SELECT MAX(stamp) from items");
	q.exec();
	if (!q.first())
		return;
	stamp = q.value(0).toULongLong();
	q.finish();

	if (stamp > DbTransaction::DatabaseStamp) {
		SQL_PREPARE(q, "SELECT DISTINCT type FROM items WHERE stamp=?");
		q.bindValue(0, stamp);
		q.exec();

		QList<enum pki_type> typelist;
		while (q.next())
			typelist << (enum pki_type)q.value(0).toInt();

		q.finish();
		qDebug() << "CHANGED" << typelist;
		foreach(db_base *model, models)
			model->reloadContainer(typelist);
	}
	DbTransaction::DatabaseStamp = stamp;
}

void database_model::dump_database(const QString &dirname) const
{
	if (dirname.isEmpty())
		return;

	QDir d(dirname);
	if (!d.exists() && !d.mkdir(dirname)) {
		throw errorEx(tr("Unable to create '%1': %2").arg(dirname));
		return;
	}

	qDebug() << "Dumping to" << dirname;
	foreach(db_base *model, models)
		model->dump(dirname);
}

QString database_model::get_default_db() const
{
	if (QSqlDatabase::database().isOpen())
		return QString();

	QString dbfile = GlobalSettings().value("defaultdb").toString();

	if (QFile::exists(dbfile) || isRemoteDB(dbfile))
		return dbfile;
	return QString();
}

void database_model::as_default_database(const QString &db)
{
	if (db.isEmpty())
		GlobalSettings().remove("defaultdb");
	else
		GlobalSettings().setValue("defaultdb", db);
}

database_model::~database_model()
{
	QByteArray ba;
	QString connName =  QSqlDatabase::database().connectionName();

	/* no transactions on a connection that is gone (review of
	 * xca#68): begin() would run on the removed connection */
	DbTransaction::setHasTransaction(false);
	if (!QSqlDatabase::database().isOpen()) {
		QSqlDatabase::removeDatabase(connName);
		Settings.clear();
		return;
	}
	killTimer(dbTimer);

	qDeleteAll(models);
	models.clear();
	Store.flush();
	pki_base::freeUnstored();

	/* VACUUM only after a run that committed a write (BTD-225): every
	 * close rewrote the whole file, also after read-only commands such
	 * as list, --plan or --audit-verify, so its bytes and mtime changed
	 * and a read-only file failed the VACUUM unnoticed. A remote
	 * database keeps the VACUUM it had. Best effort: a failure is
	 * logged, the close goes on. */
	bool wrote = true;
	if (!isRemoteDB(dbName)) {
		qint64 now = fileChangeCounter(dbName);
		wrote = openChangeCounter < 0 || now < 0 ||
			now != openChangeCounter;
	}
	if (wrote) {
		XSqlQuery v;
		if (!v.exec("VACUUM"))
			qWarning() << "VACUUM after the writes of this run "
				"failed:" << v.lastError().text();
	}

	QSqlDatabase::database().close();
	pki_evp::passwd.cleanse();

	pkcs11::libraries.remove_libs();
	QSqlDatabase::removeDatabase(connName);
	Settings.clear();
	XSqlQuery::clearTablePrefix();
}

#define NUM_PARAM 6
#define NUM_PARAM_LEAST 5

DbMap database_model::splitRemoteDbName(const QString &db)
{
	static const char * const names[NUM_PARAM] =
		{ "all", "user", "host", "type", "dbname", "prefix" };
	DbMap map;
	auto match = QRegularExpression("(.*)@(.*)/(.*):([^#]*)#?([^#]*)")
					.match(db);
	QStringList list = match.capturedTexts();

	if (match.hasMatch() && list.size() >= NUM_PARAM_LEAST) {
		if (list.size() == NUM_PARAM_LEAST)
			list[NUM_PARAM_LEAST] = "";
		list[NUM_PARAM_LEAST] = list[NUM_PARAM_LEAST].toLower();
		for (int i=0; i < NUM_PARAM; i++) {
			map[names[i]] = list[i];
		}
		qDebug() << "SPLIT DB:" << map;
	}
	return map;
}

bool database_model::isRemoteDB(const QString &db)
{
	DbMap remote_param = splitRemoteDbName(db);
	return remote_param.size() == NUM_PARAM;
}

void database_model::openRemoteDatabase(const QString &connName,
				const DbMap &params, const Passwd &pass)
{
	QSqlDatabase db = QSqlDatabase::database(connName, false);

	db.setDatabaseName(params["dbname"]);
	QStringList hostport = params["host"].split(":");
	if (hostport.size() > 0)
		db.setHostName(hostport[0]);
	if (hostport.size() > 1)
		db.setPort(hostport[1].toInt());
	db.setUserName(params["user"]);
	db.setPassword(pass);

	const QStringList sql_opt_sections = {
		QString("%1-%2").arg(db.driverName()).arg(params["host"]),
		QString("%1").arg(db.driverName())
	};
	QSettings s = GlobalSettings();
	for (const QString &section : sql_opt_sections) {
		QStringList options;
		s.beginGroup(section);
		QStringList keys = s.childKeys();
		qDebug() << "TRYING" << section << "Entries:" << keys.size();
		if (!keys.isEmpty()) {
			for (const QString &key : keys) {
				QString value = s.value(key).toString();
				qDebug() << "KEY" << key << value;
				if (!value.isEmpty())
					options << QString("%1=%2").arg(key).arg(value);
			}
		}
		s.endGroup();
		db.setConnectOptions(options.join(";"));
	}
	QString envvar(QString("XCA_%1_OPTIONS").arg(db.driverName()));
	const char *opts = getenv(envvar.toLatin1());
	if (opts)
		db.setConnectOptions(opts);

	XSqlQuery::setTablePrefix(params["prefix"]);
	db.open();
	QSqlError e = db.lastError();

	if (e.isValid() || !db.isOpen()) {
		XSqlQuery::clearTablePrefix();
		db.close();
		throw errorEx(e);
	}
	/* This is MySQL specific. Execute it always, because
	 * dbType() could return "ODBC" but connect to MariaDB
	 */
	XSqlQuery q("SET SESSION SQL_MODE='ANSI'");
	q.exec("PRAGMA secure_delete = 'true'");
}

void database_model::openLocalDatabase(const QString &connName,
					const QString &descriptor)
{
	QSqlDatabase db = QSqlDatabase::database(connName);
	XFile f(descriptor);
	qDebug() << connName << descriptor;
	if (!f.exists(descriptor)) {
		f.open(QIODevice::WriteOnly);
		f.setPermissions(QFile::WriteOwner | QFile::ReadOwner);
	}

	if (f.size() != 0) {
		f.open(QIODevice::ReadOnly);
		QByteArray ba = f.read(6);
		qDebug() << "FILE:" << f.fileName() << ba;
		if (ba != "SQLite") {
			throw errorEx(tr("The file '%1' is not an XCA database")
					.arg(f.fileName()));
		}
	}
	f.close();

	db.setDatabaseName(descriptor);
	db.open();
	QSqlError e = db.lastError();
	if (e.isValid()) {
		db.close();
		throw errorEx(e);
	}
}

void database_model::openDatabase(const QString &descriptor, const Passwd &pass)
{
	DbMap params = splitRemoteDbName(descriptor);
	bool isRemote = params.size() == NUM_PARAM;
	QString connName, type = isRemote ? params["type"] : QString("QSQLITE");

	qDebug() << "IS REMOTE?" << params.size() << NUM_PARAM << type << params;
	try {
		QSqlDatabase db = QSqlDatabase::addDatabase(type);
		connName = db.connectionName();
		if (!isRemote) {
			if (!db.isDriverAvailable("QSQLITE"))
				throw errorEx(tr("No SqLite3 driver available. Please install the qt-sqlite package of your distribution"));
			openLocalDatabase(connName, descriptor);
		} else {
			openRemoteDatabase(connName, params, pass);
		}
		DbTransaction::setHasTransaction(
			db.driver()->hasFeature(QSqlDriver::Transactions));
	} catch (errorEx &err) {
		QSqlDatabase::removeDatabase(connName);
		throw err;
	}
}

static void pwhash_upgrade()
{
	/* Start automatic update from sha512 to sha512*8000
	 * if the password is correct. The old sha512 hash does
	 * start with 'S', while the new hash starts with T. */

	/* Start automatic update from md5 to salted sha512*8000
	 * if the password is correct. The md5 hash does not
	 * start with 'S' or 'T, but with a hex-digit */
	if (pki_evp::passHash.startsWith("T")) {
		/* Fine, current hash function used. */
		return;
	}
	if (pki_evp::sha512passwd(pki_evp::passwd,
				pki_evp::passHash) == pki_evp::passHash ||
	    pki_evp::md5passwd(pki_evp::passwd) == pki_evp::passHash)
	{
		QString salt = Entropy::makeSalt();
		pki_evp::passHash = pki_evp::sha512passwT(
				pki_evp::passwd, salt);
	}
}

enum open_result database_model::initPass(const QString &dbName, const QString &passhash) const
{
	QString salt, pass;
	enum open_result result = pw_cancel;

	pass_info p(tr("New Password"), tr("Please enter a password, "
			"that will be used to encrypt your private keys "
			"in the database:\n%1").
			arg(compressFilename(dbName)));
	p.setPurpose(pass_info::DatabasePassword);

	ServiceContext::processPasswordVerified = false;
	pki_evp::passHash = passhash;
	/* Without a password source the empty password is tried: if it
	 * is the database's password, the open is verified (BTD-246) */
	bool checked = !open_without_password || passhash.isEmpty() ||
		pki_evp::sha512passwT(QByteArray(""), passhash) == passhash;
	if (pki_evp::passHash.isEmpty()) {
		result = PwDialogCore::execute(&p, &pki_evp::passwd,true,true);
		if (result != pw_ok)
			return result;
		salt = Entropy::makeSalt();
		pki_evp::passHash =pki_evp::sha512passwT(pki_evp::passwd,salt);
		Settings["pwhash"] = pki_evp::passHash;
	} else if (!open_without_password) {
		/* A given password is read and compared even if the current
		 * one (empty at first) already matches: on a database with an
		 * empty password any given one passed unread (BTD-117) */
		bool given = PwDialogCore::hasSource(p.getPurpose());
		pwhash_upgrade();
		while (given || pki_evp::sha512passwT(pki_evp::passwd,
				pki_evp::passHash) != pki_evp::passHash)
		{
			given = false;
			if (result == pw_ok)
				XCA_PASSWD_ERROR();
			p.setTitle(tr("Password"));
			p.setDescription(tr("Please enter the password for unlocking the database:\n%1").arg(compressFilename(dbName)));
			result = PwDialogCore::execute(&p, &pki_evp::passwd,
						false, true);
			if (result != pw_ok) {
				pki_evp::passwd = QByteArray();
				return result;
			}
			pwhash_upgrade();
		}
	}
	/* The password is new or matched pwhash (BTD-78) */
	ServiceContext::processPasswordVerified = checked;
	open_without_password = false;
	if (pki_evp::passwd.isNull())
		pki_evp::passwd = "";
	return pw_ok;
}

void database_model::pkiChangedSlot(pki_base *pki)
{
	emit pkiChanged(pki);
}
