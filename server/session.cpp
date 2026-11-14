/* vi: set sw=4 ts=4:
 *
 * The database session of xca-server (BTD-154), see session.h. Runs on
 * the DB worker only.
 */

#include "session.h"

#include <QCoreApplication>
#include <QFileInfo>
#include <QObject>
#include <QStringList>

#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/exception.h"
#include "lib/oid.h"
#include "lib/pass_info.h"
#include "lib/pki_export.h"
#include "lib/settings.h"
#include "lib/sql.h"
#include "lib/XcaProgress.h"
#include "lib/XcaWarningCore.h"

#include "config.h"
#include "worker.h"

namespace xcaserver {

namespace {

/* Messages of lib/ go to stderr as text, like the command line's;
 * collects the errors of the OID initialisation */
class ServerWarning: public xcaWarningCore
{
  public:
	static QStringList *collect;

	void error(const QString &msg) override
	{
		if (collect)
			*collect << msg;
		print_cmdline(COL_RED "Error", msg);
	}
};
QStringList *ServerWarning::collect;

/* No spinner on a server */
class SilentProgress: public XcaProgress_i
{
  public:
	void start(const QString &, int) override { }
	void stop() override { }
	void increment() override { }
};

void initObjects()
{
	QStringList errors;
	ServerWarning::collect = &errors;
	try {
		initOIDs();
	} catch (errorEx &err) {
		errors << err.getString();
	}
	ServerWarning::collect = nullptr;
	if (!errors.isEmpty())
		throw serviceError("oid_init_failed", QObject::tr(
			"The OID initialisation failed: %1")
			.arg(errors.join("; ")));
}

ServiceContext serverContext()
{
	return ServiceContext::localUser(ServiceContext::rest);
}

qint64 count(const QString &sql)
{
	XSqlQuery q;
	SQL_PREPARE(q, sql);
	execOrThrow(q, "status");
	return q.next() ? q.value(0).toLongLong() : 0;
}

qint64 countItems(const QList<enum pki_type> &types)
{
	QStringList t;
	for (enum pki_type type : types)
		t << QString::number(int(type));
	return count(QString("SELECT COUNT(*) FROM items WHERE del=0 AND "
			"type IN (%1)").arg(t.join(",")));
}

}

void installHooks()
{
	xcaWarning::setGui(new ServerWarning());
	XcaProgress::setGui(new SilentProgress());
}

QJsonObject openSession(const Config &config, const QString &httpLibrary)
{
	initObjects();
	Settings.clear();
	if (!QFileInfo::exists(config.databasePath))
		throw serviceError("no_database", QObject::tr(
			"The database '%1' does not exist; bxc-pki init "
			"creates it").arg(config.databasePath));
	/* entries without a caller, e.g. an upgrade baseline */
	ServiceContext::processChannel = ServiceContext::rest;
	database_model::open_without_password = false;
	try {
		Database.open(config.databasePath);
	} catch (enum open_result r) {
		if (r == open_abort)
			throw serviceError("no_database", QObject::tr(
				"The database '%1' was not opened")
				.arg(config.databasePath));
		throw secretError(secretError::missing, QObject::tr(
			"The password input for '%1' was cancelled")
			.arg(config.databasePath),
			pass_info::DatabasePassword);
	}
	if (database_model::read_only) {
		Database.close();
		throw serviceError("read_only_database", QObject::tr(
			"The database '%1' is read-only; xca-server needs to "
			"write its audit entries").arg(config.databasePath));
	}
	try {
		AuditLog::append(serverContext(), AuditLog::actionServerStart,
			"database", QString(), AuditParams()
				.set("listen_address", config.listenAddress)
				.set("listen_port", config.listenPort)
				.set("http_library", httpLibrary)
				.set("pid", QCoreApplication::applicationPid()));
	} catch (...) {
		Database.close();
		throw;
	}
	return QJsonObject{ { "database", Database.name() } };
}

QJsonObject statusJob(const QString &actor)
{
	if (!Database.isOpen())
		throw serviceError("no_database",
			QObject::tr("No database is open"));
	QJsonObject objects {
		{ "keys", countItems({ asym_key, smartCard }) },
		{ "requests", countItems({ x509_req }) },
		{ "certificates", countItems({ x509 }) },
		{ "crls", countItems({ revocation }) },
		{ "templates", countItems({ tmpl }) },
	};
	return QJsonObject {
		{ "actor", actor },
		{ "channel", ServiceContext::channelName(
					ServiceContext::rest) },
		{ "on_worker", DbWorker::isWorkerThread() },
		{ "database", Database.name() },
		{ "schema_version", XSqlQuery::schemaVersion() },
		{ "bxc_schema_version", count("SELECT value FROM settings "
					"WHERE key_='bxc_schema'") },
		{ "read_only", database_model::read_only },
		{ "objects", objects },
		{ "audit_entries", count("SELECT COUNT(*) FROM audit_log") },
	};
}

QJsonObject closeSession()
{
	if (!Database.isOpen())
		return QJsonObject{ { "stop_entry", false } };
	try {
		AuditLog::append(serverContext(), AuditLog::actionServerStop,
			"database", QString(), AuditParams()
				.set("pid", QCoreApplication::applicationPid()));
	} catch (...) {
		Database.close();
		pki_export::free_elements();
		throw;
	}
	Database.close();
	pki_export::free_elements();
	return QJsonObject{ { "stop_entry", true } };
}

}
