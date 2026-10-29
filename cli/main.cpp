/* vi: set sw=4 ts=4:
 *
 * bxc-pki main (BTD-41): process setup, OID initialisation, database,
 * secrets, dispatch, output and errors. See cli/README.md.
 */

#include <QCoreApplication>
#include <QDebug>
#include <QFileInfo>

#include <openssl/provider.h>
#include <openssl/ui.h>

#include "local.h"
#include "lib/database_model.h"
#include "lib/debug_info.h"
#include "lib/entropy.h"
#include "lib/func.h"
#include "lib/func_base.h"
#include "lib/json_report.h"
#include "lib/oid.h"
#include "lib/PwDialogCore.h"
#include "lib/settings.h"
#include "lib/XcaProgress.h"
#include "lib/XcaWarningCore.h"
#include "cli.h"

using namespace bxcpki;

/* Messages to stderr as text (stdout carries only results); remembers
 * the last SQL error for the cause of a write error (rule 11) and the
 * errors of the OID initialisation */
class CliWarning: public xcaWarningCore
{
  public:
	static QString lastSqlError;
	static QStringList *collect;

	void sqlerror(QSqlError err) override
	{
		lastSqlError = err.text();
		xcaWarningCore::sqlerror(err);
	}
	void error(const QString &msg) override
	{
		if (collect)
			*collect << msg;
		print_cmdline(COL_RED "Error", msg);
	}
};
QString CliWarning::lastSqlError;
QStringList *CliWarning::collect;

/* No spinner: a script reads stdout and stderr */
class SilentProgress: public XcaProgress_i
{
  public:
	void start(const QString &, int) override { }
	void stop() override { }
	void increment() override { }
};

static int uiwriter(UI *, UI_STRING *)
{
	/* OpenSSL never prompts on the terminal of a headless tool */
	return 1;
}

static QString defaultDatabase()
{
	return QString("./bxc-pki.xdb");
}

/* The error document or text on stderr; returns the exit code */
static int report(const errorEx &err, const CommandContext &ctx)
{
	QJsonObject doc = JsonReport::error(err);
	QString code = doc["code"].toString();
	QString detail = err.getString();
	const secretError *pw = dynamic_cast<const secretError *>(&err);

	if (pw) {
		QString o = optionForPurpose(pw->purpose);
		if (!o.isEmpty())
			detail += QObject::tr(" (option %1)").arg(o);
	}
	/* rule 11: a write error names the object and the cause */
	if ((code == "internal_error" || code == "database_error") &&
	    !CliWarning::lastSqlError.isEmpty()) {
		code = "database_error";
		detail += QObject::tr(" (database: %1)")
				.arg(CliWarning::lastSqlError);
	}
	if (!ctx.step.isEmpty())
		detail = QObject::tr("%1 was not written to %2: %3")
			.arg(ctx.step).arg(ctx.database).arg(detail);
	if (ctx.text)
		console_write(stderr, QString("Error: %1 [%2]\n")
				.arg(detail).arg(code).toUtf8());
	else
		JsonReport::write(stderr, JsonReport::error(code, detail));
	return dynamic_cast<const usageError *>(&err) ? exitUsage :
							exitFailure;
}

/* OID initialisation; any error stops every command before the
 * database is touched (lib/main.cpp of xca only reports it) */
static void initObjects()
{
	QStringList errors;
	CliWarning::collect = &errors;
	try {
		initOIDs();
	} catch (errorEx &err) {
		errors << err.getString();
	}
	CliWarning::collect = nullptr;
	if (!errors.isEmpty())
		throw serviceError("oid_init_failed", QObject::tr(
			"The OID initialisation failed: %1")
			.arg(errors.join("; ")));
}

static void setupSecrets(const Options &o)
{
	PwDialogHeadless *h = PwDialogCore::headless();
	h->setInteractive(o.has("interactive"));
	for (const OptionSpec &spec : Registry::globalOptions())
		for (enum pass_info::purpose p : spec.purposes)
			h->setSource(p, o.value(spec.name));
}

static void openDatabase(const Command &cmd, CommandContext &ctx)
{
	const Options &o = ctx.opts;
	ctx.database = o.value("db", defaultDatabase());
	bool exists = QFileInfo::exists(ctx.database);
	bool pw = o.has("password") || o.has("interactive");

	/* No database file appears for a command that cannot go on */
	if (!exists && !cmd.writes)
		throw serviceError("no_database", QObject::tr(
			"The database '%1' does not exist").arg(ctx.database));
	if (!exists && !pw)
		throw secretError(secretError::missing, QObject::tr(
			"A new database '%1' needs a database password")
			.arg(ctx.database), pass_info::DatabasePassword);

	Passwd sqlpw;
	if (o.has("sqlpass"))
		sqlpw = PwDialogCore::headless()->secret(pass_info::SqlPassword);
	/* Without --password only public objects can be read (BTD-78) */
	database_model::open_without_password = !o.has("password") &&
						!o.has("interactive");
	ServiceContext::processChannel = ServiceContext::cli;
	try {
		Database.open(ctx.database, sqlpw);
	} catch (enum open_result r) {
		throw serviceError("database_error", QObject::tr(
			"The database '%1' was not opened (%2)")
			.arg(ctx.database).arg((int)r));
	}
	database_model::open_without_password = false;
	ctx.svc = ServiceContext::localUser(ServiceContext::cli);
}

static int run(const QStringList &argv)
{
	Registry &reg = Registry::instance();
	CommandContext ctx;
	ctx.text = argv.contains("--text");

	try {
		if (argv.isEmpty() || argv[0] == "--help" || argv[0] == "-h") {
			console_write(stdout, helpText().toUtf8());
			return exitOk;
		}
		if (argv[0] == "help") {
			const Command *c = argv.size() > 1 ?
					reg.find(argv[1]) : nullptr;
			if (argv.size() > 1 && !c)
				throw usageError("unknown_command", QObject::tr(
					"Unknown command '%1'").arg(argv[1]));
			console_write(stdout, (c ? commandHelp(*c) :
						helpText()).toUtf8());
			return exitOk;
		}
		if (argv[0] == "--version") {
			console_write(stdout, QString("bxc-pki %1\n")
				.arg(version_str(false)).toUtf8());
			return exitOk;
		}
		const Command *cmd = reg.find(argv[0]);
		if (!cmd)
			throw usageError("unknown_command", QObject::tr(
				"Unknown command '%1'; see bxc-pki --help")
				.arg(argv[0]));
		ctx.opts = parseOptions(*cmd, argv.mid(1));
		if (ctx.opts.has("help")) {
			console_write(stdout, commandHelp(*cmd).toUtf8());
			return exitOk;
		}
		ctx.plan = ctx.opts.has("plan");
		JsonReport::setActive(!ctx.text);

		initObjects();
		setupSecrets(ctx.opts);
		ctx.openDatabase = [cmd, &ctx]() { openDatabase(*cmd, ctx); };
		if (cmd->needsDatabase)
			ctx.openDatabase();

		if (!cmd->writes) {
			cmd->handler(ctx);
			return exitOk;
		}
		ResultCollector result(cmd->name, ctx.plan);
		ctx.result = &result;
		CliWarning::lastSqlError.clear();
		runInTransaction(ctx, { cmd->handler });
		if (ctx.text)
			console_write(stdout, result.text().toUtf8());
		else
			JsonReport::write(stdout, result.document());
		return exitOk;
	} catch (errorEx &err) {
		return report(err, ctx);
	} catch (enum open_result r) {
		return report(serviceError("database_error", QObject::tr(
			"The database was not opened (%1)").arg((int)r)), ctx);
	}
}

int main(int argc, char *argv[])
{
	debug_info::init();
	QCoreApplication app(argc, argv);
	/* The data and settings directories of XCA (oids.txt, eku.txt) */
	app.setApplicationName("de.hohnstaedt.xca");
	app.setOrganizationDomain("hohnstaedt.de");
	app.setApplicationVersion(XCA_VERSION);

	OSSL_PROVIDER_try_load(nullptr, "legacy", 1);
	ign_openssl_error();
	UI_METHOD *ui = UI_create_method("bxc-pki");
	UI_method_set_writer(ui, uiwriter);
	UI_set_default_method(ui);

	xcaWarning::setGui(new CliWarning());
	XcaProgress::setGui(new SilentProgress());
	registerCommands(Registry::instance());
	Settings.clear();

	int ret;
	{
		Entropy entropy;
		QStringList args = app.arguments().mid(1);
		ret = run(args);
		Database.close();
	}
	UI_set_default_method(UI_OpenSSL());
	UI_destroy_method(ui);
	return ret;
}
