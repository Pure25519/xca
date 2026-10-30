/* vi: set sw=4 ts=4:
 *
 * bxc-pki main (BTD-41): process setup, OID initialisation, database,
 * secrets, dispatch, output and errors. See cli/README.md.
 */

#include <QCoreApplication>
#include <QDebug>
#include <QFile>
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

#ifdef BXC_PKI_FAULTS
#include <cstdio>
#include <unistd.h>
#include <QDir>
#include "lib/staged_file.h"

/* The directory of a target (a directory target itself, else the one it
 * is in) is renamed to <dir>.moved and replaced by a symbolic link to
 * <dir>.other (created if missing): a swap between stage and publish */
static void swapDirectory(const QString &target)
{
	QFileInfo t(target);
	QString dir = t.isDir() && !t.isSymLink() ? t.absoluteFilePath() :
			t.absolutePath();
	QByteArray d = QFile::encodeName(dir);
	QDir().mkpath(dir + ".other");
	if (::rename(d.constData(), (d + ".moved").constData()) == 0)
		(void)::symlink((d + ".other").constData(), d.constData());
}

/* Test build only (bxc-pki-faults, BTD-42, BTD-210):
 * BXC_PKI_FAULT=<mode>:<step>:<text>, several separated by ",", acts at
 * the step (create, owner_check, probe, write, sync, publish, noreplace,
 * unlink, recheck, swap) of every staged file or directory whose target
 * contains <text>: the step fails (mode fail), the process ends there with
 * exit code 137 like a killed run (mode kill), at the step swap of a
 * directory the file late.txt is added to it (mode addfile), the target
 * file appears with the content "late" (mode addtarget), or the directory
 * of the target is swapped for a symbolic link (mode swapdir) */
static void installFaults()
{
	QList<QStringList> faults;
	for (const QString &spec : QString::fromLocal8Bit(
			qgetenv("BXC_PKI_FAULT")).split(',', Qt::SkipEmptyParts)) {
		QStringList f = spec.split(':');
		if (f.size() == 3)
			faults << f;
	}
	if (faults.isEmpty())
		return;
	StagedFile::faultHook = [faults](enum StagedFile::step s,
				const QString &target) {
		bool failStep = false;
		for (const QStringList &f : faults) {
			if (StagedFile::stepName(s) != f[1] ||
			    !target.contains(f[2]))
				continue;
			if (f[0] == "kill")
				_exit(137);
			if (f[0] == "addfile" || f[0] == "addtarget") {
				/* a file that appears in the target directory,
				 * or the target itself */
				QFile late(f[0] == "addfile" ?
					target + "/late.txt" : target);
				if (late.open(QIODevice::WriteOnly))
					late.write("late\n");
			} else if (f[0] == "swapdir") {
				swapDirectory(target);
			} else {
				failStep = true;
			}
		}
		return failStep;
	};
}
#endif

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
		/* the cause, without the statement and its values */
		lastSqlError = err.databaseText().trimmed();
		if (lastSqlError.isEmpty())
			lastSqlError = err.driverText().trimmed();
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
	/* rule 11: a write error names the object and the cause; the
	 * code stays the one of the error (review of xca#54) */
	if (code == "database_error" && !CliWarning::lastSqlError.isEmpty())
		detail += QObject::tr(" (database: %1)")
				.arg(CliWarning::lastSqlError);
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

/* The open results of database_model (review of xca#54): a cancelled
 * or ended password input is missing_password, no database no_database */
[[noreturn]] static void throwOpenError(enum open_result r,
		const QString &db)
{
	if (r == open_abort)
		throw serviceError("no_database", QObject::tr(
			"No database was given or '%1' was not opened").arg(db));
	throw secretError(secretError::missing, QObject::tr(
		"The password input for '%1' was cancelled").arg(db),
		pass_info::DatabasePassword);
}

static void openDatabase(const Command &cmd, CommandContext &ctx)
{
	const Options &o = ctx.opts;
	PwDialogHeadless *h = PwDialogCore::headless();
	/* bootstrap sets the database (and its password sources) from its
	 * file before it opens it (BTD-166) */
	if (ctx.database.isEmpty())
		ctx.database = o.value("db", defaultDatabase());
	/* user@host/db#QPSQL7 and the like: the server knows (review of
	 * xca#54) */
	bool remote = database_model::isRemoteDB(ctx.database);
	bool exists = remote || QFileInfo::exists(ctx.database);
	bool pw = h->hasSource(pass_info::DatabasePassword) ||
			o.has("interactive");

	/* Only init and bootstrap (not --plan) create a database */
	if (!exists && (!cmd.createsDatabase || ctx.plan))
		throw serviceError("no_database", QObject::tr(
			"The database '%1' does not exist; init creates it")
			.arg(ctx.database));
	if (!exists && !pw)
		throw secretError(secretError::missing, QObject::tr(
			"A new database '%1' needs a database password")
			.arg(ctx.database), pass_info::DatabasePassword);

	Passwd sqlpw;
	if (h->hasSource(pass_info::SqlPassword))
		sqlpw = h->secret(pass_info::SqlPassword);
	/* Without --password only public objects can be read (BTD-78) */
	database_model::open_without_password = !pw;
	ServiceContext::processChannel = ServiceContext::cli;
	try {
		Database.open(ctx.database, sqlpw);
	} catch (enum open_result r) {
		throwOpenError(r, ctx.database);
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
		ctx.command = cmd->name;
		JsonReport::setActive(!ctx.text);

		initObjects();
		CliWarning::lastSqlError.clear();
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
		OutputFiles files(ctx.opts.has("force"), ctx.plan);
		ctx.files = &files;
		if (cmd->ownTransaction)
			cmd->handler(ctx);
		else
			runInTransaction(ctx, { cmd->handler });
		if (ctx.text)
			console_write(stdout, result.text().toUtf8());
		else
			JsonReport::write(stdout, result.document());
		return exitOk;
	} catch (errorEx &err) {
		return report(err, ctx);
	} catch (enum open_result r) {
		/* anything that still throws an open result */
		if (r == open_abort)
			return report(serviceError("no_database", QObject::tr(
				"No database was given")), ctx);
		return report(secretError(secretError::missing, QObject::tr(
			"The password input was cancelled"),
			pass_info::DatabasePassword), ctx);
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
#ifdef BXC_PKI_FAULTS
	installFaults();
#endif
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
