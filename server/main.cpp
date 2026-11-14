/* vi: set sw=4 ts=4:
 *
 * xca-server (BTD-154): the REST server of the bxc-pki fork.
 *
 *   xca-server --config <xca-server.json>            start
 *   xca-server --config <xca-server.json> --check-config
 *   xca-server --version
 *
 * Start: the configuration is checked, the lock <database>.lock is taken
 * (database_in_use if another process holds it), the TLS server is set up
 * with the client CA (mTLS: no handshake without a client certificate of
 * that CA) and bound, the DB worker opens the database and writes
 * server.start, then the server answers until SIGTERM or SIGINT. Stop:
 * no new connections, the running job finishes, the worker writes
 * server.stop and closes the database, the lock is released, exit 0.
 *
 * Exit codes: 0 ok, 1 an error at run time, 2 a refused configuration or
 * command line and database_in_use. Errors are one JSON error object on
 * stderr (the form of bxc-pki), e.g. {"code":"invalid_config",
 * "detail":"/limits/queue_max: required member is missing",...}.
 */

#include <atomic>
#include <chrono>
#include <csignal>
#include <memory>
#include <thread>

#include <QCoreApplication>
#include <QStringList>

#include <openssl/crypto.h>
#include <openssl/provider.h>
#include <openssl/ui.h>

#include "local.h"
#include "lib/audit.h"
#include "lib/database_lock.h"
#include "lib/debug_info.h"
#include "lib/func.h"
#include "lib/func_base.h"
#include "lib/json_report.h"
#include "lib/pki_export.h"

#include "config.h"
#include "session.h"
#include "worker.h"
/* last: sys/param.h of the header redefines MIN of lib/base.h, which
 * is quiet only in this order (system header) */
#include "routes.h"

using namespace xcaserver;

namespace {

const int exitOk = 0;
const int exitFailure = 1;
const int exitConfig = 2;

std::atomic<int> stopSignal{ 0 };

extern "C" void onStopSignal(int sig)
{
	stopSignal = sig;
}

int fail(const QString &code, const QString &detail, int rc = exitFailure)
{
	JsonReport::write(stderr, JsonReport::error(code, detail));
	return rc;
}

int configError(const ConfigError &e)
{
	return fail("invalid_config", e.detail(), exitConfig);
}

int uiwriter(UI *, UI_STRING *)
{
	/* OpenSSL never prompts on a server */
	return 1;
}

QString httpLibrary()
{
	return QString("cpp-httplib %1").arg(CPPHTTPLIB_VERSION);
}

QString usage()
{
	return QObject::tr("usage: xca-server --config <xca-server.json> "
			"[--check-config] | --version");
}

int serve(const Config &config)
{
	try {
		config.checkFiles();
	} catch (ConfigError &e) {
		return configError(e);
	}
	/* the database belongs to this process until it stops; the kernel
	 * releases the lock when the process ends, also after SIGKILL
	 * (BTD-302) */
	std::unique_ptr<DatabaseLock> lock;
	try {
		lock.reset(new DatabaseLock(config.databasePath,
				DatabaseLock::Exclusive));
	} catch (errorEx &e) {
		return fail("database_in_use", e.getString(), exitConfig);
	}

	httplib::SSLServer srv(config.tlsCert.toLocal8Bit().constData(),
			config.tlsKey.toLocal8Bit().constData(),
			config.tlsClientCa.toLocal8Bit().constData());
	if (!srv.is_valid())
		return fail("invalid_config", QObject::tr("/tls: the "
			"certificate, key or client CA cannot be loaded"),
			exitConfig);
	DbWorker worker(config.databasePassword,
			size_t(config.limits.queueMax));
	installRoutes(srv, worker, config);
	if (!srv.bind_to_port(config.listenAddress.toStdString(),
				config.listenPort))
		return fail("listen_failed", QObject::tr("Cannot listen on "
			"%1:%2").arg(config.listenAddress)
			.arg(config.listenPort));

	/* a stop signal during the open stops right after it */
	std::signal(SIGTERM, onStopSignal);
	std::signal(SIGINT, onStopSignal);
	worker.start();
	JobResult opened = worker.call([&config]() {
		return openSession(config, httpLibrary());
	});
	if (opened.state != JobResult::done) {
		worker.shutdown([]() { return closeSession(); });
		return fail(opened.code, opened.detail);
	}

	std::atomic<bool> listening{ true };
	/* stop() is not async-signal-safe: a thread watches the flag */
	std::thread watcher([&srv, &listening]() {
		while (listening && !stopSignal)
			std::this_thread::sleep_for(
				std::chrono::milliseconds(50));
		srv.stop();
	});
	bool ok = srv.listen_after_bind();
	listening = false;
	watcher.join();
	std::signal(SIGTERM, SIG_DFL);
	std::signal(SIGINT, SIG_DFL);

	JobResult closed = worker.shutdown([]() { return closeSession(); });
	lock.reset();
	if (closed.state != JobResult::done)
		return fail(closed.code, closed.detail);
	if (!ok && !stopSignal)
		return fail("listen_failed", QObject::tr("The server stopped "
			"listening on %1:%2").arg(config.listenAddress)
			.arg(config.listenPort));
	return exitOk;
}

int run(const QStringList &args)
{
	QString file;
	bool check = false;
	for (int i = 0; i < args.size(); i++) {
		const QString &a = args[i];
		if (a == "--version") {
			console_write(stdout, QString("xca-server %1 (%2, %3)\n")
				.arg(version_str(false)).arg(httpLibrary())
				.arg(OpenSSL_version(OPENSSL_VERSION)).toUtf8());
			return exitOk;
		} else if (a == "--help" || a == "-h") {
			console_write(stdout, (usage() + "\n").toUtf8());
			return exitOk;
		} else if (a == "--check-config") {
			check = true;
		} else if (a == "--config" && i + 1 < args.size()) {
			file = args[++i];
		} else if (a.startsWith("--config=")) {
			file = a.mid(9);
		} else {
			return fail("usage", QObject::tr("Unknown argument "
				"'%1'; %2").arg(a).arg(usage()), exitConfig);
		}
	}
	if (file.isEmpty())
		return fail("usage", usage(), exitConfig);
	Config config;
	try {
		config = Config::load(file);
	} catch (ConfigError &e) {
		return configError(e);
	}
	if (check)
		return exitOk;
	return serve(config);
}

}

int main(int argc, char *argv[])
{
	debug_info::init();
	QCoreApplication app(argc, argv);
	/* the data and settings directories of XCA (oids.txt, eku.txt) */
	app.setApplicationName("de.hohnstaedt.xca");
	app.setOrganizationDomain("hohnstaedt.de");
	app.setApplicationVersion(XCA_VERSION);

	OSSL_PROVIDER_try_load(nullptr, "legacy", 1);
	ign_openssl_error();
	UI_METHOD *ui = UI_create_method("xca-server");
	UI_method_set_writer(ui, uiwriter);
	UI_set_default_method(ui);
	installHooks();
	JsonReport::setActive(true);

	int ret = run(app.arguments().mid(1));

	pki_export::free_elements();
	UI_set_default_method(UI_OpenSSL());
	UI_destroy_method(ui);
	return ret;
}
