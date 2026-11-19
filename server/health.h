/* vi: set sw=4 ts=4:
 *
 * The health listener of xca-server (BTD-163): plain HTTP, loopback unless
 * allow_remote, for container probes that have no client certificate.
 *
 *   GET /health  200 {"status":"ok"}: the process answers; no database job
 *   GET /ready   200 {"status":"ok"} or 503 {"status":"not_ready"}
 *
 * Every other method or path is 404 without a body; all of it is answered
 * before routing, so no request body is read. Ready means: the server has
 * started (database opened, TLS listener bound), a readiness job (the write
 * lock an audit entry needs) answers on the DB worker within
 * min(job_timeout_s, 2) seconds, the database is not read-only and the last
 * audit entry of the server was written. Only one readiness job is queued
 * at a time; while it is pending the answer is not ready.
 */

#ifndef __XCA_SERVER_HEALTH_H
#define __XCA_SERVER_HEALTH_H

#include <atomic>
#include <memory>

#include <QtGlobal>

namespace httplib {
class Server;
}

namespace xcaserver {

class DbWorker;

class Readiness
{
	DbWorker &worker;
	const qint64 timeoutS;
	std::shared_ptr<std::atomic<bool>> pending;
	std::atomic<bool> started{};

  public:
	Readiness(DbWorker &w, qint64 jobTimeoutS);
	/* the database is open and the TLS listener bound */
	void setStarted()
	{
		started = true;
	}
	/* any thread */
	bool ready();
};

/* /health, /ready and 404 for the rest on srv */
void installHealth(httplib::Server &srv, Readiness &readiness, DbWorker &worker);

}

#endif
