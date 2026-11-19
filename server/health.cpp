/* vi: set sw=4 ts=4:
 *
 * The health listener of xca-server (BTD-163), see health.h.
 */

#include <algorithm>

#include "health.h"
#include "session.h"
#include "worker.h"
#ifdef BXC_PKI_TEST_SEAMS
#include "test_seams.h"
#endif
/* last: sys/param.h of the header redefines MIN of lib/base.h (routes.cpp) */
#include "routes.h"

namespace xcaserver {

Readiness::Readiness(DbWorker &w, qint64 jobTimeoutS)
	: worker(w), timeoutS(std::max<qint64>(1, std::min<qint64>(jobTimeoutS, 2))),
	  pending(std::make_shared<std::atomic<bool>>(false))
{
}

bool Readiness::ready()
{
	if (!started || !lastAuditWriteOk())
		return false;
	/* one readiness job at a time: a stuck worker does not fill its
	 * queue with probes */
	bool expected = false;
	if (!pending->compare_exchange_strong(expected, true))
		return false;
	std::shared_ptr<std::atomic<bool>> flag = pending;
	JobResult r = worker.call([flag]() {
		struct Done {
			std::shared_ptr<std::atomic<bool>> f;
			~Done() { *f = false; }
		} done{ flag };
		return readyJob();
	}, timeoutS);
	if (r.state == JobResult::queueFull || r.state == JobResult::stopping)
		*pending = false;
	return r.state == JobResult::done && !r.body["read_only"].toBool();
}

void installHealth(httplib::Server &srv, Readiness &readiness, DbWorker &worker)
{
	(void)worker;
	/* no request has a body here */
	srv.set_payload_max_length(1);
	srv.set_keep_alive_max_count(1);
	srv.set_pre_routing_handler([&readiness, &worker](
			const httplib::Request &req, httplib::Response &res) {
		(void)worker;
		bool get = req.method == "GET";
		if (get && req.path == "/health") {
			res.status = 200;
			res.set_content("{\"status\":\"ok\"}", "application/json");
		} else if (get && req.path == "/ready") {
			bool ok = readiness.ready();
			res.status = ok ? 200 : 503;
			res.set_content(ok ? "{\"status\":\"ok\"}" :
				"{\"status\":\"not_ready\"}", "application/json");
#ifdef BXC_PKI_TEST_SEAMS
		} else if (ServerTestSeams::handle(req, res, worker)) {
#endif
		} else {
			res.status = 404;
		}
		return httplib::Server::HandlerResponse::Handled;
	});
	srv.set_error_handler([](const httplib::Request &, httplib::Response &) {
		/* the library's own answers (400, 413, 408) stay without a
		 * body; /ready keeps its 503 body */
		return httplib::Server::HandlerResponse::Handled;
	});
}

}
