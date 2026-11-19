/* vi: set sw=4 ts=4:
 *
 * Test seams of xca-server (BTD-163), see test_seams.h. Without
 * BXC_PKI_TEST_SEAMS this file compiles to nothing.
 */

#ifdef BXC_PKI_TEST_SEAMS

#include <cstdlib>
#include <thread>

#include <QJsonObject>
#include <QThread>

#include "test_seams.h"
#include "worker.h"
/* last: sys/param.h of the header redefines MIN of lib/base.h */
#include "routes.h"

namespace xcaserver {

namespace ServerTestSeams {

bool handle(const httplib::Request &req, httplib::Response &res,
		DbWorker &worker)
{
	const char *on = std::getenv("BXC_PKI_TEST_SEAMS");
	if (!on || std::string(on) != "1")
		return false;
	if (req.method != "POST" || req.path != "/_test/stall")
		return false;
	int seconds = std::atoi(req.get_param_value("seconds").c_str());
	if (seconds < 1 || seconds > 60) {
		res.status = 400;
		return true;
	}
	/* the worker runs the job; this thread only queues it */
	std::thread([&worker, seconds]() {
		worker.call([seconds]() {
			QThread::sleep(seconds);
			return QJsonObject();
		});
	}).detach();
	res.status = 202;
	return true;
}

}

}

#endif
