/* vi: set sw=4 ts=4:
 *
 * The DB worker of xca-server (BTD-154), see worker.h.
 */

#include "worker.h"

#include <chrono>
#include <exception>

#include <QObject>

#include "lib/PwDialogCore.h"
#include "lib/entropy.h"
#include "lib/exception.h"
#include "lib/json_report.h"
#include "lib/pass_info.h"

namespace xcaserver {

thread_local bool DbWorker::onWorker = false;

DbWorker::DbWorker(const QString &source, size_t max)
	: passwordSource(source), queueMax(max)
{
	setObjectName("xca-server DB worker");
}

DbWorker::~DbWorker()
{
	if (isRunning())
		shutdown([]() { return QJsonObject(); });
}

JobResult DbWorker::execute(const Job &job)
{
	JobResult r;
	try {
		r.body = job();
		return r;
	} catch (errorEx &err) {
		QJsonObject e = JsonReport::error(err);
		r.code = e["code"].toString();
		r.detail = e["detail"].toString();
	} catch (enum open_result res) {
		if (res == open_abort) {
			r.code = "no_database";
			r.detail = QObject::tr("The database was not opened");
		} else {
			r.code = "missing_password";
			r.detail = QObject::tr("The database password input "
						"was cancelled");
		}
	} catch (std::exception &e) {
		r.code = "internal_error";
		r.detail = QString::fromLocal8Bit(e.what());
	} catch (...) {
		r.code = "internal_error";
		r.detail = QObject::tr("Unknown error");
	}
	r.state = JobResult::failed;
	return r;
}

void DbWorker::run()
{
	onWorker = true;
	/* The database password for every request of this thread: the
	 * open, and keys protected by the database password later on */
	PasswordSourceScope password(pass_info::DatabasePassword,
				passwordSource);
	Entropy entropy;
	for (;;) {
		Task task;
		{
			std::unique_lock<std::mutex> lock(mutex);
			cv.wait(lock, [this] {
				return stopping || !queue.empty();
			});
			if (queue.empty())
				return;
			task = std::move(queue.front());
			queue.pop_front();
		}
		task.result->set_value(execute(task.job));
	}
}

JobResult DbWorker::call(Job job, qint64 timeoutS)
{
	JobResult r;
	auto promise = std::make_shared<std::promise<JobResult>>();
	std::future<JobResult> result = promise->get_future();
	{
		std::lock_guard<std::mutex> lock(mutex);
		if (stopping) {
			r.state = JobResult::stopping;
			return r;
		}
		if (queue.size() >= queueMax) {
			r.state = JobResult::queueFull;
			return r;
		}
		queue.push_back(Task{ std::move(job), promise });
	}
	cv.notify_one();
	if (timeoutS > 0 && result.wait_for(std::chrono::seconds(timeoutS)) !=
				std::future_status::ready) {
		/* the job finishes on the worker; its promise is kept alive
		 * by the task */
		r.state = JobResult::timedOut;
		return r;
	}
	return result.get();
}

JobResult DbWorker::shutdown(Job last)
{
	if (!isRunning()) {
		JobResult r;
		r.state = JobResult::stopping;
		return r;
	}
	auto promise = std::make_shared<std::promise<JobResult>>();
	std::future<JobResult> result = promise->get_future();
	{
		std::lock_guard<std::mutex> lock(mutex);
		stopping = true;
		JobResult refused;
		refused.state = JobResult::stopping;
		for (Task &t : queue)
			t.result->set_value(refused);
		queue.clear();
		queue.push_back(Task{ std::move(last), promise });
	}
	cv.notify_one();
	JobResult r = result.get();
	wait();
	return r;
}

}
