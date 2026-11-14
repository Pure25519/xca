/* vi: set sw=4 ts=4:
 *
 * The DB worker of xca-server (BTD-154, bxc-pki
 * docs/xca-server-architecture.md).
 *
 * lib/ keeps process-global state (Database, Store, Settings, the default
 * QSqlDatabase connection, which Qt allows only in the thread that opened
 * it). One QThread therefore owns all of it: it opens the database, runs
 * every job one at a time, writes the stop entry and closes the database.
 * The HTTP pool threads never call lib/; they submit a job and wait for
 * its result.
 *
 * The queue is bounded (queue_max): a full queue refuses the job at once.
 * A job that does not finish within the job timeout is reported as timed
 * out to its caller; it still finishes (and is audited) on the worker.
 */

#ifndef __XCA_SERVER_WORKER_H
#define __XCA_SERVER_WORKER_H

#include <condition_variable>
#include <deque>
#include <functional>
#include <future>
#include <memory>
#include <mutex>

#include <QJsonObject>
#include <QString>
#include <QThread>

namespace xcaserver {

/* What a job gave back: a JSON body, or the error code and its text */
class JobResult
{
  public:
	enum state { done, failed, queueFull, timedOut, stopping };
	enum state state{ done };
	QJsonObject body{};
	QString code{};
	QString detail{};
};

class DbWorker: public QThread
{
	using Job = std::function<QJsonObject()>;
	struct Task
	{
		Job job;
		std::shared_ptr<std::promise<JobResult>> result;
	};

	const QString passwordSource;
	const size_t queueMax;
	std::mutex mutex{};
	std::condition_variable cv{};
	std::deque<Task> queue{};
	bool stopping{};
	/* the thread id of the worker, for on_worker */
	static thread_local bool onWorker;

	void run() override;
	static JobResult execute(const Job &job);

  public:
	/* passwordSource answers the database password (env: or file:)
	 * for the whole run of the worker */
	DbWorker(const QString &passwordSource, size_t queueMax);
	~DbWorker();

	/* Queues job and waits at most timeoutS seconds (0: no limit) for
	 * its result; queueFull, stopping and timedOut without waiting
	 * longer. Any thread but the worker. */
	JobResult call(Job job, qint64 timeoutS = 0);
	/* Stops accepting jobs, refuses the queued ones (stopping), lets
	 * the running job finish, runs last on the worker and waits for the
	 * end of the thread. Returns the result of last. */
	JobResult shutdown(Job last);
	/* true on the worker thread */
	static bool isWorkerThread()
	{
		return onWorker;
	}
};

}

#endif
