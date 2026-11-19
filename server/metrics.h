/* vi: set sw=4 ts=4:
 *
 * The metrics of xca-server (BTD-163): GET /v1/metrics in the Prometheus
 * text format 0.0.4. Names and labels: server/METRICS.md.
 *
 * Two parts:
 * - databaseText() runs on the DB worker: the counters of the audit log
 *   (cached for metrics.audit_cache_s; after the first full count only
 *   the entries after the last counted seq are read, the log is
 *   append-only), the remaining lifetime of the certificates and the age
 *   of the last audit checkpoint;
 * - processText() runs on the request thread: request latency per
 *   operation, the DB queue length and how the worker calls ended.
 * Labels hold ids, serials and fingerprints only, never a subject.
 */

#ifndef __XCA_SERVER_METRICS_H
#define __XCA_SERVER_METRICS_H

#include <chrono>
#include <map>
#include <mutex>
#include <tuple>
#include <vector>

#include <QString>

#include "config.h"

namespace xcaserver {

class DbWorker;

class Metrics
{
	const MetricsLimits limits;

	/* request latency, one histogram per operation id; any thread */
	class Histogram
	{
	  public:
		std::vector<qint64> buckets{};
		qint64 count{};
		double sum{};
	};
	std::mutex latencyMutex{};
	std::map<QString, Histogram> latency{};

	/* the audit counters; on the DB worker only */
	using Key = std::tuple<QString, QString, QString>;  // action, channel, result
	std::map<Key, qint64> audit{};
	qint64 auditSeq{};
	bool auditCounted{};
	std::chrono::steady_clock::time_point auditAt{};

	void refreshAudit();

  public:
	static const std::vector<double> latencyBuckets;

	explicit Metrics(const MetricsLimits &l) : limits(l)
	{
	}
	/* One request of operationId took seconds; any thread */
	void observe(const QString &operationId, double seconds);
	/* The values that need the database; on the DB worker only */
	QString databaseText();
	/* The values of this process; any thread */
	QString processText(DbWorker &worker);
};

}

#endif
