/* vi: set sw=4 ts=4:
 *
 * The metrics of xca-server (BTD-163), see metrics.h and METRICS.md.
 */

#include "metrics.h"

#include <algorithm>
#include <limits>
#include <set>

#include <QCryptographicHash>
#include <QDateTime>
#include <QMap>
#include <QStringList>

#include "lib/database_model.h"
#include "lib/exception.h"
#include "lib/pki_lookup.h"
#include "lib/pki_x509.h"
#include "lib/sql.h"

#include "session.h"
#include "worker.h"

namespace xcaserver {

const std::vector<double> Metrics::latencyBuckets{ 0.005, 0.01, 0.025, 0.05,
	0.1, 0.25, 0.5, 1, 2.5, 5, 10 };

namespace {

/* A label value of the text format: backslash, quote and newline escaped */
QString label(const QString &value)
{
	QString v = value;
	v.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
	return "\"" + v + "\"";
}

/* The HELP and TYPE lines of a family */
void family(QStringList &out, const char *name, const char *type,
		const char *help)
{
	out << QString("# HELP %1 %2").arg(name, help)
	    << QString("# TYPE %1 %2").arg(name, type);
}

QString number(double v)
{
	if (v == std::numeric_limits<double>::infinity())
		return "+Inf";
	return QString::number(v, 'g', 15);
}

}

void Metrics::observe(const QString &operationId, double seconds)
{
	std::lock_guard<std::mutex> lock(latencyMutex);
	Histogram &h = latency[operationId];
	if (h.buckets.empty())
		h.buckets.assign(latencyBuckets.size(), 0);
	for (size_t i = 0; i < latencyBuckets.size(); i++)
		if (seconds <= latencyBuckets[i])
			h.buckets[i]++;
	h.count++;
	h.sum += seconds;
}

void Metrics::refreshAudit()
{
	auto now = std::chrono::steady_clock::now();
	if (auditCounted && now - auditAt <
			std::chrono::seconds(limits.auditCacheS))
		return;
	XSqlQuery q;
	SQL_PREPARE(q, "SELECT MAX(seq) FROM audit_log");
	execOrThrow(q, "audit size");
	qint64 last = q.next() ? q.value(0).toLongLong() : 0;
	if (last < auditSeq) {
		/* another database or a rewritten log: count again */
		audit.clear();
		auditSeq = 0;
	}
	/* the log is append-only: only the entries after the last count */
	SQL_PREPARE(q, "SELECT action, channel, result, COUNT(*), MAX(seq) "
		"FROM audit_log WHERE seq > ? GROUP BY action, channel, result");
	q.bindValue(0, auditSeq);
	execOrThrow(q, "audit counters");
	qint64 seen = auditSeq;
	while (q.next()) {
		Key k{ q.value(0).toString(), q.value(1).toString(),
			q.value(2).toString() };
		audit[k] += q.value(3).toLongLong();
		seen = std::max(seen, q.value(4).toLongLong());
	}
	auditSeq = seen;
	auditCounted = true;
	auditAt = now;
}

QString Metrics::databaseText()
{
	if (!Database.isOpen())
		throw serviceError("no_database",
			QObject::tr("No database is open"));
	QStringList out;

	/* the counters of the audit log */
	refreshAudit();
	family(out, "xca_audit_entries_total", "counter",
		"Audit log entries by action, channel and result.");
	std::map<QString, qint64> issued, revoked;
	std::map<std::pair<QString, QString>, qint64> errors;
	for (const auto &e : audit) {
		const QString &action = std::get<0>(e.first);
		const QString &channel = std::get<1>(e.first);
		const QString &result = std::get<2>(e.first);
		out << QString("xca_audit_entries_total{action=%1,channel=%2,"
			"result=%3} %4").arg(label(action), label(channel),
			label(result)).arg(e.second);
		if (result == "success" && action == "certificate.issue")
			issued[channel] += e.second;
		if (result == "success" && action == "certificate.revoke")
			revoked[channel] += e.second;
		if (result != "success")
			errors[{ channel, action }] += e.second;
	}
	family(out, "xca_issuances_total", "counter",
		"Certificates issued, by channel (audit action certificate.issue).");
	for (const auto &e : issued)
		out << QString("xca_issuances_total{channel=%1} %2")
			.arg(label(e.first)).arg(e.second);
	family(out, "xca_revocations_total", "counter",
		"Certificates revoked, by channel (audit action certificate.revoke).");
	for (const auto &e : revoked)
		out << QString("xca_revocations_total{channel=%1} %2")
			.arg(label(e.first)).arg(e.second);
	family(out, "xca_errors_total", "counter",
		"Audit entries with result failure or denied, by channel and action.");
	for (const auto &e : errors)
		out << QString("xca_errors_total{channel=%1,action=%2} %3")
			.arg(label(e.first.first), label(e.first.second))
			.arg(e.second);

	/* the remaining lifetime; a CA is named by its bootstrap id, else by
	 * its item id */
	QMap<qint64, QString> bootstrapIds;
	QMap<QString, qint64> cas = bootstrapCas();
	for (auto it = cas.begin(); it != cas.end(); ++it)
		if (!bootstrapIds.contains(it.value()))
			bootstrapIds[it.value()] = it.key();
	auto caId = [&bootstrapIds](const pki_x509 *ca) {
		if (!ca)
			return QString("none");
		qint64 item = ca->getSqlItemId().toLongLong();
		return bootstrapIds.value(item, QString("item-%1").arg(item));
	};
	QDateTime now = QDateTime::currentDateTimeUtc();
	QList<pki_x509 *> certs = Store.getAll<pki_x509>();
	bool limited = qint64(certs.size()) > limits.certificatesMax;
	QStringList caLines, certLines;
	std::map<QString, qint64> count, within7, within30;
	std::map<QString, qint64> minimum;
	for (pki_x509 *c : certs) {
		qint64 left = now.secsTo(c->getNotAfter());
		QString issuer = caId(c->getSigner());
		count[issuer]++;
		if (left >= 0 && left <= 7 * 86400)
			within7[issuer]++;
		if (left >= 0 && left <= 30 * 86400)
			within30[issuer]++;
		if (!minimum.count(issuer) || left < minimum[issuer])
			minimum[issuer] = left;
		if (c->isCA()) {
			QString fp = QString::fromLatin1(QCryptographicHash::hash(
				c->i2d(), QCryptographicHash::Sha256).toHex());
			caLines << QString("xca_ca_certificate_expiry_seconds{"
				"ca_id=%1,fingerprint=%2} %3").arg(label(caId(c)),
				label(fp)).arg(left);
		}
		if (!limited)
			certLines << QString("xca_certificate_expiry_seconds{"
				"ca_id=%1,serial=%2} %3").arg(label(issuer),
				label(c->getSerial().toHex())).arg(left);
	}
	family(out, "xca_ca_certificate_expiry_seconds", "gauge",
		"Seconds until the CA certificate expires (negative: expired).");
	out << caLines;
	family(out, "xca_certificate_expiry_seconds", "gauge",
		"Seconds until the certificate expires, by issuing CA and serial; "
		"only up to metrics.certificates_max certificates.");
	out << certLines;
	family(out, "xca_metrics_certificates_limited", "gauge",
		"1 when there are more certificates than metrics.certificates_max "
		"and only the per-CA values are given.");
	out << QString("xca_metrics_certificates_limited %1").arg(limited ? 1 : 0);
	family(out, "xca_certificates", "gauge",
		"Certificates by issuing CA.");
	for (const auto &e : count)
		out << QString("xca_certificates{ca_id=%1} %2")
			.arg(label(e.first)).arg(e.second);
	family(out, "xca_certificates_expiring", "gauge",
		"Certificates that expire within 7 or 30 days, by issuing CA.");
	for (const auto &e : count) {
		out << QString("xca_certificates_expiring{ca_id=%1,within=\"7d\"} %2")
			.arg(label(e.first)).arg(within7[e.first]);
		out << QString("xca_certificates_expiring{ca_id=%1,within=\"30d\"} %2")
			.arg(label(e.first)).arg(within30[e.first]);
	}
	family(out, "xca_certificate_min_expiry_seconds", "gauge",
		"The shortest remaining lifetime of the certificates of a CA.");
	for (const auto &e : minimum)
		out << QString("xca_certificate_min_expiry_seconds{ca_id=%1} %2")
			.arg(label(e.first)).arg(e.second);

	/* the last audit checkpoint (BTD-148) */
	XSqlQuery q;
	SQL_PREPARE(q, "SELECT created FROM audit_log WHERE action = "
		"'audit.checkpoint' ORDER BY seq DESC LIMIT 1");
	execOrThrow(q, "audit checkpoint");
	if (q.next()) {
		QDateTime at = QDateTime::fromString(q.value(0).toString(),
							Qt::ISODate);
		if (at.isValid()) {
			family(out, "xca_audit_checkpoint_age_seconds", "gauge",
				"Seconds since the last audit checkpoint entry.");
			out << QString("xca_audit_checkpoint_age_seconds %1")
				.arg(at.secsTo(now));
		}
	}
	return out.join('\n') + '\n';
}

QString Metrics::processText(DbWorker &worker)
{
	QStringList out;
	family(out, "xca_http_request_duration_seconds", "histogram",
		"Time from the role check to the answer, by operation id.");
	{
		std::lock_guard<std::mutex> lock(latencyMutex);
		for (const auto &e : latency) {
			QString op = label(e.first);
			for (size_t i = 0; i < latencyBuckets.size(); i++)
				out << QString("xca_http_request_duration_seconds_bucket"
					"{operation_id=%1,le=\"%2\"} %3").arg(op,
					number(latencyBuckets[i]))
					.arg(e.second.buckets[i]);
			out << QString("xca_http_request_duration_seconds_bucket"
				"{operation_id=%1,le=\"+Inf\"} %2").arg(op)
				.arg(e.second.count);
			out << QString("xca_http_request_duration_seconds_sum"
				"{operation_id=%1} %2").arg(op,
				number(e.second.sum));
			out << QString("xca_http_request_duration_seconds_count"
				"{operation_id=%1} %2").arg(op).arg(e.second.count);
		}
	}
	family(out, "xca_db_queue_length", "gauge",
		"Jobs waiting for the database worker.");
	out << QString("xca_db_queue_length %1").arg(worker.queued());
	family(out, "xca_db_jobs_total", "counter",
		"Calls of the database worker, by how they ended.");
	static const std::pair<enum JobResult::state, const char *> states[] = {
		{ JobResult::done, "done" }, { JobResult::failed, "failed" },
		{ JobResult::queueFull, "queue_full" },
		{ JobResult::timedOut, "timed_out" },
		{ JobResult::stopping, "stopping" } };
	for (const auto &s : states)
		out << QString("xca_db_jobs_total{state=\"%1\"} %2")
			.arg(s.second).arg(worker.calls(s.first));
	return out.join('\n') + '\n';
}

}
