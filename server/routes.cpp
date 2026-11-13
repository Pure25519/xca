/* vi: set sw=4 ts=4:
 *
 * The HTTP side of xca-server (BTD-154), see routes.h.
 */

#include "routes.h"

#include <cstdio>
#include <exception>

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <QJsonDocument>
#include <QJsonObject>
#include <QString>

#include "lib/json_report.h"

#include "config.h"
#include "session.h"
#include "worker.h"

namespace xcaserver {

namespace {

const char problemType[] = "application/problem+json";

/* The error document of the CLI (code, title, detail, type) plus the
 * HTTP status: one form for both (bxc-pki schemas/error.schema.json) */
void problem(httplib::Response &res, int status, const QString &code,
		const QString &detail)
{
	QJsonObject p = JsonReport::error(code, detail);
	p["status"] = status;
	res.status = status;
	res.set_content(QJsonDocument(p).toJson(QJsonDocument::Compact)
			.toStdString(), problemType);
}

void json(httplib::Response &res, const QJsonObject &o)
{
	res.status = 200;
	res.set_content(QJsonDocument(o).toJson(QJsonDocument::Compact)
			.toStdString(), "application/json");
}

/* The code of a status the library itself answers with */
QString statusCode(int status)
{
	switch (status) {
	case 400: return "bad_request";
	case 404: return "not_found";
	case 405: return "method_not_allowed";
	case 408: return "request_timeout";
	case 413: return "payload_too_large";
	case 414: return "uri_too_long";
	case 431: return "header_too_large";
	case 500: return "internal_error";
	case 503: return "service_unavailable";
	}
	return QString("http_%1").arg(status);
}

/* The HTTP status of an error code of a job */
int jobStatus(const QString &code)
{
	if (code == "missing_password" || code == "password_rejected" ||
	    code == "no_database")
		return 503;
	return 500;
}

/* A job's result as the answer; a timeout or a full queue is 503 */
void answer(httplib::Response &res, const JobResult &r)
{
	switch (r.state) {
	case JobResult::done:
		json(res, r.body);
		return;
	case JobResult::failed:
		problem(res, jobStatus(r.code), r.code, r.detail);
		return;
	case JobResult::queueFull:
		res.set_header("Retry-After", "1");
		problem(res, 503, "queue_full", QObject::tr("The job queue "
			"of the database is full; try again later"));
		return;
	case JobResult::timedOut:
		res.set_header("Retry-After", "1");
		problem(res, 503, "job_timeout", QObject::tr("The job did "
			"not finish within the job timeout; it still "
			"finishes on the server"));
		return;
	case JobResult::stopping:
		problem(res, 503, "server_stopping",
			QObject::tr("The server is stopping"));
		return;
	}
}

bool knownPath(const std::string &path)
{
	return path == "/v1/health" || path == "/v1/status";
}

}

std::string certActor(const httplib::Request &req)
{
	const SSL *ssl = static_cast<const SSL *>(req.ssl);
	X509 *cert = ssl ? SSL_get0_peer_certificate(ssl) : nullptr;
	if (!cert)
		return std::string();
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int len = 0;
	if (!X509_digest(cert, EVP_sha256(), md, &len))
		return std::string();
	std::string actor = "cert:";
	char hex[3];
	for (unsigned int i = 0; i < len; i++) {
		std::snprintf(hex, sizeof hex, "%02x", md[i]);
		actor += hex;
	}
	return actor;
}

void installRoutes(httplib::Server &srv, DbWorker &worker,
		const Config &config)
{
	const Limits limits = config.limits;
	/* condition 5 of the architecture: every limit explicit */
	srv.set_payload_max_length(size_t(limits.payloadMaxBytes));
	srv.set_read_timeout(time_t(limits.readTimeoutS), 0);
	srv.set_write_timeout(time_t(limits.writeTimeoutS), 0);
	srv.set_keep_alive_max_count(size_t(limits.keepAliveMaxCount));

	srv.set_pre_routing_handler([limits](const httplib::Request &req,
					httplib::Response &res) {
		/* the request line and the header lines, as sent */
		qint64 size = qint64(req.method.size() + req.target.size() +
				req.version.size() + 4);
		for (const auto &h : req.headers)
			size += qint64(h.first.size() + h.second.size() + 4);
		if (size > limits.headerMaxBytes) {
			problem(res, 431, "header_too_large", QObject::tr(
				"The request header has %1 bytes, more than "
				"the limit of %2").arg(size)
				.arg(limits.headerMaxBytes));
			return httplib::Server::HandlerResponse::Handled;
		}
		if (!knownPath(req.path)) {
			problem(res, 404, "not_found", QObject::tr(
				"No resource at '%1'").arg(
				QString::fromStdString(req.path)));
			return httplib::Server::HandlerResponse::Handled;
		}
		if (req.method != "GET" && req.method != "HEAD") {
			res.set_header("Allow", "GET, HEAD");
			problem(res, 405, "method_not_allowed", QObject::tr(
				"%1 is not allowed on '%2'").arg(
				QString::fromStdString(req.method),
				QString::fromStdString(req.path)));
			return httplib::Server::HandlerResponse::Handled;
		}
		return httplib::Server::HandlerResponse::Unhandled;
	});

	srv.Get("/v1/health", [](const httplib::Request &,
					httplib::Response &res) {
		json(res, QJsonObject{ { "status", "ok" } });
	});

	qint64 timeout = limits.jobTimeoutS;
	srv.Get("/v1/status", [&worker, timeout](const httplib::Request &req,
					httplib::Response &res) {
		/* mTLS makes this unreachable; kept for API keys later */
		QString actor = QString::fromStdString(certActor(req));
		if (actor.isEmpty()) {
			problem(res, 401, "unauthenticated", QObject::tr(
				"No client certificate"));
			return;
		}
		answer(res, worker.call([actor]() {
			return statusJob(actor);
		}, timeout));
	});

	/* anything the library answers itself (400, 413, 408, ...) */
	srv.set_error_handler([](const httplib::Request &,
					httplib::Response &res) {
		if (res.get_header_value("Content-Type") != problemType)
			problem(res, res.status, statusCode(res.status),
				QString::fromUtf8(httplib::status_message(
					res.status)));
		return httplib::Server::HandlerResponse::Handled;
	});
	srv.set_exception_handler([](const httplib::Request &,
				httplib::Response &res, std::exception_ptr) {
		problem(res, 500, "internal_error",
			QObject::tr("Internal error"));
	});
}

}
