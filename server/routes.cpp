/* vi: set sw=4 ts=4:
 *
 * The HTTP side of xca-server (BTD-154, BTD-155), see routes.h.
 */

#include <cstdio>
#include <exception>
#include <memory>

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMap>
#include <QString>

#include "lib/audit.h"
#include "lib/json_report.h"

#include "auth.h"
#include "config.h"
#include "session.h"
#include "tls.h"
#include "worker.h"
/* last: sys/param.h of the header redefines MIN of lib/base.h, which
 * is quiet only in this order (system header) */
#include "routes.h"

namespace xcaserver {

namespace {

const char problemType[] = "application/problem+json";

/* The error document of the CLI (code, title, detail, type) plus the
 * HTTP status: one form for both (bxc-pki schemas/error.schema.json) */
void problem(httplib::Response &res, int status, const QString &code,
		const QString &detail,
		const QJsonObject &members = QJsonObject())
{
	QJsonObject p = JsonReport::error(code, detail);
	for (auto it = members.begin(); it != members.end(); ++it)
		p[it.key()] = it.value();
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

class Context
{
  public:
	DbWorker &worker;
	const Config &config;
	const OperationTable &operations;
	RoleHolder &roles;
	AuthAudit &audit;
	qint64 timeout;
};

/* What the pre-routing handler found out for the route handler of the
 * same request, on the same thread */
class Current
{
  public:
	const httplib::Request *req{};
	const Operation *op{};
	Identity identity{};
	QMap<QString, QString> params{};
};
thread_local Current current;

const SSL *sslOf(const httplib::Request &req)
{
	return static_cast<const SSL *>(req.ssl);
}

QString peerOf(const httplib::Request &req)
{
	return QString::fromStdString(req.remote_addr);
}

/* auth.denied for the request, then the problem */
void deny(Context &ctx, const httplib::Request &req, httplib::Response &res,
		int status, const QString &code, const QString &detail,
		const Identity &id, const Operation *op, const QString &reason,
		const QVariantMap &extra = QVariantMap())
{
	DeniedEvent e;
	e.actor = id.actor;
	e.errorCode = code;
	e.objectType = op ? "operation" : "connection";
	e.objectId = op ? op->id : QString();
	e.params = extra;
	e.params["peer_address"] = peerOf(req);
	e.params["reason"] = reason;
	if (op)
		e.params["operation_id"] = op->id;
	if (id.kind == Identity::cert) {
		e.params["subject"] = id.subject;
		e.params["issuer"] = id.issuer;
	} else if (id.kind == Identity::apiKey) {
		e.params["api_key_id"] = id.keyId;
	}
	ctx.audit.denied(e);
	problem(res, status, code, detail);
}

/* The identity of the request, or false with the reason */
bool authenticate(Context &ctx, const httplib::Request &req, Identity *id,
		QString *reason)
{
	const SSL *ssl = sslOf(req);
	X509 *cert = ssl ? SSL_get0_peer_certificate(ssl) : nullptr;
	/* a certificate that did not verify ends the handshake; this is
	 * the second lock of the same door */
	if (cert && SSL_get_verify_result(ssl) != X509_V_OK)
		cert = nullptr;
	std::shared_ptr<const RoleTable> table = ctx.roles.get();
	size_t keys = req.get_header_value_count("X-API-Key");
	if (ctx.config.apiKeys && keys > 0) {
		if (keys > 1) {
			*reason = "several_api_keys";
			return false;
		}
		/* the header only, never the query or the path */
		std::string presented = req.get_header_value("X-API-Key");
		QString keyId;
		QList<Grant> grants;
		bool ok = table->keyGrants(presented, &keyId, &grants);
		OPENSSL_cleanse(&presented[0], presented.size());
		if (!ok) {
			*reason = "unknown_api_key";
			return false;
		}
		id->kind = Identity::apiKey;
		id->keyId = keyId;
		id->actor = "apikey:" + keyId;
		id->grants = grants;
		return true;
	}
	if (cert) {
		QString sha256 = certSha256(cert);
		id->kind = Identity::cert;
		id->actor = "cert:" + sha256;
		id->subject = rfc4514(X509_get_subject_name(cert));
		id->issuer = rfc4514(X509_get_issuer_name(cert));
		id->grants = table->certGrants(id->subject, id->issuer, sha256);
		return true;
	}
	*reason = "no_credentials";
	return false;
}

/* The CA reference of the request for op.caParam (auth.h) */
bool caReference(const Operation &op, const httplib::Request &req,
		const QMap<QString, QString> &params, QJsonValue *ref,
		bool *issuerOf)
{
	QString kind = op.caParam.section(':', 0, 0);
	QString name = op.caParam.section(':', 1).section('#', 0, 0);
	*issuerOf = op.caParam.endsWith("#issuer");
	if (kind == "path") {
		*ref = params.value(name);
		return !params.value(name).isEmpty();
	}
	if (kind != "body")
		return false;
	QJsonDocument doc = QJsonDocument::fromJson(
			QByteArray::fromStdString(req.body));
	QJsonValue v = doc.object().value(name);
	if (v.isDouble() && v.toDouble() >= 0) {
		*ref = v;
		return true;
	}
	if (v.isString() && !v.toString().isEmpty()) {
		*ref = v;
		return true;
	}
	return false;
}

/* POST /v1/reload: re-reads the roles of the configuration file on the
 * DB worker and writes config.reload with the result */
void reload(Context &ctx, const Identity &id, httplib::Response &res)
{
	QString file = ctx.config.file;
	bool apiKeys = ctx.config.apiKeys;
	RoleHolder *holder = &ctx.roles;
	QString actor = id.actor;
	JobResult r = ctx.worker.call([file, apiKeys, holder, actor]() {
		try {
			Config c = Config::load(file);
			if (c.apiKeys != apiKeys)
				throw ConfigError("/auth/api_keys", QObject::tr(
					"a change of API keys needs a restart"));
			std::shared_ptr<const RoleTable> t =
				RoleTable::build(c);
			QJsonArray changed = t->changes(*holder->get());
			QStringList text;
			for (const QJsonValue &v : changed)
				text << v["id"].toString() + ":" +
					v["change"].toString();
			appendEntry(actor, AuditLog::actionConfigReload,
				"configuration", file, QVariantMap{
					{ "changed", text.join(',') },
					{ "count", qint64(changed.size()) } },
				"success", QString());
			/* applied after its entry, on the worker: a caller
			 * that timed out still gets what the log says */
			holder->set(t);
			return QJsonObject{ { "changed", changed } };
		} catch (ConfigError &e) {
			appendEntry(actor, AuditLog::actionConfigReload,
				"configuration", file, QVariantMap{
					{ "reason", e.detail() } },
				"failure", "invalid_config");
			return QJsonObject{ { "invalid_config", true },
				{ "field", e.pointer },
				{ "detail", e.detail() } };
		}
	}, ctx.timeout);
	if (r.state == JobResult::done && r.body.contains("invalid_config")) {
		problem(res, 422, "invalid_config",
			r.body["detail"].toString(), QJsonObject{
				{ "field", r.body["field"] } });
		return;
	}
	answer(res, r);
}

/* The route of op: the role and CA check, then its handler */
void handle(Context &ctx, const Operation &op, const httplib::Request &req,
		httplib::Response &res)
{
	if (current.req != &req || current.op != &op) {
		/* the router and the table disagree: never run a handler
		 * that was not checked */
		current = Current();
		problem(res, 404, "not_found", QObject::tr("No resource at "
			"'%1'").arg(QString::fromStdString(req.path)));
		return;
	}
	Identity id = current.identity;
	QMap<QString, QString> params = current.params;
	current = Current();

	Access access = authorize(id, op);
	if (access.result == Access::forbidden) {
		deny(ctx, req, res, 403, "forbidden", QObject::tr("The roles "
			"of %1 do not allow %2").arg(id.actor, op.id), id, &op,
			"role");
		return;
	}
	if (access.result == Access::checkCa) {
		QJsonValue ref;
		bool issuerOf = false;
		if (!caReference(op, req, params, &ref, &issuerOf)) {
			deny(ctx, req, res, 403, "forbidden", QObject::tr(
				"%1 names no CA, and the roles of %2 are "
				"limited to some CAs").arg(op.id, id.actor),
				id, &op, "ca_not_named");
			return;
		}
		QString refText = ref.isDouble() ?
			QString::number(qint64(ref.toDouble())) :
			ref.toString().left(128);
		JobResult r = ctx.worker.call([ref, issuerOf]() {
			return caScopeJob(ref, issuerOf);
		}, ctx.timeout);
		if (r.state == JobResult::failed &&
		    (r.code == "unknown_reference" ||
		     r.code == "ambiguous_reference")) {
			deny(ctx, req, res, 403, "forbidden", QObject::tr(
				"The CA of %1 is not known: %2").arg(op.id,
				r.detail), id, &op, "ca_unknown",
				QVariantMap{ { "ca_ref", refText } });
			return;
		}
		if (r.state != JobResult::done) {
			answer(res, r);
			return;
		}
		bool allowed = false;
		for (const QJsonValue &v : r.body["bootstrap_ids"].toArray())
			allowed = allowed || access.cas.contains(v.toString());
		if (!allowed) {
			deny(ctx, req, res, 403, "forbidden", QObject::tr(
				"The roles of %1 do not allow %2 for this "
				"CA").arg(id.actor, op.id), id, &op,
				"ca_scope", QVariantMap{ { "ca_ref", refText } });
			return;
		}
	}

	if (op.id == "getStatus") {
		QString actor = id.actor;
		answer(res, ctx.worker.call([actor]() {
			return statusJob(actor);
		}, ctx.timeout));
		return;
	}
	if (op.id == "reloadConfiguration") {
		reload(ctx, id, res);
		return;
	}
	/* BTD-155: the operations exist with their access rules, their
	 * work comes with the tickets of the service functions */
	problem(res, 501, "not_implemented", QObject::tr("%1 is not "
		"implemented yet").arg(op.id));
}

}

std::string certActor(const httplib::Request &req)
{
	const SSL *ssl = sslOf(req);
	X509 *cert = ssl ? SSL_get0_peer_certificate(ssl) : nullptr;
	if (!cert)
		return std::string();
	return ("cert:" + certSha256(cert)).toStdString();
}

void installRoutes(httplib::Server &srv, DbWorker &worker,
		const Config &config, const OperationTable &operations,
		RoleHolder &roles, AuthAudit &audit)
{
	const Limits limits = config.limits;
	/* condition 5 of the architecture: every limit explicit */
	srv.set_payload_max_length(size_t(limits.payloadMaxBytes));
	srv.set_read_timeout(time_t(limits.readTimeoutS), 0);
	srv.set_write_timeout(time_t(limits.writeTimeoutS), 0);
	srv.set_keep_alive_max_count(size_t(limits.keepAliveMaxCount));

	auto ctx = std::make_shared<Context>(Context{ worker, config,
		operations, roles, audit, limits.jobTimeoutS });

	srv.set_pre_routing_handler([ctx, limits](const httplib::Request &req,
					httplib::Response &res) {
		current = Current();
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
		QString method = QString::fromStdString(req.method);
		QString path = QString::fromStdString(req.path);
		bool get = method == "GET" || method == "HEAD";
		bool health = path == "/v1/health";
		const Operation *op = nullptr;
		QMap<QString, QString> params;
		QStringList allow;
		if (health)
			allow << "GET";
		else if (path.startsWith("/v1/"))
			op = ctx->operations.match(get ? "GET" : method,
					path.mid(3), &params, &allow);

		Identity id;
		QString reason;
		if (!authenticate(*ctx, req, &id, &reason)) {
			deny(*ctx, req, res, 401, "unauthenticated",
				QObject::tr("No valid client certificate or "
				"API key (header X-API-Key)"), id, op, reason);
			return httplib::Server::HandlerResponse::Handled;
		}
		if (allow.isEmpty()) {
			problem(res, 404, "not_found", QObject::tr(
				"No resource at '%1'").arg(path));
			return httplib::Server::HandlerResponse::Handled;
		}
		if (health ? !get : !op) {
			if (allow.contains("GET"))
				allow << "HEAD";
			res.set_header("Allow", allow.join(", ").toStdString());
			problem(res, 405, "method_not_allowed", QObject::tr(
				"%1 is not allowed on '%2'").arg(method, path));
			return httplib::Server::HandlerResponse::Handled;
		}
		if (!health && !loggedIn(sslOf(req), id.actor.toStdString())) {
			JobResult r;
			if (!ctx->audit.login(id, peerOf(req))) {
				/* no work without its login entry */
				r.state = JobResult::queueFull;
				answer(res, r);
				return httplib::Server::HandlerResponse::Handled;
			}
			setLoggedIn(sslOf(req), id.actor.toStdString());
		}
		current.req = &req;
		current.op = op;
		current.identity = id;
		current.params = params;
		return httplib::Server::HandlerResponse::Unhandled;
	});

	srv.Get("/v1/health", [](const httplib::Request &,
					httplib::Response &res) {
		json(res, QJsonObject{ { "status", "ok" } });
	});
	/* more literal segments first (OperationTable::parse) */
	for (const Operation &op : operations.operations()) {
		const Operation *o = &op;
		auto h = [ctx, o](const httplib::Request &req,
				httplib::Response &res) {
			handle(*ctx, *o, req, res);
		};
		std::string pattern = op.pattern();
		if (op.method == "GET")
			srv.Get(pattern, h);
		else if (op.method == "POST")
			srv.Post(pattern, h);
		else if (op.method == "PUT")
			srv.Put(pattern, h);
		else if (op.method == "PATCH")
			srv.Patch(pattern, h);
		else if (op.method == "DELETE")
			srv.Delete(pattern, h);
	}

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
