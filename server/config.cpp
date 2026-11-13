/* vi: set sw=4 ts=4:
 *
 * xca-server.json (BTD-154), see config.h.
 */

#include "config.h"

#include <cmath>
#include <limits>

#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QJsonValue>
#include <QObject>
#include <QStringList>

namespace xcaserver {

const char configSchema[] = "urn:bxc-pki:schema:xca-server:v1";

QString ConfigError::detail() const
{
	return pointer.isEmpty() ? message : pointer + ": " + message;
}

namespace {

QString tr(const char *s)
{
	return QObject::tr(s);
}

/* The object at pointer with exactly the members names */
QJsonObject object(const QJsonObject &parent, const QString &name,
		const QString &pointer, const QStringList &names)
{
	QString p = pointer + "/" + name;
	if (!parent.contains(name))
		throw ConfigError(p, tr("required member is missing"));
	QJsonValue v = parent.value(name);
	if (!v.isObject())
		throw ConfigError(p, tr("must be an object"));
	QJsonObject o = v.toObject();
	for (const QString &key : o.keys())
		if (!names.contains(key))
			throw ConfigError(p + "/" + key,
				tr("unknown member"));
	for (const QString &key : names)
		if (!o.contains(key))
			throw ConfigError(p + "/" + key,
				tr("required member is missing"));
	return o;
}

QString string(const QJsonObject &o, const QString &name,
		const QString &pointer)
{
	QJsonValue v = o.value(name);
	if (!v.isString() || v.toString().isEmpty())
		throw ConfigError(pointer + "/" + name,
			tr("must be a non-empty string"));
	return v.toString();
}

qint64 integer(const QJsonObject &o, const QString &name,
		const QString &pointer, qint64 min, qint64 max)
{
	QString p = pointer + "/" + name;
	QJsonValue v = o.value(name);
	if (!v.isDouble())
		throw ConfigError(p, tr("must be an integer"));
	double d = v.toDouble();
	if (std::floor(d) != d)
		throw ConfigError(p, tr("must be an integer"));
	if (d < double(min) || d > double(max))
		throw ConfigError(p, QObject::tr("must be between %1 and %2")
				.arg(min).arg(max));
	return qint64(d);
}

/* env:<variable> or file:<path>; never the secret itself */
QString secretReference(const QJsonObject &o, const QString &name,
		const QString &pointer)
{
	QString p = pointer + "/" + name;
	QJsonValue v = o.value(name);
	if (!v.isString())
		throw ConfigError(p, tr("must be a secret reference "
			"(env:<variable> or file:<path>)"));
	QString s = v.toString();
	if (s.startsWith("op://"))
		throw ConfigError(p, tr("an op:// reference is not resolved "
			"by the server; resolve it at deployment (op inject or "
			"op run) into env:<variable> or file:<path>"));
	if ((s.startsWith("env:") && s.size() > 4) ||
	    (s.startsWith("file:") && s.size() > 5))
		return s;
	/* the value is not repeated: it may be the secret */
	throw ConfigError(p, tr("a literal secret is not accepted; give a "
		"reference: env:<variable> or file:<path>"));
}

}

Config Config::load(const QString &file)
{
	QFile f(file);
	if (!f.open(QIODevice::ReadOnly))
		throw ConfigError(QString(), QObject::tr(
			"cannot read the configuration file '%1': %2")
			.arg(file).arg(f.errorString()));
	QJsonParseError err;
	QJsonDocument doc = QJsonDocument::fromJson(f.readAll(), &err);
	if (err.error != QJsonParseError::NoError)
		throw ConfigError(QString(), QObject::tr(
			"'%1' is not JSON: %2 at offset %3")
			.arg(file).arg(err.errorString()).arg(err.offset));
	if (!doc.isObject())
		throw ConfigError(QString(), QObject::tr(
			"'%1' is not a JSON object").arg(file));
	QJsonObject root = doc.object();
	const QStringList top { "schema", "listen", "database", "tls",
				"limits", "auth" };
	for (const QString &key : root.keys())
		if (!top.contains(key))
			throw ConfigError("/" + key, tr("unknown member"));
	for (const QString &key : top)
		if (!root.contains(key))
			throw ConfigError("/" + key,
				tr("required member is missing"));
	if (root.value("schema").toString() != configSchema)
		throw ConfigError("/schema", QObject::tr("must be %1")
				.arg(configSchema));

	Config c;
	QJsonObject listen = object(root, "listen", "", { "address", "port" });
	c.listenAddress = string(listen, "address", "/listen");
	c.listenPort = int(integer(listen, "port", "/listen", 1, 65535));

	QJsonObject db = object(root, "database", "", { "path", "password" });
	c.databasePath = string(db, "path", "/database");
	c.databasePassword = secretReference(db, "password", "/database");

	QJsonObject tls = object(root, "tls", "",
				{ "cert", "key", "client_ca" });
	c.tlsCert = string(tls, "cert", "/tls");
	c.tlsKey = string(tls, "key", "/tls");
	c.tlsClientCa = string(tls, "client_ca", "/tls");

	QJsonObject limits = object(root, "limits", "", {
		"payload_max_bytes", "header_max_bytes", "read_timeout_s",
		"write_timeout_s", "keep_alive_max_count", "job_timeout_s",
		"queue_max" });
	const qint64 max = std::numeric_limits<int>::max();
	c.limits.payloadMaxBytes = integer(limits, "payload_max_bytes",
					"/limits", 1, max);
	c.limits.headerMaxBytes = integer(limits, "header_max_bytes",
					"/limits", 1, max);
	c.limits.readTimeoutS = integer(limits, "read_timeout_s",
					"/limits", 1, 86400);
	c.limits.writeTimeoutS = integer(limits, "write_timeout_s",
					"/limits", 1, 86400);
	c.limits.keepAliveMaxCount = integer(limits, "keep_alive_max_count",
					"/limits", 1, max);
	c.limits.jobTimeoutS = integer(limits, "job_timeout_s",
					"/limits", 1, 86400);
	c.limits.queueMax = integer(limits, "queue_max", "/limits", 1, max);

	QJsonObject auth = object(root, "auth", "", { "api_keys" });
	QJsonValue apiKeys = auth.value("api_keys");
	if (!apiKeys.isBool())
		throw ConfigError("/auth/api_keys", tr("must be a boolean"));
	if (apiKeys.toBool())
		throw ConfigError("/auth/api_keys", tr("API keys are not "
			"available yet (BTD-155); only false is accepted"));
	c.apiKeys = false;
	return c;
}

void Config::checkFiles() const
{
	const QList<QPair<QString, QString>> files {
		{ "/tls/cert", tlsCert }, { "/tls/key", tlsKey },
		{ "/tls/client_ca", tlsClientCa } };
	for (const auto &f : files) {
		QFileInfo fi(f.second);
		if (!fi.isFile() || !fi.isReadable())
			throw ConfigError(f.first, QObject::tr(
				"'%1' is not a readable file").arg(f.second));
	}
}

}
