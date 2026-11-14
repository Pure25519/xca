/* vi: set sw=4 ts=4:
 *
 * xca-server.json (BTD-154, BTD-155), see config.h.
 */

#include "config.h"

#include <cmath>
#include <limits>

#include <QFile>
#include <QJsonArray>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QJsonValue>
#include <QMap>
#include <QObject>
#include <QRegularExpression>
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

/* v as an object at p with the members names and optionally optional */
QJsonObject members(const QJsonValue &v, const QString &p,
		const QStringList &names, const QStringList &optional = {})
{
	if (!v.isObject())
		throw ConfigError(p, tr("must be an object"));
	QJsonObject o = v.toObject();
	for (const QString &key : o.keys())
		if (!names.contains(key) && !optional.contains(key))
			throw ConfigError(p + "/" + key,
				tr("unknown member"));
	for (const QString &key : names)
		if (!o.contains(key))
			throw ConfigError(p + "/" + key,
				tr("required member is missing"));
	return o;
}

/* The object at pointer with exactly the members names (and optionally
 * optional) */
QJsonObject object(const QJsonObject &parent, const QString &name,
		const QString &pointer, const QStringList &names,
		const QStringList &optional = {})
{
	QString p = pointer + "/" + name;
	if (!parent.contains(name))
		throw ConfigError(p, tr("required member is missing"));
	return members(parent.value(name), p, names, optional);
}

/* The array at pointer/name */
QJsonArray array(const QJsonObject &o, const QString &name,
		const QString &pointer)
{
	QJsonValue v = o.value(name);
	if (!v.isArray())
		throw ConfigError(pointer + "/" + name, tr("must be an array"));
	return v.toArray();
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

/* The role names of xca-server.json, those of the bootstrap schema */
const QStringList roleNames { "reader", "ra-operator", "ca-admin",
				"auditor" };

/* A bootstrap id ($defs/id of the bootstrap schema) */
const QRegularExpression caIdPattern("^[a-z0-9][a-z0-9-]{0,62}$");
/* An API key id: the actor apikey:<id> */
const QRegularExpression keyIdPattern("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$");
const QRegularExpression sha256Pattern("^[0-9a-f]{64}$");

ClientCertRule clientCert(const QJsonValue &v, const QString &p)
{
	QJsonObject o = members(v, p, { "subject", "issuer" }, { "sha256" });
	ClientCertRule c;
	c.subject = string(o, "subject", p);
	c.issuer = string(o, "issuer", p);
	if (o.contains("sha256")) {
		c.sha256 = string(o, "sha256", p).remove(':').toLower();
		if (!sha256Pattern.match(c.sha256).hasMatch())
			throw ConfigError(p + "/sha256", tr("must be the "
				"SHA-256 of the certificate: 64 hex digits"));
	}
	return c;
}

ApiKeyRef apiKey(const QJsonValue &v, const QString &p)
{
	QJsonObject k = members(v, p, { "id", "secret" });
	ApiKeyRef key;
	key.pointer = p;
	key.id = k.value("id").toString();
	if (!k.value("id").isString() || !keyIdPattern.match(key.id).hasMatch())
		throw ConfigError(p + "/id", tr("must be a key id of 1 to 64 "
			"letters, digits, dots, underscores or hyphens"));
	key.secret = secretReference(k, "secret", p);
	return key;
}

RoleDef role(const QJsonValue &v, const QString &p, bool apiKeys)
{
	QJsonObject o = members(v, p, { "name" },
			{ "client_certs", "api_keys", "cas" });
	RoleDef r;
	r.name = o.value("name").toString();
	if (!o.value("name").isString() || !roleNames.contains(r.name))
		throw ConfigError(p + "/name", QObject::tr("must be one of "
			"%1").arg(roleNames.join(", ")));
	if (o.contains("client_certs")) {
		QJsonArray certs = array(o, "client_certs", p);
		for (int i = 0; i < certs.size(); i++)
			r.clientCerts << clientCert(certs[i], QString(
				"%1/client_certs/%2").arg(p).arg(i));
	}
	if (o.contains("api_keys")) {
		QJsonArray keys = array(o, "api_keys", p);
		if (!keys.isEmpty() && !apiKeys)
			throw ConfigError(p + "/api_keys", tr("API keys are "
				"off (/auth/api_keys is false)"));
		for (int i = 0; i < keys.size(); i++)
			r.apiKeys << apiKey(keys[i], QString(
				"%1/api_keys/%2").arg(p).arg(i));
	}
	if (o.contains("cas")) {
		QJsonArray cas = array(o, "cas", p);
		r.allCas = false;
		for (int i = 0; i < cas.size(); i++) {
			QString id = cas[i].toString();
			if (!cas[i].isString() ||
			    !caIdPattern.match(id).hasMatch())
				throw ConfigError(QString("%1/cas/%2").arg(p)
					.arg(i), tr("must be a CA id of the "
					"bootstrap file"));
			r.cas << id;
		}
	}
	return r;
}

/* The roles; one key id names one secret */
QList<RoleDef> parseRoles(const QJsonObject &root, bool apiKeys)
{
	QList<RoleDef> list;
	QJsonArray a = array(root, "roles", "");
	QMap<QString, QString> keySecrets;
	for (int i = 0; i < a.size(); i++) {
		RoleDef r = role(a[i], QString("/roles/%1").arg(i), apiKeys);
		for (const ApiKeyRef &k : r.apiKeys) {
			if (keySecrets.contains(k.id) &&
			    keySecrets[k.id] != k.secret)
				throw ConfigError(k.pointer + "/id", QObject::tr(
					"the key id '%1' was given with another "
					"secret before").arg(k.id));
			keySecrets[k.id] = k.secret;
		}
		list << r;
	}
	return list;
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
				"limits", "auth", "roles" };
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
	c.file = file;
	QJsonObject listen = object(root, "listen", "", { "address", "port" });
	c.listenAddress = string(listen, "address", "/listen");
	c.listenPort = int(integer(listen, "port", "/listen", 1, 65535));

	QJsonObject db = object(root, "database", "", { "path", "password" });
	c.databasePath = string(db, "path", "/database");
	c.databasePassword = secretReference(db, "password", "/database");

	QJsonObject tls = object(root, "tls", "",
				{ "cert", "key", "client_ca" },
				{ "key_password" });
	c.tlsCert = string(tls, "cert", "/tls");
	c.tlsKey = string(tls, "key", "/tls");
	c.tlsClientCa = string(tls, "client_ca", "/tls");
	if (tls.contains("key_password"))
		c.tlsKeyPassword = secretReference(tls, "key_password",
						"/tls");

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

	QJsonObject auth = object(root, "auth", "",
				{ "api_keys", "denied_per_minute" });
	QJsonValue apiKeys = auth.value("api_keys");
	if (!apiKeys.isBool())
		throw ConfigError("/auth/api_keys", tr("must be a boolean"));
	c.apiKeys = apiKeys.toBool();
	c.deniedPerMinute = integer(auth, "denied_per_minute", "/auth",
					1, 1000000);
	c.roles = parseRoles(root, c.apiKeys);
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
