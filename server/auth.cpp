/* vi: set sw=4 ts=4:
 *
 * Authentication and access rules of xca-server (BTD-155), see auth.h.
 */

#include "auth.h"

#include <algorithm>
#include <cstdio>
#include <mutex>
#include <vector>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <QDateTime>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QObject>
#include <QSet>

#include "lib/Passwd.h"
#include "lib/PwDialogCore.h"
#include "lib/audit.h"
#include "lib/exception.h"
#include "lib/json_report.h"

#include "session.h"
#include "worker.h"

namespace xcaserver {

namespace {

/* The shortest API key accepted */
const int apiKeyMinBytes = 32;

/* The HMAC key of this process: 32 random bytes, memory only */
unsigned char processKey[32];
std::once_flag processKeyOnce;

void makeProcessKey()
{
	std::call_once(processKeyOnce, []() {
		if (RAND_bytes(processKey, sizeof processKey) != 1)
			throw ConfigError("/roles", QObject::tr("no random bytes "
				"for the HMAC key of the API keys"));
	});
}

QByteArray mac(const char *data, size_t len)
{
	unsigned char out[EVP_MAX_MD_SIZE];
	size_t outLen = 0;
	if (!EVP_Q_mac(nullptr, "HMAC", nullptr, "SHA256", nullptr,
			processKey, sizeof processKey,
			reinterpret_cast<const unsigned char *>(data), len,
			out, sizeof out, &outLen))
		return QByteArray();
	return QByteArray(reinterpret_cast<const char *>(out), int(outLen));
}

}

const std::chrono::seconds AuthAudit::window(60);

QString openapiRole(const QString &configRole)
{
	/* the bootstrap schema writes ra-operator, the OpenAPI document
	 * ra_operator: the same four roles */
	static const QMap<QString, QString> names {
		{ "reader", "reader" }, { "ra-operator", "ra_operator" },
		{ "ca-admin", "ca_admin" }, { "auditor", "auditor" } };
	return names.value(configRole);
}

std::string Operation::pattern() const
{
	QStringList p;
	for (const QString &s : segments)
		p << (s.startsWith('{') ? ":" + s.mid(1, s.size() - 2) : s);
	return ("/v1/" + p.join('/')).toStdString();
}

bool OperationTable::parse(const QByteArray &json, QString *error)
{
	QJsonParseError err;
	QJsonDocument doc = QJsonDocument::fromJson(json, &err);
	if (err.error != QJsonParseError::NoError || !doc.isObject()) {
		*error = QObject::tr("roles.json is not a JSON object: %1")
				.arg(err.errorString());
		return false;
	}
	QJsonObject root = doc.object();
	QJsonObject params = root.value("path_params").toObject();
	for (const QString &name : params.keys()) {
		QStringList values;
		for (const QJsonValue &v : params.value(name).toArray())
			values << v.toString();
		pathParams[name] = values;
	}
	static const QStringList methods { "GET", "PUT", "POST", "DELETE",
						"PATCH" };
	for (const QJsonValue &v : root.value("operations").toArray()) {
		QJsonObject o = v.toObject();
		Operation op;
		op.id = o.value("operation_id").toString();
		op.method = o.value("method").toString();
		op.path = o.value("path").toString();
		op.caParam = o.value("ca_param").toString();
		for (const QJsonValue &r : o.value("roles").toArray())
			op.roles << r.toString();
		op.segments = op.path.mid(1).split('/');
		for (const QString &s : op.segments)
			if (!s.startsWith('{'))
				op.literals++;
		if (op.id.isEmpty() || !methods.contains(op.method) ||
		    !op.path.startsWith('/') || op.roles.isEmpty()) {
			*error = QObject::tr("roles.json: an incomplete "
				"operation '%1'").arg(op.id);
			return false;
		}
		ops << op;
	}
	if (ops.isEmpty()) {
		*error = QObject::tr("roles.json has no operations");
		return false;
	}
	/* more literal segments first, as cpp-httplib takes the first
	 * route that matches: /status before /{collection} */
	std::stable_sort(ops.begin(), ops.end(),
		[](const Operation &a, const Operation &b) {
			return a.literals > b.literals;
		});
	return true;
}

const Operation *OperationTable::match(const QString &method,
		const QString &path, QMap<QString, QString> *params,
		QStringList *allow) const
{
	if (!path.startsWith('/'))
		return nullptr;
	QStringList parts = path.mid(1).split('/');
	const Operation *found = nullptr;
	for (const Operation &op : ops) {
		if (op.segments.size() != parts.size())
			continue;
		QMap<QString, QString> values;
		bool ok = true;
		for (int i = 0; i < parts.size() && ok; i++) {
			const QString &s = op.segments[i];
			if (!s.startsWith('{')) {
				ok = s == parts[i];
				continue;
			}
			QString name = s.mid(1, s.size() - 2);
			ok = !parts[i].isEmpty() &&
				(!pathParams.contains(name) ||
				 pathParams[name].contains(parts[i]));
			values[name] = parts[i];
		}
		if (!ok)
			continue;
		if (!allow->contains(op.method))
			*allow << op.method;
		if (!found && op.method == method) {
			found = &op;
			*params = values;
		}
	}
	return found;
}

std::shared_ptr<const RoleTable> RoleTable::build(const Config &config)
{
	makeProcessKey();
	auto t = std::make_shared<RoleTable>();
	QMap<QByteArray, QString> keyIds;
	for (const RoleDef &r : config.roles) {
		Grant g;
		g.role = openapiRole(r.name);
		g.allCas = r.allCas;
		g.cas = r.cas;
		QStringList sig;
		for (const ClientCertRule &c : r.clientCerts) {
			t->certs << CertEntry{ c, g };
			sig << QString("cert %1|%2|%3").arg(c.subject, c.issuer,
							c.sha256);
		}
		for (const ApiKeyRef &k : r.apiKeys) {
			QString p = k.pointer + "/secret";
			Passwd key;
			try {
				key = PwDialogHeadless::readSource(k.secret);
			} catch (errorEx &e) {
				throw ConfigError(p, e.getString());
			}
			if (key.size() < apiKeyMinBytes)
				throw ConfigError(p, QObject::tr("the API key "
					"from %1 has %2 bytes; at least %3 are "
					"required").arg(k.secret).arg(key.size())
					.arg(apiKeyMinBytes));
			QByteArray m = mac(key.constData(), size_t(key.size()));
			key.cleanse();
			if (m.isEmpty())
				throw ConfigError(p, QObject::tr("the HMAC of "
					"the API key failed"));
			if (keyIds.contains(m) && keyIds[m] != k.id)
				throw ConfigError(p, QObject::tr("the key of "
					"'%1' is the key of '%2' as well")
					.arg(k.id, keyIds[m]));
			keyIds[m] = k.id;
			t->keys << KeyEntry{ k.id, m, g };
			sig << QString("key %1|%2").arg(k.id,
					QString::fromLatin1(m.toHex()));
		}
		sig << (r.allCas ? QString("cas *") :
				QString("cas ") + r.cas.join(','));
		t->signatures[r.name] << sig.join(';');
	}
	for (QStringList &s : t->signatures)
		s.sort();
	return t;
}

QList<Grant> RoleTable::certGrants(const QString &subject,
		const QString &issuer, const QString &sha256) const
{
	QList<Grant> grants;
	for (const CertEntry &c : certs)
		if (c.rule.subject == subject && c.rule.issuer == issuer &&
		    (c.rule.sha256.isEmpty() || c.rule.sha256 == sha256))
			grants << c.grant;
	return grants;
}

bool RoleTable::keyGrants(const std::string &presented, QString *id,
		QList<Grant> *grants) const
{
	QByteArray m = mac(presented.data(), presented.size());
	if (m.isEmpty())
		return false;
	bool found = false;
	for (const KeyEntry &k : keys) {
		if (k.mac.size() != m.size() ||
		    CRYPTO_memcmp(k.mac.constData(), m.constData(),
				size_t(m.size())) != 0)
			continue;
		if (!found)
			*id = k.id;
		found = true;
		*grants << k.grant;
	}
	return found;
}

QJsonArray RoleTable::changes(const RoleTable &before) const
{
	QJsonArray changed;
	QStringList names = signatures.keys() + before.signatures.keys();
	names.removeDuplicates();
	names.sort();
	for (const QString &name : names) {
		QString change;
		if (!before.signatures.contains(name))
			change = "added";
		else if (!signatures.contains(name))
			change = "retired";
		else if (signatures[name] != before.signatures[name])
			change = "updated";
		else
			continue;
		changed << QJsonObject{ { "kind", "role" }, { "id", name },
					{ "change", change } };
	}
	return changed;
}

void RoleTable::wipeProcessKey()
{
	OPENSSL_cleanse(processKey, sizeof processKey);
}

Access authorize(const Identity &identity, const Operation &op)
{
	Access a;
	QList<Grant> granted;
	for (const Grant &g : identity.grants)
		if (op.roles.contains(g.role))
			granted << g;
	if (granted.isEmpty())
		return a;
	for (const Grant &g : granted) {
		if (g.allCas) {
			a.result = Access::allow;
			a.allCas = true;
			a.cas.clear();
			return a;
		}
		for (const QString &ca : g.cas)
			if (!a.cas.contains(ca))
				a.cas << ca;
	}
	if (!op.caParam.isEmpty())
		a.result = Access::checkCa;
	else if (op.method == "GET")
		/* a read: the operation shows only the objects of a.cas */
		a.result = Access::allow;
	/* else a write that names no CA needs a role for every CA */
	return a;
}

bool AuthAudit::write(const QString &actor, const QString &action,
		const QString &objectType, const QString &objectId,
		const QVariantMap &params, const QString &result,
		const QString &errorCode)
{
	JobResult r = worker.call([=]() {
		return appendEntry(actor, action, objectType, objectId,
				params, result, errorCode);
	}, timeoutS);
	if (r.state == JobResult::done)
		return true;
	QString why = r.state == JobResult::failed ? r.code :
		r.state == JobResult::queueFull ? QString("queue_full") :
		r.state == JobResult::timedOut ? QString("job_timeout") :
		QString("server_stopping");
	/* the entry names no secret, nor does this */
	JsonReport::write(stderr, JsonReport::error("audit_entry_lost",
		QObject::tr("The audit entry %1 (%2) was not written: %3")
		.arg(action, errorCode.isEmpty() ? result : errorCode, why)));
	return false;
}

bool AuthAudit::login(const Identity &identity, const QString &peer)
{
	QVariantMap p;
	p["peer_address"] = peer;
	if (identity.kind == Identity::cert) {
		p["actor_kind"] = "cert";
		p["subject"] = identity.subject;
		p["issuer"] = identity.issuer;
	} else {
		p["actor_kind"] = "apikey";
		p["api_key_id"] = identity.keyId;
	}
	return write(identity.actor, AuditLog::actionAuthLogin, "connection",
			QString(), p, "success", QString());
}

void AuthAudit::summary(const QString &peer, const Window &w)
{
	QVariantMap p;
	p["peer_address"] = peer;
	p["suppressed"] = w.suppressed;
	p["window_start"] = w.startUtc;
	p["denied_per_minute"] = perMinute;
	write(QString(), AuditLog::actionAuthDenied, "connection", QString(),
		p, "denied", "rate_limited");
}

void AuthAudit::denied(const DeniedEvent &e)
{
	QString peer = e.params.value("peer_address").toString();
	auto now = std::chrono::steady_clock::now();
	std::vector<std::pair<QString, Window>> ended;
	bool single = false;
	{
		std::lock_guard<std::mutex> lock(mutex);
		auto it = windows.find(peer);
		if (it != windows.end() && now - it->second.start >= window) {
			if (it->second.suppressed)
				ended.emplace_back(peer, it->second);
			windows.erase(it);
			it = windows.end();
		}
		if (it == windows.end()) {
			Window w;
			w.start = now;
			w.startUtc = QDateTime::currentDateTimeUtc()
				.toString(Qt::ISODate);
			it = windows.emplace(peer, w).first;
		}
		if (it->second.count < perMinute) {
			it->second.count++;
			single = true;
		} else {
			it->second.suppressed++;
		}
	}
	for (const auto &w : ended)
		summary(w.first, w.second);
	if (single)
		write(e.actor, AuditLog::actionAuthDenied, e.objectType,
			e.objectId, e.params, "denied", e.errorCode);
}

void AuthAudit::tick()
{
	auto now = std::chrono::steady_clock::now();
	std::vector<std::pair<QString, Window>> ended;
	{
		std::lock_guard<std::mutex> lock(mutex);
		for (auto it = windows.begin(); it != windows.end();) {
			if (now - it->second.start < window) {
				++it;
				continue;
			}
			if (it->second.suppressed)
				ended.emplace_back(it->first, it->second);
			it = windows.erase(it);
		}
	}
	for (const auto &w : ended)
		summary(w.first, w.second);
}

void AuthAudit::flush()
{
	std::vector<std::pair<QString, Window>> ended;
	{
		std::lock_guard<std::mutex> lock(mutex);
		for (const auto &w : windows)
			if (w.second.suppressed)
				ended.emplace_back(w.first, w.second);
		windows.clear();
	}
	for (const auto &w : ended)
		summary(w.first, w.second);
}

}
