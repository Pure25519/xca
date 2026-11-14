/* vi: set sw=4 ts=4:
 *
 * Authentication and access rules of xca-server (BTD-155).
 *
 * Identities: a client certificate (actor cert:<SHA-256>) that the TLS
 * handshake verified against tls.client_ca, or, with auth.api_keys true,
 * an API key in the header X-API-Key (actor apikey:<id>; never in the
 * query or the path). A role of xca-server.json grants a certificate whose
 * subject and issuer DN are exactly those of a client_certs entry (and
 * whose SHA-256 is the entry's sha256, if given), and a key whose value is
 * that of an api_keys entry. Several roles of one identity add up; a role
 * with "cas" grants only for those CAs (Access).
 *
 * API keys are read at the start (and by POST /v1/reload), must have at
 * least 32 bytes, and only their HMAC-SHA256 under a random key of this
 * process (memory only) is kept; the key is wiped after hashing and
 * compared with CRYPTO_memcmp.
 *
 * Operations: roles.json (server/tools/gen_roles.py from the OpenAPI
 * document) is compiled into the binary. Its paths are those of the
 * document; the server serves them below /v1. Its role names are those of
 * the document (reader, ra_operator, ca_admin, auditor); a role of
 * xca-server.json (reader, ra-operator, ca-admin, auditor) maps to them by
 * replacing '-' with '_' (openapiRole()).
 *
 * CA scope: ca_param of an operation names the CA it acts on:
 *   body:issuer        the member issuer of the JSON body (a Reference: item
 *                      id, name or SHA-256 fingerprint of the CA certificate)
 *   path:id            the item id in the path is the CA certificate
 *   path:id#issuer     the issuer of the certificate with the item id
 * A bootstrap CA id of "cas" is found in the database by the settings row
 * bootstrap_<first 10 hex digits of SHA-256("ca:" + id)> that bxc-pki
 * bootstrap writes, whose member item is the item id of the CA certificate
 * (caScopeJob() in session.h). An operation without ca_param is granted by
 * a role with "cas" only when it reads (GET); its result is then to be
 * filtered to those CAs by the operation (Access::cas). A write without
 * ca_param needs a role for every CA.
 *
 * Audit: auth.login once per TLS connection and identity, auth.denied for
 * every refusal, at most auth.denied_per_minute single entries per peer
 * address and minute, then one summary entry with the number left out
 * (AuthAudit).
 */

#ifndef __XCA_SERVER_AUTH_H
#define __XCA_SERVER_AUTH_H

#include <chrono>
#include <map>
#include <memory>
#include <mutex>
#include <string>

#include <QByteArray>
#include <QJsonArray>
#include <QList>
#include <QMap>
#include <QString>
#include <QStringList>
#include <QVariantMap>

#include "config.h"

namespace xcaserver {

class DbWorker;

/* server/roles.json, compiled in (server/CMakeLists.txt) */
extern const char rolesJson[];

/* The OpenAPI name of a role of xca-server.json */
QString openapiRole(const QString &configRole);

class Operation
{
  public:
	QString id{};
	QString method{};
	/* as in the OpenAPI document, without /v1 */
	QString path{};
	QStringList roles{};
	/* empty: the operation names no CA */
	QString caParam{};
	QStringList segments{};
	int literals{};

	/* The cpp-httplib pattern: /v1 and the path with :name */
	std::string pattern() const;
};

class OperationTable
{
	QList<Operation> ops{};
	QMap<QString, QStringList> pathParams{};

  public:
	/* Parses roles.json; false and the reason in error */
	bool parse(const QByteArray &json, QString *error);
	/* The operation for method (GET for HEAD) and path (without /v1)
	 * with its path parameters, or nullptr; allow then lists the
	 * methods the path has (empty: unknown path) */
	const Operation *match(const QString &method, const QString &path,
			QMap<QString, QString> *params,
			QStringList *allow) const;
	const QList<Operation> &operations() const
	{
		return ops;
	}
};

/* What one role entry grants: an OpenAPI role, for all CAs or some */
class Grant
{
  public:
	QString role{};
	bool allCas{ true };
	QStringList cas{};
};

class Identity
{
  public:
	enum kind { none, cert, apiKey };
	enum kind kind{ none };
	QString actor{};
	/* RFC 4514, of a certificate */
	QString subject{};
	QString issuer{};
	QString keyId{};
	QList<Grant> grants{};
};

/* The roles of xca-server.json, with the API keys as HMACs */
class RoleTable
{
	class CertEntry
	{
	  public:
		ClientCertRule rule{};
		Grant grant{};
	};
	class KeyEntry
	{
	  public:
		QString id{};
		QByteArray mac{};
		Grant grant{};
	};
	QList<CertEntry> certs{};
	QList<KeyEntry> keys{};
	/* role name -> what its entries grant, to compare a reload */
	QMap<QString, QStringList> signatures{};

  public:
	/* Reads the API keys of config (each at least 32 bytes); throws
	 * ConfigError with the pointer of the key. Calls lib/ (the secret
	 * sources): at the start or on the DB worker only. */
	static std::shared_ptr<const RoleTable> build(const Config &config);
	QList<Grant> certGrants(const QString &subject, const QString &issuer,
			const QString &sha256) const;
	/* The id and the grants of the key presented; false for an unknown
	 * key. Every entry is compared, in constant time each. */
	bool keyGrants(const std::string &presented, QString *id,
			QList<Grant> *grants) const;
	/* The roles added, updated and retired since before, as entries
	 * {kind: role, id: <name>, change} */
	QJsonArray changes(const RoleTable &before) const;
	/* Wipes the HMAC key of this process (at the end of main) */
	static void wipeProcessKey();
};

/* The current roles; POST /v1/reload replaces them */
class RoleHolder
{
	mutable std::mutex mutex{};
	std::shared_ptr<const RoleTable> table{};

  public:
	explicit RoleHolder(std::shared_ptr<const RoleTable> t)
		: table(std::move(t))
	{
	}
	std::shared_ptr<const RoleTable> get() const
	{
		std::lock_guard<std::mutex> lock(mutex);
		return table;
	}
	void set(std::shared_ptr<const RoleTable> t)
	{
		std::lock_guard<std::mutex> lock(mutex);
		table = std::move(t);
	}
};

/* The role check of an operation */
class Access
{
  public:
	enum result { allow, forbidden, checkCa };
	enum result result{ forbidden };
	/* allow without a CA restriction */
	bool allCas{};
	/* the bootstrap CA ids the identity may act on (checkCa) or see
	 * (allow of a read with allCas false) */
	QStringList cas{};
};
Access authorize(const Identity &identity, const Operation &op);

/* One refusal for auth.denied */
class DeniedEvent
{
  public:
	/* empty: the channel default (the server's user) */
	QString actor{};
	/* tls_handshake_failed, unauthenticated or forbidden */
	QString errorCode{};
	QString objectType{};
	QString objectId{};
	/* peer_address is required */
	QVariantMap params{};
};

/* auth.login and auth.denied, the latter rate-limited per peer address */
class AuthAudit
{
	class Window
	{
	  public:
		std::chrono::steady_clock::time_point start{};
		QString startUtc{};
		qint64 count{};
		qint64 suppressed{};
	};
	DbWorker &worker;
	const qint64 perMinute;
	const qint64 timeoutS;
	std::mutex mutex{};
	std::map<QString, Window> windows{};

	bool write(const QString &actor, const QString &action,
		const QString &objectType, const QString &objectId,
		const QVariantMap &params, const QString &result,
		const QString &errorCode);
	void summary(const QString &peer, const Window &w);

  public:
	static const std::chrono::seconds window;

	AuthAudit(DbWorker &w, qint64 deniedPerMinute, qint64 jobTimeoutS)
		: worker(w), perMinute(deniedPerMinute), timeoutS(jobTimeoutS)
	{
	}
	/* auth.login; false if it could not be written */
	bool login(const Identity &identity, const QString &peer);
	/* auth.denied, or counted for the summary of its peer and minute */
	void denied(const DeniedEvent &e);
	/* Writes the summaries of the minutes that ended */
	void tick();
	/* Writes the summaries of all minutes (at the stop) */
	void flush();
};

}

#endif
