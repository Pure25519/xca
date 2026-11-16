/* vi: set sw=4 ts=4:
 *
 * xca-server.json (BTD-154): the configuration of xca-server.
 *
 * Every member is required and explicit, unknown members are refused.
 * A secret is a reference, "env:<variable>" or "file:<path>", never the
 * secret itself; an "op://" reference is resolved at deployment (op
 * inject, op run), not by the server. A refused file gives a ConfigError
 * with the JSON pointer of the member.
 *
 * BTD-155 adds auth.denied_per_minute, the optional tls.key_password and
 * the roles (see RoleDef). Role names are those of the bootstrap schema
 * (reader, ra-operator, ca-admin, auditor); the OpenAPI document and
 * roles.json name them reader, ra_operator, ca_admin, auditor (auth.h).
 */

#ifndef __XCA_SERVER_CONFIG_H
#define __XCA_SERVER_CONFIG_H

#include <QList>
#include <QString>
#include <QStringList>

namespace xcaserver {

/* The schema id of xca-server.json */
extern const char configSchema[];

class ConfigError
{
  public:
	QString pointer;
	QString message;
	ConfigError(const QString &p, const QString &m)
		: pointer(p), message(m)
	{
	}
	/* "<pointer>: <message>", the detail of invalid_config */
	QString detail() const;
};

class Limits
{
  public:
	qint64 payloadMaxBytes{};
	qint64 headerMaxBytes{};
	qint64 readTimeoutS{};
	qint64 writeTimeoutS{};
	qint64 keepAliveMaxCount{};
	qint64 jobTimeoutS{};
	qint64 queueMax{};
};

/* A client certificate of a role: its subject and issuer DN, exactly as
 * RFC 4514 strings (the form of x509name::rfc4514(), e.g. "CN=admin,O=BxC";
 * openssl x509 -noout -subject -issuer -nameopt RFC2253 prints them), and
 * optionally the SHA-256 of the certificate (lowercase hex) */
class ClientCertRule
{
  public:
	QString subject{};
	QString issuer{};
	QString sha256{};
};

/* An API key of a role: its id (the actor is apikey:<id>) and the
 * reference of the key, env:<variable> or file:<path> */
class ApiKeyRef
{
  public:
	QString id{};
	QString secret{};
	/* the JSON pointer of the entry, for the errors of the start */
	QString pointer{};
};

/* One entry of "roles", the shape of $defs/role of the bootstrap schema
 * except client_certs (subject and issuer) and api_keys (id and secret).
 * Without "cas" the role applies to every CA; with it, only to these
 * bootstrap CA ids. */
class RoleDef
{
  public:
	QString name{};
	QList<ClientCertRule> clientCerts{};
	QList<ApiKeyRef> apiKeys{};
	bool allCas{ true };
	QStringList cas{};
};

class Config
{
  public:
	/* the file it was read from, for POST /v1/reload */
	QString file{};
	QString listenAddress{};
	int listenPort{};
	QString databasePath{};
	/* the password source, env: or file: */
	QString databasePassword{};
	QString tlsCert{};
	QString tlsKey{};
	QString tlsClientCa{};
	/* the password of an encrypted tls.key: a reference or empty */
	QString tlsKeyPassword{};
	Limits limits{};
	/* auth.api_keys: X-API-Key besides client certificates */
	bool apiKeys{};
	/* auth.denied_per_minute: single auth.denied entries per peer
	 * address and minute */
	qint64 deniedPerMinute{};
	QList<RoleDef> roles{};

	/* Reads and checks the file; throws ConfigError */
	static Config load(const QString &file);
	/* Checks what only a real start can: the TLS files are readable;
	 * throws ConfigError */
	void checkFiles() const;
};

}

#endif
