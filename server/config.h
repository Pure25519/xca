/* vi: set sw=4 ts=4:
 *
 * xca-server.json (BTD-154): the configuration of xca-server.
 *
 * Every member is required and explicit, unknown members are refused.
 * A secret is a reference, "env:<variable>" or "file:<path>", never the
 * secret itself; an "op://" reference is resolved at deployment (op
 * inject, op run), not by the server. API keys stay off until BTD-155.
 * A refused file gives a ConfigError with the JSON pointer of the member.
 */

#ifndef __XCA_SERVER_CONFIG_H
#define __XCA_SERVER_CONFIG_H

#include <QString>

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

class Config
{
  public:
	QString listenAddress{};
	int listenPort{};
	QString databasePath{};
	/* the password source, env: or file: */
	QString databasePassword{};
	QString tlsCert{};
	QString tlsKey{};
	QString tlsClientCa{};
	Limits limits{};
	bool apiKeys{};

	/* Reads and checks the file; throws ConfigError */
	static Config load(const QString &file);
	/* Checks what only a real start can: the TLS files are readable;
	 * throws ConfigError */
	void checkFiles() const;
};

}

#endif
