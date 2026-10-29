/* vi: set sw=4 ts=4:
 *
 * bxc-pki: headless command line of the bxc-pki fork (BTD-41).
 * Design: cli/README.md. Links xcacore only (no Qt Gui, Widgets, Help).
 *
 * The framework is shared by all commands and by the later bootstrap
 * command (BTD-166):
 *  - OptionSpec / OptionParser: one strict parser for every command.
 *  - Command: name, help, options, handler; registered in a Registry.
 *  - CommandContext: what a handler gets (options, service context,
 *    plan mode, the result collector).
 *  - ResultCollector: the objects a handler wrote, as JSON snapshots;
 *    it becomes ONE result document per command after the commit.
 *  - Runner: runs write handlers inside one transaction it owns, or
 *    inside a caller-owned one (bootstrap), commits, or rolls back for
 *    --plan, and replays the failure audit entries after a rollback.
 */

#ifndef __BXC_PKI_CLI_H
#define __BXC_PKI_CLI_H

#include <functional>

#include <QJsonArray>
#include <QJsonObject>
#include <QList>
#include <QMap>
#include <QString>
#include <QStringList>

#include "lib/audit.h"
#include "lib/exception.h"
#include "lib/issuance.h"
#include "lib/pass_info.h"

class pki_base;
class pki_key;
class pki_x509;
class pki_x509req;
class pki_temp;
class x509name;

namespace bxcpki {

/* An error of the command line itself (unknown option, wrong value):
 * exit code 2 instead of 1 */
class usageError: public serviceError
{
  public:
	usageError(const QString &c, const QString &txt)
		: serviceError(c, txt)
	{
	}
};

enum exitCode { exitOk = 0, exitFailure = 1, exitUsage = 2 };

/* --- Options -------------------------------------------------------- */

class OptionSpec
{
  public:
	enum kind {
		flag,       // no value
		string,     // any non-empty text
		integer,    // non-negative decimal
		duration,   // ISO 8601 duration (IsoDuration)
		timestamp,  // RFC 3339 date-time
		secret,     // pass:, env:, file:, fd: or stdin
		reference,  // database id or unique name
	};
	QString name{};             // without "--"
	enum kind type{ string };
	QString valueName{};        // for the help, e.g. "<duration>"
	QString help{};
	bool repeatable{};
	bool required{};
	/* Secret options: the purposes their source answers */
	QList<enum pass_info::purpose> purposes{};
	/* Reserved until a later ticket: accepted by the parser for the
	 * help, rejected with not_supported and this reason */
	QString reserved{};
};

class Options
{
	QMap<QString, QStringList> values{};
	QStringList positional{};

  public:
	void add(const QString &name, const QString &value)
	{
		values[name] << value;
	}
	void addPositional(const QString &v)
	{
		positional << v;
	}
	bool has(const QString &name) const
	{
		return values.contains(name);
	}
	QString value(const QString &name, const QString &def = QString()) const
	{
		return has(name) ? values[name].last() : def;
	}
	QStringList all(const QString &name) const
	{
		return values.value(name);
	}
	QStringList args() const
	{
		return positional;
	}
	QStringList names() const
	{
		return values.keys();
	}
};

/* --- Commands -------------------------------------------------------- */

class ResultCollector;

class CommandContext
{
  public:
	Options opts{};
	ServiceContext svc{ ServiceContext::cli, QString() };
	bool plan{};                // --plan: evaluate, write nothing
	bool text{};                // --text instead of JSON
	QString database{};
	ResultCollector *result{};
	/* What the handler is writing now, for error messages naming
	 * the object (rule 11), e.g. "key 'plc10'" */
	QString step{};
	/* Opens --db; for a command that needs the database only for some
	 * inputs (show without --file) */
	std::function<void()> openDatabase{};
};

class Command
{
  public:
	QString name{};
	QString summary{};
	QString usage{};            // positional part, e.g. "<csr>"
	QString description{};
	QList<OptionSpec> options{};
	/* pairs of options that exclude each other */
	QList<QPair<QString, QString> > conflicts{};
	int minArgs{}, maxArgs{};
	bool writes{};              // runs in a transaction, --plan allowed
	bool needsDatabase{ true };
	std::function<void(CommandContext &)> handler{};
};

class Registry
{
	QList<Command> commands{};

  public:
	void add(const Command &c)
	{
		commands << c;
	}
	const Command *find(const QString &name) const;
	QList<Command> all() const
	{
		return commands;
	}
	static Registry &instance();
	/* The options every command takes (--db, the secrets, --text, ...) */
	static QList<OptionSpec> globalOptions();
	static QList<QPair<QString, QString> > globalConflicts();
};

void registerCommands(Registry &r);

/* Parses argv after the command name; throws usageError */
Options parseOptions(const Command &cmd, const QStringList &argv);
/* Help texts: all commands, or one */
QString helpText();
QString commandHelp(const Command &cmd);

/* --- Result ----------------------------------------------------------- */

class ResultCollector
{
	QString command{};
	bool plan{};
	QJsonArray objects{};
	QJsonObject entry(const pki_base *pki) const;

  public:
	ResultCollector(const QString &cmd, bool p) : command(cmd), plan(p)
	{
	}
	/* Records an object the handler wrote; the JSON document is taken
	 * at once (after a rollback the object is gone) */
	void written(const pki_base *pki);
	/* A certificate: validity_capped and, when capped,
	 * requested_not_after (BTD-51) */
	void writtenCertificate(const pki_x509 *cert, const IssuanceSpec &spec);
	QJsonObject document() const;
	QString text() const;
	int count() const
	{
		return objects.size();
	}
};

/* --- Runner ----------------------------------------------------------- */

/* Runs a write handler in a transaction this call owns: commit, or with
 * ctx.plan a deliberate rollback. On failure the transaction is rolled
 * back and the failure audit entries of the service calls are written
 * again (AuditFailureCapture). Bootstrap (BTD-166) passes many steps:
 * one transaction, all or nothing; --plan evaluates them all. */
void runInTransaction(CommandContext &ctx,
		const QList<std::function<void(CommandContext &)> > &steps);

/* --- References and input -------------------------------------------- */

/* A database object by id or unique internal name. kinds: "key",
 * "certificate", "request", "template" (the JsonReport type names);
 * empty: any. Throws unknown_reference or ambiguous_reference (with
 * the candidates). */
pki_base *resolve(const QString &ref, const QStringList &kinds,
		const QString &option);
template <class T>
T *resolveAs(const QString &ref, const QString &kind, const QString &option)
{
	return dynamic_cast<T *>(resolve(ref, QStringList(kind), option));
}

/* RFC 4514 distinguished name; order kept, multi-valued RDNs (+),
 * UTF8String for directory strings. Throws usageError invalid_subject. */
x509name parseDn(const QString &rfc4514);
/* Strict checks of the SAN values; throw usageError invalid_<kind> */
QString checkIp(const QString &ip);         // canonical text
QString checkUri(const QString &uri);
QString checkDns(const QString &dns);
QString checkEmail(const QString &email);
/* RFC 3339 date-time; throws usageError invalid_value */
a1time parseTimestamp(const QString &text, const QString &option);
IsoDuration parseDuration(const QString &text, const QString &option);
/* --key: a name of the bootstrap keyType vocabulary (rsa-3072, ec-p256,
 * ed25519, ml-dsa-65, ...) as keyjob text; an unknown name is
 * invalid_key_type, a name this build cannot generate not_supported.
 * Size and curve are checked by the key generation service. */
QString keyJobText(const QString &keyType);
QStringList supportedKeyTypes();

/* The command line option that supplies a secret of this purpose */
QString optionForPurpose(int purpose);

} // namespace bxcpki

#endif
