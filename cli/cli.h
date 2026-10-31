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
#include <memory>

#include <QDateTime>
#include <QJsonArray>
#include <QJsonObject>
#include <QList>
#include <QMap>
#include <QString>
#include <QStringList>

#include "lib/audit.h"
#include "lib/crl_policy.h"
#include "lib/digest.h"
#include "lib/exception.h"
#include "lib/issuance.h"
#include "lib/pass_info.h"
#include "lib/x509name.h"

class pki_base;
class pki_crl;
class pki_key;
class pki_x509;
class pki_x509req;
class pki_temp;
class StagedDirectory;
class StagedFile;

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
class OutputFiles;

class CommandContext
{
  public:
	Options opts{};
	ServiceContext svc{ ServiceContext::cli, QString() };
	QString command{};
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
	/* The files of --out and export (BTD-42): staged by the handlers
	 * before the commit, published by the runner after it */
	OutputFiles *files{};
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
	/* may create a database that does not exist (init, bootstrap) */
	bool createsDatabase{};
	/* the handler calls runInTransaction() itself (bootstrap: it reads
	 * its file and opens the database first; its --plan writes nothing,
	 * not even the cli.plan entry) */
	bool ownTransaction{};
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
	static QString bootstrapText(const QJsonObject &bootstrap);

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
	/* --plan: an object that would be written; no document, because
	 * nothing is signed (id and document null) */
	void planned(const QString &type, const QString &name);
	void plannedCertificate(const IssuanceSpec &spec);
	/* "type:name" of every object, for the cli.plan audit entry */
	QStringList plannedObjects() const;
	QJsonObject document() const;
	QString text() const;
	int count() const
	{
		return objects.size();
	}

	/* Members of BTD-42 beside objects: files (OutputFiles), crls
	 * (crlReport()), trust_list, warnings. A member is present only
	 * when a command sets it. */
	void set(const QString &member, const QJsonValue &v);
	void append(const QString &member, const QJsonValue &v);
	/* A warning the command accepted, e.g. budget_exceeded,
	 * crl_reissue_due (with --force); also printed on stderr */
	void warning(const QString &code, const QString &detail);
	/* "certificate 7 'plc10', crl 8 'BxC Root'": the objects that are
	 * stored, for an error after the commit (rule 11) */
	QString storedText() const;

  private:
	QJsonObject extra{};
	QStringList textWarnings{};
};

/* --- Files (BTD-42) ---------------------------------------------------- */

/* The files of one command: each is staged (written to a temporary file
 * beside its target, lib/staged_file.h) before the commit and published
 * after it; with --plan only the target is checked. */
class OutputFiles
{
  public:
	class entry
	{
	  public:
		QString path{};
		QString kind{};          // key, csr, crt, crl, der, p12, ...
		QString objectType{};
		qint64 objectId{};
		QString objectName{};
		bool secret{};
		qint64 size{};
		QString sha256{};
		QJsonObject info{};       // more members, e.g. ml_dsa_encoding
		std::shared_ptr<StagedFile> file{};
	};

  private:
	QList<entry> files{};
	bool force{};
	bool plan{};
	bool done{};
	/* the directory replaced as a whole (trust lists) */
	std::shared_ptr<StagedDirectory> directory{};
	QString plannedDirectory{};

  public:
	OutputFiles(bool forceReplace, bool planOnly)
		: force(forceReplace), plan(planOnly)
	{
	}
	/* Stages data for path (absolute or relative to the working
	 * directory); throws file_exists, invalid_output, write_failed. Two
	 * files of one command with the same path are file_exists too. */
	void add(const QString &path, const QString &kind, const pki_base *pki,
			const QByteArray &data, bool secret,
			const QJsonObject &info = QJsonObject());
	/* --plan: the checks of add() without writing; the path may hold
	 * "{id}" for an id not known yet */
	void planned(const QString &path, const QString &kind,
			const QString &type, const QString &name, bool secret);
	/* A directory replaced as a whole (trust lists, review of
	 * xca#62): checked and staged now (lib/staged_file.h
	 * StagedDirectory: empty, or exactly an earlier export whose
	 * marker file is a JSON manifest with this schema); the files
	 * added below it go to its sibling and become visible together
	 * in publish(). --plan: the checks only. */
	void addDirectory(const QString &dir, const QString &marker,
			const QString &schema);
	/* After publish(): old content of the directory that could not be
	 * removed (files that appeared during the run); empty if none */
	QString leftover() const;
	/* The warnings of the files (stale_temp_removed, temp_file_left,
	 * BTD-210): code and detail */
	QList<QPair<QString, QString> > warnings() const;
	/* After the commit; throws the error of the first file that fails,
	 * the files before it stay published */
	void publish();
	void discard();
	/* Whether the file of e is visible under its path */
	bool written(const entry &e) const;
	bool isEmpty() const
	{
		return files.isEmpty();
	}
	QList<entry> all() const
	{
		return files;
	}
	QJsonArray json() const;
};

/* --out <dir> [--layout id|certstrap] [--force] and, for commands that
 * write a key, --key-unencrypted and --no-key-file */
QList<OptionSpec> outOptions(bool withKey);
/* The file name part of an internal name: certstrap replaces spaces by
 * '_'; bxc-pki also every character outside [A-Za-z0-9._+@-] and a
 * leading '.', so a name never leaves the directory or hides */
QString fileBase(const QString &name);
/* <dir>/<base>-<id>.<ext> (layout id, default) or <dir>/<base>.<ext>
 * (layout certstrap) */
QString outPath(const CommandContext &ctx, const QString &dir,
		const QString &name, qint64 id, const QString &ext);
/* Up-front checks of the --out options of a command that writes a key
 * (before anything is generated): an encrypted key file needs
 * --export-pass (missing_password naming the option) */
void checkOutOptions(const CommandContext &ctx, bool writesKey);
/* --out of init, request-cert, sign, crl, revoke: writes one file of
 * the certstrap layout for pki (kind key, csr, crt or crl); with --plan
 * only the check under its planned name */
void writeOut(CommandContext &ctx, pki_base *pki, const QString &kind,
		const QString &plannedName = QString());

/* --- CRLs (BTD-42) ------------------------------------------------------ */

/* --crl-validity, --crl-reissue-fraction, --crl-size-budget */
QList<OptionSpec> crlOptions(const QString &scope);
bool hasCrlOptions(const Options &o);
/* The CA's stored setting with the options of the command over it */
CrlPolicy crlPolicy(const Options &o, const pki_x509 *ca);
/* Issues a CRL of ca with policy (nextUpdate = thisUpdate + validity),
 * records it in the result (object and crls report) and returns it;
 * with --plan only the checks without signature and nullptr */
pki_crl *issueCrl(CommandContext &ctx, pki_x509 *ca, const CrlPolicy &policy,
		const QString &trigger, const QDateTime &thisUpdate = QDateTime(),
		bool report = true);
/* Rule 7: issues a new CRL when the latest one of ca is past its
 * re-issue point (or expired). Returns the new CRL or nullptr. */
pki_crl *reissueIfDue(CommandContext &ctx, pki_x509 *ca,
		const CrlPolicy &policy);
/* The crls entry of the result: sizes, budget, re-issue point and the
 * remaining validity */
QJsonObject crlReport(const pki_crl *crl, const CrlPolicy &policy,
		const QDateTime &now);

/* --- Shared helpers of the handlers ----------------------------------- */

OptionSpec opt(const QString &name, enum OptionSpec::kind type,
		const QString &valueName, const QString &help,
		bool repeatable = false, bool required = false);
QDateTime nowSeconds();
/* --hash or the default for the key type of signKey */
digest hashFrom(const Options &o, const pki_key *signKey);
/* --plan: decrypts the key (checks its password), signs nothing */
void unlockCheck(const pki_key *key);

void registerLifecycleCommands(Registry &r);  // revoke, crl
void registerExportCommands(Registry &r);     // export
void registerBootstrapCommand(Registry &r);   // bootstrap (BTD-166)

/* --- CA creation (init, bootstrap) -------------------------------------- */

/* What bootstrap (BTD-166) gives the CA creation of init beyond init's
 * options (ctx.opts: --name, --key, --validity, --not-before,
 * --not-after, --hash, --path-len). Default constructed: init as it is. */
class CaExtras
{
  public:
	x509name subject{};         // empty: --cn or --subject
	pki_x509 *parent{};         // nullptr: --parent, if given
	QStringList keyUsage{};     // empty: keyCertSign, cRLSign
	QString nameConstraints{};  // OpenSSL configuration value
	QString crlDistPoints{};    // OpenSSL configuration value
	/* the CRL settings, stored through CrlPolicy::store(); otherwise
	 * the --crl-* options */
	bool hasCrlPolicy{};
	CrlPolicy crlPolicy{};
	/* Password sources (env:, file:) for the keys: with passwords on,
	 * the new key gets a password of its own (XCA ptPrivate) from
	 * keyPassword, unless it is empty; signerPassword unlocks the
	 * parent's key; defaultPassword is the database password source */
	bool passwords{};
	QString keyPassword{}, signerPassword{}, defaultPassword{};
};

class CaCreated
{
  public:
	pki_key *key{};
	pki_x509 *cert{};
	pki_crl *crl{};             // nullptr when the CA is not valid now
};

/* init's CA: key, certificate (basicConstraints CA:TRUE critical, key
 * usage critical, SKI, AKI; pathLen only when given), the CRL settings
 * when given and the empty CRL (rule 7). With --plan only init's checks;
 * the result then holds nullptr. */
CaCreated createCa(CommandContext &ctx, const CaExtras &x = CaExtras());

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
/* A refusal of a handler before its service call (review of xca#62):
 * the failure entry of action the service would have written; pki is
 * the object if known. Not under --plan, whose cli.plan entry records
 * the run. */
void auditRefusal(const CommandContext &ctx, const QString &action,
		const pki_base *pki, const AuditParams &params,
		const QString &code);

/* RFC 4514 distinguished name; order kept, multi-valued RDNs (+),
 * UTF8String for directory strings. Throws usageError invalid_subject
 * naming the source: the option (--subject '<dn>' is no ...) or a JSON
 * pointer of the bootstrap file (/cas/2/subject: '<dn>' is no ...). */
x509name parseDn(const QString &rfc4514,
		const QString &source = QStringLiteral("--subject"));
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
/* Every name of the vocabulary, also those this build cannot generate */
QStringList keyTypeNames();

/* The command line option that supplies a secret of this purpose */
QString optionForPurpose(int purpose);

} // namespace bxcpki

#endif
