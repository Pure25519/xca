/* vi: set sw=4 ts=4:
 *
 * The option parser shared by every bxc-pki command (BTD-41): strict,
 * nothing is ignored or resolved silently. Unknown options, missing or
 * wrong values, repeated single options, conflicting options and
 * unexpected arguments are usage errors (JSON error, exit code 2).
 */

#include <QRegularExpression>
#include <QSet>

#include "lib/PwDialogCore.h"
#include "lib/func.h"
#include "cli.h"

namespace bxcpki {

Registry &Registry::instance()
{
	static Registry r;
	return r;
}

const Command *Registry::find(const QString &name) const
{
	for (const Command &c : commands)
		if (c.name == name)
			return &c;
	return nullptr;
}

static OptionSpec opt(const QString &name, enum OptionSpec::kind type,
		const QString &valueName, const QString &help)
{
	OptionSpec o;
	o.name = name;
	o.type = type;
	o.valueName = valueName;
	o.help = help;
	return o;
}

static OptionSpec secretOpt(const QString &name, const QString &help,
		QList<enum pass_info::purpose> purposes,
		const QString &reserved = QString())
{
	OptionSpec o = opt(name, OptionSpec::secret, "<source>", help);
	o.purposes = purposes;
	o.reserved = reserved;
	return o;
}

QList<OptionSpec> Registry::globalOptions()
{
	static const QString tokens = QObject::tr(
		"token PINs come with the PKCS#11 work of BTD-17");
	return QList<OptionSpec> {
		opt("db", OptionSpec::string, "<file>", QObject::tr(
			"XCA database (SQLite file), default ./bxc-pki.xdb")),
		secretOpt("password", QObject::tr(
			"database password; also the password of keys that "
			"have one of their own"), { pass_info::DatabasePassword,
			pass_info::KeyPassword }),
		secretOpt("sqlpass", QObject::tr(
			"password of a remote SQL database server"),
			{ pass_info::SqlPassword }),
		secretOpt("import-pass", QObject::tr(
			"password of an encrypted file that is read (PEM, DER, "
			"PKCS#8, PKCS#12)"), { pass_info::ImportPassword }),
		secretOpt("export-pass", QObject::tr(
			"password of an encrypted file that is written (export "
			"commands of BTD-42)"), { pass_info::ExportPassword }),
		secretOpt("pin", QObject::tr("token PIN"),
			{ pass_info::TokenPin }, tokens),
		secretOpt("so-pin", QObject::tr("token security officer PIN"),
			{ pass_info::TokenSoPin }, tokens),
		secretOpt("new-pin", QObject::tr("new token PIN"),
			{ pass_info::NewTokenPin }, tokens),
		secretOpt("new-so-pin", QObject::tr(
			"new token security officer PIN"),
			{ pass_info::NewTokenSoPin }, tokens),
		opt("interactive", OptionSpec::flag, QString(), QObject::tr(
			"ask on the terminal for a password without source "
			"(prompt on stderr); without it a missing source is an "
			"error")),
		opt("text", OptionSpec::flag, QString(), QObject::tr(
			"human readable output instead of JSON Lines")),
		opt("plan", OptionSpec::flag, QString(), QObject::tr(
			"writing commands: run everything, report what would be "
			"written, then roll back; nothing is written (keys and "
			"serials of a later real run differ)")),
		opt("help", OptionSpec::flag, QString(),
			QObject::tr("show the help of the command")),
	};
}

QList<QPair<QString, QString> > Registry::globalConflicts()
{
	return QList<QPair<QString, QString> >();
}

/* Only pass:, env:, file:, fd: and stdin; never a literal (BTD-30
 * side finding 4) */
static void checkSecret(const OptionSpec &o, const QString &v)
{
	static const QRegularExpression fd("^fd:[0-9]+$");
	bool ok = v == "stdin" || (v.startsWith("pass:") && v.size() > 5) ||
		(v.startsWith("env:") && v.size() > 4) ||
		(v.startsWith("file:") && v.size() > 5) || fd.match(v).hasMatch();
	if (!ok)
		throw usageError("invalid_secret_source", QObject::tr(
			"--%1 takes a source: pass:<password>, env:<variable>, "
			"file:<path>, fd:<number> or stdin; the given value "
			"is not one and is never used as the password")
			.arg(o.name));
	if (v.startsWith("pass:"))
		console_write(stderr, QObject::tr("Warning: --%1 pass:... puts "
			"the secret on the command line, where other users and "
			"the shell history can see it; prefer env:, file:, fd: "
			"or stdin\n").arg(o.name).toUtf8());
}

static void checkValue(const OptionSpec &o, const QString &v)
{
	static const QRegularExpression number("^[0-9]{1,9}$");

	switch (o.type) {
	case OptionSpec::flag:
		break;
	case OptionSpec::string:
	case OptionSpec::reference:
		if (v.isEmpty())
			throw usageError("invalid_value",
				QObject::tr("--%1 needs a non-empty value")
					.arg(o.name));
		break;
	case OptionSpec::integer:
		if (!number.match(v).hasMatch())
			throw usageError("invalid_value", QObject::tr(
				"--%1 needs a non-negative integer, not '%2'")
				.arg(o.name).arg(v));
		break;
	case OptionSpec::duration:
		parseDuration(v, o.name);
		break;
	case OptionSpec::timestamp:
		parseTimestamp(v, o.name);
		break;
	case OptionSpec::secret:
		checkSecret(o, v);
		break;
	}
}

Options parseOptions(const Command &cmd, const QStringList &argv)
{
	QList<OptionSpec> specs = Registry::globalOptions() + cmd.options;
	QMap<QString, OptionSpec> byName;
	Options opts;
	bool onlyArgs = false;

	for (const OptionSpec &o : specs)
		byName[o.name] = o;

	for (int i = 0; i < argv.size(); i++) {
		QString a = argv[i];
		if (onlyArgs || !a.startsWith("--")) {
			opts.addPositional(a);
			continue;
		}
		if (a == "--") {
			onlyArgs = true;
			continue;
		}
		QString name = a.mid(2), value;
		bool inlineValue = false;
		int eq = name.indexOf('=');
		if (eq >= 0) {
			value = name.mid(eq + 1);
			name = name.left(eq);
			inlineValue = true;
		}
		if (!byName.contains(name))
			throw usageError("unknown_option", QObject::tr(
				"Unknown option --%1 for '%2'; see bxc-pki %2 --help")
				.arg(name).arg(cmd.name));
		const OptionSpec &o = byName[name];
		if (o.type == OptionSpec::flag) {
			if (inlineValue)
				throw usageError("invalid_value", QObject::tr(
					"--%1 takes no value").arg(name));
		} else if (!inlineValue) {
			/* "--cn --db x": the next option is no value; a
			 * value starting with "--" needs --name=value */
			if (i + 1 >= argv.size() || argv[i + 1].startsWith("--"))
				throw usageError("missing_value", QObject::tr(
					"--%1 needs a value %2").arg(name)
					.arg(o.valueName));
			value = argv[++i];
		}
		if (opts.has(name) && !o.repeatable)
			throw usageError("duplicate_option", QObject::tr(
				"--%1 is given more than once").arg(name));
		if (!o.reserved.isEmpty())
			throw usageError("not_supported", QObject::tr(
				"--%1 is reserved: %2").arg(name).arg(o.reserved));
		checkValue(o, value);
		opts.add(name, value);
	}
	if (opts.has("help"))
		return opts;

	for (const OptionSpec &o : specs)
		if (o.required && !opts.has(o.name))
			throw usageError("missing_option", QObject::tr(
				"'%1' needs --%2 %3").arg(cmd.name).arg(o.name)
				.arg(o.valueName));
	for (const auto &c : Registry::globalConflicts() + cmd.conflicts)
		if (opts.has(c.first) && opts.has(c.second))
			throw usageError("conflicting_options", QObject::tr(
				"--%1 and --%2 exclude each other")
				.arg(c.first).arg(c.second));
	int n = opts.args().size();
	if (n < cmd.minArgs)
		throw usageError("missing_argument", QObject::tr(
			"'%1' needs %2").arg(cmd.name).arg(cmd.usage));
	if (n > cmd.maxArgs)
		throw usageError("unexpected_argument", QObject::tr(
			"Unexpected argument '%1' for '%2'")
			.arg(opts.args()[cmd.maxArgs]).arg(cmd.name));
	if (opts.has("plan") && !cmd.writes)
		throw usageError("conflicting_options", QObject::tr(
			"--plan applies to writing commands only, not to '%1'")
			.arg(cmd.name));
	return opts;
}

static QString optionLines(const QList<OptionSpec> &specs)
{
	QString s;
	for (const OptionSpec &o : specs) {
		QString head = QString("  --%1").arg(o.name);
		if (!o.valueName.isEmpty())
			head += " " + o.valueName;
		QStringList notes;
		if (o.required)
			notes << QObject::tr("required");
		if (o.repeatable)
			notes << QObject::tr("repeatable");
		if (!o.reserved.isEmpty())
			notes << QObject::tr("reserved: %1").arg(o.reserved);
		QString help = o.help;
		if (!notes.isEmpty())
			help += " (" + notes.join("; ") + ")";
		s += QString("%1\n      %2\n").arg(head).arg(help);
	}
	return s;
}

QString commandHelp(const Command &cmd)
{
	QString s = QString("bxc-pki %1 [options] %2\n  %3\n")
			.arg(cmd.name).arg(cmd.usage).arg(cmd.summary);
	if (!cmd.description.isEmpty())
		s += "\n" + cmd.description + "\n";
	if (!cmd.options.isEmpty())
		s += "\n" + QObject::tr("Options of %1:").arg(cmd.name) + "\n" +
			optionLines(cmd.options);
	QStringList c;
	for (const auto &p : cmd.conflicts)
		c << QString("--%1/--%2").arg(p.first).arg(p.second);
	if (!c.isEmpty())
		s += QObject::tr("  Mutually exclusive: %1").arg(c.join(", ")) +
			"\n";
	return s;
}

QString helpText()
{
	QString s = QObject::tr(
		"bxc-pki - headless PKI command line on an XCA database\n\n"
		"Usage: bxc-pki <command> [options] [arguments]\n"
		"       bxc-pki help [<command>]\n\n"
		"Output: one JSON document per line on stdout (JSON Lines), "
		"--text for people.\nMessages, warnings, prompts and errors go "
		"to stderr; an error is a JSON error object\n(urn:bxc-pki:schema:"
		"error:v1) there. Exit code 0 ok, 1 failure, 2 usage error.\n"
		"Secrets only as pass:<pw>, env:<var>, file:<path>, fd:<n> or "
		"stdin.\nReferences (--ca, --parent, --key, --template, show) "
		"are a database id or a unique name.\nDurations are ISO 8601 "
		"(P20Y, P1Y6M, P90D, PT12H), dates RFC 3339\n"
		"(2026-10-29T12:00:00Z).\n\nCommands:\n");
	for (const Command &c : Registry::instance().all())
		s += QString("  %1 %2\n").arg(c.name, -13).arg(c.summary);
	s += "\n" + QObject::tr("Options of every command:") + "\n" +
		optionLines(Registry::globalOptions());
	for (const Command &c : Registry::instance().all())
		s += "\n" + commandHelp(c);
	s += "\n" + QObject::tr("Key types: %1")
			.arg(supportedKeyTypes().join(", ")) + "\n";
	return s;
}

QString optionForPurpose(int purpose)
{
	for (const OptionSpec &o : Registry::globalOptions())
		if (o.purposes.contains((enum pass_info::purpose)purpose))
			return "--" + o.name;
	return QString();
}

} // namespace bxcpki
