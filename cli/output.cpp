/* vi: set sw=4 ts=4:
 *
 * File output of the bxc-pki command line (BTD-42): --out <dir> of init,
 * request-cert, sign, crl and revoke (certstrap layout) and the files of
 * export. Every file goes through lib/staged_file.h: staged before the
 * database commit, published after it (cli/README.md "Files").
 */

#include <QCryptographicHash>
#include <QDir>
#include <QFileInfo>
#include <QRegularExpression>

#include "lib/PwDialogCore.h"
#include "lib/database_model.h"
#include "lib/db_base.h"
#include "lib/digest.h"
#include "lib/func.h"
#include "lib/importexport.h"
#include "lib/json_report.h"
#include "lib/pki_crl.h"
#include "lib/pki_export.h"
#include "lib/pki_key.h"
#include "lib/pki_x509.h"
#include "lib/pki_x509req.h"
#include "lib/staged_file.h"
#include "cli.h"

namespace bxcpki {

/* --- OutputFiles -------------------------------------------------------- */

static QString absolute(const QString &path)
{
	return QDir::cleanPath(QFileInfo(path).absoluteFilePath());
}

static void checkUnique(const QList<OutputFiles::entry> &files,
			const QString &path)
{
	for (const OutputFiles::entry &f : files)
		if (absolute(f.path) == absolute(path))
			throw serviceError("file_exists", QObject::tr(
				"The command would write '%1' twice; use "
				"--layout id").arg(QDir::toNativeSeparators(
					path)));
}

void OutputFiles::add(const QString &path, const QString &kind,
		const pki_base *pki, const QByteArray &data, bool secret,
		const QJsonObject &info)
{
	checkUnique(files, path);
	entry e;
	e.info = info;
	e.path = path;
	e.kind = kind;
	if (pki) {
		e.objectType = JsonReport::objectType(pki);
		e.objectId = pki->getSqlItemId().toLongLong();
		e.objectName = pki->getIntName();
	}
	e.secret = secret;
	e.size = data.size();
	e.sha256 = QString::fromLatin1(QCryptographicHash::hash(data,
			QCryptographicHash::Sha256).toHex());
	/* below a staged directory: into its sibling, which is new */
	QString staged = directory ? directory->stagedPath(path) : QString();
	if (!staged.isEmpty() &&
	    !QDir().mkpath(QFileInfo(staged).absolutePath()))
		throw serviceError("write_failed", QObject::tr(
			"Creating the directory of '%1' failed")
			.arg(QDir::toNativeSeparators(path)));
	e.file = std::make_shared<StagedFile>(staged.isEmpty() ? path : staged,
			secret, staged.isEmpty() && force);
	e.file->stage(data);
	files << e;
}

void OutputFiles::addDirectory(const QString &dir, const QString &marker,
		const QString &schema)
{
	if (plan) {
		StagedDirectory::checkTarget(dir, marker, schema, force);
		plannedDirectory = QDir::cleanPath(QFileInfo(dir)
					.absoluteFilePath());
		return;
	}
	directory = std::make_shared<StagedDirectory>(dir, marker, schema,
						force);
	directory->stage();
}

QString OutputFiles::leftover() const
{
	return directory ? directory->leftover() : QString();
}

bool OutputFiles::written(const entry &e) const
{
	if (plan || !e.file || !e.file->isPublished())
		return false;
	return !directory || !directory->contains(e.path) ||
		directory->isPublished();
}

void OutputFiles::planned(const QString &path, const QString &kind,
		const QString &type, const QString &name, bool secret)
{
	checkUnique(files, path);
	/* a directory the run would create (trust lists): its nearest
	 * existing ancestor must be a writable directory */
	QString dir = QFileInfo(path).absolutePath();
	bool missing = false;
	while (!QFileInfo::exists(dir) && dir != QFileInfo(dir).absolutePath()) {
		dir = QFileInfo(dir).absolutePath();
		missing = true;
	}
	/* below a directory of addDirectory(): checked as a whole there */
	QString abs = QDir::cleanPath(QFileInfo(path).absoluteFilePath());
	bool inDirectory = !plannedDirectory.isEmpty() &&
		abs.startsWith(plannedDirectory + "/");
	if (!inDirectory && (missing || path.contains("{id}")))
		StagedFile::checkTarget(dir + "/.bxc-pki-plan-check", true);
	else if (!inDirectory)
		StagedFile::checkTarget(path, force);
	entry e;
	e.path = path;
	e.kind = kind;
	e.objectType = type;
	e.objectName = name;
	e.secret = secret;
	files << e;
}

void OutputFiles::publish()
{
	if (plan || done)
		return;
	for (entry &e : files)
		e.file->publish();
	if (directory)
		directory->publish();
	done = true;
}

void OutputFiles::discard()
{
	for (entry &e : files)
		if (e.file)
			e.file->discard();
	if (directory)
		directory->discard();
}

QJsonArray OutputFiles::json() const
{
	QJsonArray a;
	for (const entry &e : files) {
		QJsonObject o = e.info;
		o["path"] = e.path;
		o["kind"] = e.kind;
		o["secret"] = e.secret;
		o["written"] = written(e);
		if (!plan) {
			o["size"] = e.size;
			o["sha256"] = e.sha256;
		}
		if (!e.objectType.isEmpty()) {
			o["object_type"] = e.objectType;
			o["object_id"] = e.objectId ? QJsonValue(e.objectId) :
						QJsonValue();
			o["object_name"] = e.objectName;
		}
		a.append(o);
	}
	return a;
}

/* --- --out ------------------------------------------------------------- */

QList<OptionSpec> outOptions(bool withKey)
{
	QList<OptionSpec> l {
		opt("out", OptionSpec::string, "<dir>", QObject::tr(
			"also write the files of the certstrap layout "
			"(<name>.key, .csr, .crt, .crl) to this existing "
			"directory, after the database commit")),
		opt("layout", OptionSpec::string, "<layout>", QObject::tr(
			"file names under --out: id (default, <name>-<id>.<ext>, "
			"never two objects in one file) or certstrap "
			"(<name>.<ext>, refused when the file exists)")),
		opt("force", OptionSpec::flag, QString(), QObject::tr(
			"replace existing files (otherwise file_exists)")),
	};
	if (withKey)
		l << opt("key-unencrypted", OptionSpec::flag, QString(),
			QObject::tr("--out: write the key file as unencrypted "
			"PKCS#8 (default: encrypted PKCS#8 with --export-pass)"))
		  << opt("no-key-file", OptionSpec::flag, QString(),
			QObject::tr("--out: no key file; the key stays in the "
			"database only"));
	return l;
}

QString fileBase(const QString &name)
{
	static const QRegularExpression bad("[^A-Za-z0-9._+@-]");
	QString s = name;
	/* certstrap: spaces become underscores */
	s.replace(' ', '_');
	s.replace(bad, "_");
	if (s.startsWith('.'))
		s[0] = '_';
	return s.isEmpty() ? QString("unnamed") : s;
}

QString outPath(const CommandContext &ctx, const QString &dir,
		const QString &name, qint64 id, const QString &ext)
{
	QString base = fileBase(name);
	if (ctx.opts.value("layout", "id") == "id")
		base += id > 0 ? QString("-%1").arg(id) : QString("-{id}");
	return QDir(dir).filePath(base + "." + ext);
}

static void checkLayout(const Options &o)
{
	QString l = o.value("layout", "id");
	if (l != "id" && l != "certstrap")
		throw usageError("invalid_value", QObject::tr(
			"--layout '%1' is not one of id, certstrap").arg(l));
	for (const QString &n : { QString("layout"),
				QString("key-unencrypted"),
				QString("no-key-file") })
		if (o.has(n) && !o.has("out"))
			throw usageError("conflicting_options", QObject::tr(
				"--%1 needs --out").arg(n));
}

void checkOutOptions(const CommandContext &ctx, bool writesKey)
{
	const Options &o = ctx.opts;
	checkLayout(o);
	if (!o.has("out"))
		return;
	QFileInfo dir(o.value("out"));
	if (!dir.isDir())
		throw serviceError("invalid_output", QObject::tr(
			"--out '%1' is no existing directory")
			.arg(o.value("out")));
	if (writesKey && !o.has("key-unencrypted") && !o.has("no-key-file") &&
	    !PwDialogCore::headless()->hasSource(pass_info::ExportPassword) &&
	    !o.has("interactive"))
		throw secretError(secretError::missing, QObject::tr(
			"--out writes the key file encrypted and needs its "
			"password; or give --key-unencrypted or --no-key-file"),
			pass_info::ExportPassword);
}

/* The export format of a file of the certstrap layout */
static int formatOf(const QString &kind, bool unencrypted)
{
	if (kind == "key")
		return unencrypted ? 29 : 28;  // PKCS#8 (encrypted)
	if (kind == "csr")
		return 30;
	if (kind == "crt")
		return 1;
	return 32;                         // crl, PEM
}

void writeOut(CommandContext &ctx, pki_base *pki, const QString &kind,
		const QString &plannedName)
{
	const Options &o = ctx.opts;
	if (!o.has("out") || (kind == "key" && o.has("no-key-file")))
		return;
	bool secret = kind == "key";
	if (ctx.plan) {
		QString name = pki ? pki->getIntName() : plannedName;
		qint64 id = pki ? pki->getSqlItemId().toLongLong() : 0;
		ctx.files->planned(outPath(ctx, o.value("out"), name, id, kind),
			kind, kind == "key" ? "key" : kind == "csr" ? "request" :
			kind == "crt" ? "certificate" : "crl", name, secret);
		return;
	}
	QString path = outPath(ctx, o.value("out"), pki->getIntName(),
			pki->getSqlItemId().toLongLong(), kind);
	/* every file passes the export service: one object.export entry,
	 * key.export_private for the key */
	ExportSpec spec;
	spec.items << pki;
	spec.format = pki_export::by_id(formatOf(kind,
					o.has("key-unencrypted")));
	spec.publishedFile = path;
	db_base *db = Database.modelForPki(pki);
	QString step = ctx.step;
	ctx.step = QObject::tr("file '%1'").arg(path);
	QByteArray data;
	try {
		data = db->exportItems(ctx.svc, spec);
	} catch (serviceError &err) {
		if (err.code == "missing_password")
			throw serviceError(err.code, err.getString() +
				QObject::tr(" (option --export-pass)"));
		throw;
	}
	ctx.files->add(path, kind, pki, data, secret);
	ctx.step = step;
}

} // namespace bxcpki
