/* vi: set sw=4 ts=4:
 *
 * export of bxc-pki part 2 (BTD-42): pem, der, pkcs8, p12 and chain of
 * single objects through the export service of BTD-34 (secure defaults of
 * BTD-52, rule 9), and the trust list of one or more CAs in a target
 * format of the trust-list format registry (opcua-dir, pem-bundle,
 * der-files; PLAN.md 14.6, OPC 10000-12 7.8.2). Files are staged before
 * the commit and published after it (cli/output.cpp).
 */

#include <QCryptographicHash>
#include <QDir>
#include <QJsonDocument>

#include "lib/BioByteArray.h"
#include "lib/PwDialogCore.h"
#include "lib/database_model.h"
#include "lib/db_base.h"
#include "lib/func.h"
#include "lib/importexport.h"
#include "lib/json_report.h"
#include "lib/pki_crl.h"
#include "lib/pki_evp.h"
#include "lib/pki_export.h"
#include "lib/pki_key.h"
#include "lib/pki_pkcs12.h"
#include "lib/pki_x509.h"
#include "lib/pki_x509req.h"
#include "cli.h"

namespace bxcpki {

static const QStringList exportFormats { "pem", "der", "pkcs8", "p12",
					"chain", "trustlist" };

/* --- Single objects ------------------------------------------------------ */

class ExportChoice
{
  public:
	int format{};
	QString ext{};
	QString kind{};
	bool secret{};
	pki_base *item{};
};

static serviceError notApplicable(const QString &format, const pki_base *pki)
{
	return serviceError("format_not_applicable", QObject::tr(
		"--format %1 is not possible for the %2 '%3'").arg(format)
		.arg(JsonReport::objectType(pki)).arg(pki->getIntName()));
}

/* The format of the export service for --format and the object */
static ExportChoice choose(const Options &o, pki_base *pki,
			const QString &format)
{
	ExportChoice c;
	QString type = JsonReport::objectType(pki);
	c.item = pki;
	if (type == "certificate" && format == "pkcs8") {
		/* the private key of the certificate */
		pki_key *key = static_cast<pki_x509 *>(pki)->getRefKey();
		if (!key || key->isPubKey())
			throw serviceError("no_private_key", QObject::tr(
				"There is no private key for '%1'")
				.arg(pki->getIntName()));
		pki = key;
		type = "key";
		c.item = key;
	}
	if (type == "certificate") {
		if (format == "pem") {
			c.format = 1; c.ext = "crt"; c.kind = "crt";
		} else if (format == "der") {
			c.format = 13; c.ext = "der"; c.kind = "der";
		} else if (format == "chain") {
			c.format = 2; c.ext = "chain.pem"; c.kind = "chain";
		} else if (format == "p12") {
			/* certificate, its key and the chain, AES-256 with
			 * PBKDF2 by default (BTD-52) */
			c.format = 14; c.ext = "p12"; c.kind = "p12";
			c.secret = true;
		}
	} else if (type == "key") {
		if (format == "pem") {
			c.format = 19; c.ext = "pub.pem"; c.kind = "public_key";
		} else if (format == "der") {
			c.format = 24; c.ext = "pub.der"; c.kind = "public_key";
		} else if (format == "pkcs8") {
			/* rule 9: encrypted PKCS#8 (PBES2); unencrypted and
			 * RFC 1423 PEM only on request */
			c.format = o.has("key-unencrypted") ? 29 :
				o.has("legacy-key-pem") ? 21 : 28;
			c.ext = "key"; c.kind = "key"; c.secret = true;
		}
	} else if (type == "request") {
		if (format == "pem") {
			c.format = 30; c.ext = "csr"; c.kind = "csr";
		} else if (format == "der") {
			c.format = 31; c.ext = "csr.der"; c.kind = "csr";
		}
	} else if (type == "crl") {
		if (format == "pem") {
			c.format = 32; c.ext = "crl"; c.kind = "crl";
		} else if (format == "der") {
			c.format = 33; c.ext = "crl.der"; c.kind = "crl";
		}
	}
	if (!c.format)
		throw notApplicable(format, pki);
	return c;
}

static void exportObject(CommandContext &ctx, pki_base *pki)
{
	const Options &o = ctx.opts;
	QString format = o.value("format");
	ExportChoice c = choose(o, pki, format);
	const pki_export *xport = pki_export::by_id(c.format);
	QString path = outPath(ctx, o.value("out"), c.item->getIntName(),
			c.item->getSqlItemId().toLongLong(), c.ext);
	bool encrypted = xport->match_all(F_CRYPT);

	if (o.has("pkcs12-algorithm") && format != "p12")
		throw usageError("conflicting_options", QObject::tr(
			"--pkcs12-algorithm needs --format p12"));
	if ((o.has("key-unencrypted") || o.has("legacy-key-pem")) &&
	    format != "pkcs8")
		throw usageError("conflicting_options", QObject::tr(
			"--key-unencrypted and --legacy-key-pem need --format "
			"pkcs8"));
	/* encrypted output only with --export-pass: no prompt (unless
	 * --interactive) and never an unencrypted file instead. A real run
	 * leaves it to the export service, which audits the refusal */
	if (ctx.plan && encrypted && !o.has("interactive") &&
	    !PwDialogCore::headless()->hasSource(pass_info::ExportPassword))
		throw secretError(secretError::missing, QObject::tr(
			"The %1 export of '%2' is encrypted and needs a password")
			.arg(xport->desc).arg(c.item->getIntName()),
			pass_info::ExportPassword);
	if (ctx.plan) {
		ctx.files->planned(path, c.kind, JsonReport::objectType(c.item),
			c.item->getIntName(), c.secret);
		return;
	}

	ExportSpec spec;
	spec.items << c.item;
	spec.format = xport;
	spec.publishedFile = path;
	spec.pkcs12Algorithm = o.value("pkcs12-algorithm");
	spec.privateKeyFormat = o.value("mldsa-key-format");
	QMap<QString, QString> mlDsa;
	spec.mlDsaWritten = &mlDsa;
	ctx.step = QObject::tr("file '%1'").arg(path);
	QByteArray data;
	try {
		data = Database.modelForPki(c.item)->exportItems(ctx.svc, spec);
	} catch (serviceError &err) {
		if (err.code == "missing_password" ||
		    err.code == "wrong_password")
			throw serviceError(err.code, err.getString() +
				QObject::tr(" (option --export-pass)"));
		throw;
	}
	QJsonObject info;
	info["format"] = format;
	info["encrypted"] = encrypted;
	if (xport->match_all(F_PKCS12))
		info["pkcs12_algorithm"] = spec.pkcs12Algorithm.isEmpty() ?
			encAlgo::forExport().name() : spec.pkcs12Algorithm;
	if (!mlDsa.isEmpty())
		info["ml_dsa_encoding"] = mlDsa.values().join(",");
	ctx.files->add(path, c.kind, c.item, data, c.secret, info);
	ctx.step.clear();
}

/* --- Trust lists ---------------------------------------------------------- */

/* One certificate or CRL of a trust list */
class TrustListItem
{
  public:
	QString kind{};          // ca_certificate, crl, leaf_certificate
	QString role{};          // trusted, issuer, own
	pki_base *object{};      // nullptr: a CRL --plan would issue
	QString name{};
	qint64 id{};
	/* the id of the file name: the CA's for a CRL, so that a new CRL
	 * replaces the file of the old one (review of xca#62) */
	qint64 fileId{};
	QByteArray der{}, pem{};
};

/* One file of a layout, relative to --out */
class TrustListFile
{
  public:
	QString path{};
	QString kind{};
	QList<const TrustListItem *> items{};
	QByteArray data{};
};

/* A target format: the extension point for device-specific layouts. A
 * new format is one more entry of trustListFormats(); the content
 * (which CAs, CRLs and leaves, in manifest order) and the checks
 * (CRL freshness, budgets) are the same for every format. */
class TrustListFormat
{
  public:
	QString name{};
	QString description{};
	QString onBudgetExceeded{ "warning" };
	std::function<QList<TrustListFile>(const QList<TrustListItem> &)>
		layout{};
};

/* The manifest of a trust list; an earlier one in --out is recognised by
 * it (StagedDirectory marker and schema) */
static const QString manifestName("manifest.json");
static const QString manifestSchema(
		"urn:bxc-pki:schema:trust-list-manifest:v1");

static QString itemFile(const TrustListItem &i, const QString &ext)
{
	return QString("%1-%2.%3").arg(fileBase(i.name))
		.arg(i.fileId).arg(ext);
}

static TrustListFile single(const QString &path, const QString &kind,
			const TrustListItem &i, bool pem)
{
	TrustListFile f;
	f.path = path;
	f.kind = kind;
	f.items << &i;
	f.data = pem ? i.pem : i.der;
	return f;
}

/* OPC 10000-12 7.8.2: trusted/certs, trusted/crl for the CAs whose
 * certificates are trusted, issuer/certs, issuer/crl for the CAs that
 * only build chains; DER files. Leaves (--leaf) in own/certs. */
static QList<TrustListFile> opcuaDir(const QList<TrustListItem> &items)
{
	QList<TrustListFile> l;
	for (const TrustListItem &i : items) {
		if (i.kind == "ca_certificate")
			l << single(QString("%1/certs/%2").arg(i.role)
				.arg(itemFile(i, "der")), "der", i, false);
		else if (i.kind == "crl")
			l << single(QString("%1/crl/%2").arg(i.role)
				.arg(itemFile(i, "crl")), "crl", i, false);
		else
			l << single(QString("own/certs/%1").arg(
				itemFile(i, "der")), "der", i, false);
	}
	return l;
}

/* All CA certificates, then all CRLs in one PEM file; leaves apart */
static QList<TrustListFile> pemBundle(const QList<TrustListItem> &items)
{
	TrustListFile bundle, leaves;
	bundle.path = "trustlist.pem";
	bundle.kind = "pem_bundle";
	leaves.path = "leaves.pem";
	leaves.kind = "pem_bundle";
	for (const TrustListItem &i : items) {
		TrustListFile &f = i.kind == "leaf_certificate" ? leaves :
								bundle;
		f.items << &i;
		f.data += i.pem;
	}
	QList<TrustListFile> l { bundle };
	if (!leaves.items.isEmpty())
		l << leaves;
	return l;
}

/* One DER file per certificate (.der) and CRL (.crl) */
static QList<TrustListFile> derFiles(const QList<TrustListItem> &items)
{
	QList<TrustListFile> l;
	for (const TrustListItem &i : items)
		l << single(QString("%1%2").arg(i.kind == "leaf_certificate" ?
			"leaf-" : "").arg(itemFile(i, i.kind == "crl" ? "crl" :
			"der")), i.kind == "crl" ? "crl" : "der", i, false);
	return l;
}

static const QList<TrustListFormat> &trustListFormats()
{
	static const QList<TrustListFormat> formats {
		{ "opcua-dir", QObject::tr("OPC UA directory layout: "
			"trusted/ and issuer/ with certs/ (DER) and crl/"),
			"warning", opcuaDir },
		{ "pem-bundle", QObject::tr("CA certificates, then CRLs in "
			"one PEM file trustlist.pem"), "warning", pemBundle },
		{ "der-files", QObject::tr("one DER file per certificate "
			"and CRL"), "warning", derFiles },
	};
	return formats;
}

static TrustListFormat trustListFormat(const QString &name)
{
	QStringList names;
	for (const TrustListFormat &f : trustListFormats()) {
		if (f.name == name)
			return f;
		names << f.name;
	}
	throw usageError("invalid_value", QObject::tr(
		"--target-format '%1' is not one of %2").arg(name)
		.arg(names.join(", ")));
}

static TrustListItem certItem(pki_x509 *cert, const QString &kind,
			const QString &role)
{
	TrustListItem i;
	i.kind = kind;
	i.role = role;
	i.object = cert;
	i.name = cert->getIntName();
	i.id = cert->getSqlItemId().toLongLong();
	i.fileId = i.id;
	i.der = cert->i2d();
	BioByteArray b;
	cert->pem(b);
	i.pem = b.byteArray();
	return i;
}

static TrustListItem crlItem(pki_crl *crl, pki_x509 *ca, const QString &role)
{
	TrustListItem i;
	i.kind = "crl";
	i.role = role;
	i.object = crl;
	i.name = ca->getIntName();
	i.fileId = ca->getSqlItemId().toLongLong();
	if (crl) {
		i.id = crl->getSqlItemId().toLongLong();
		i.der = crl->i2d();
		BioByteArray b;
		crl->pem(b);
		i.pem = b.byteArray();
	}
	return i;
}

/* The CRL of ca for the trust list: renewed when it is missing or past
 * its re-issue point (rule 7) unless --no-reissue or the CA has no
 * private key; a missing or expired one or one past the re-issue point
 * is refused without --allow-stale-crl (an S7 refuses the whole trust
 * list for one expired CRL, SMP-831). --force only replaces files: a
 * routine re-export needs it and must not switch this check off (review
 * of xca#62). */
static pki_crl *trustListCrl(CommandContext &ctx, pki_x509 *ca,
		const CrlPolicy &policy, QJsonObject *report)
{
	const Options &o = ctx.opts;
	bool allowStale = o.has("allow-stale-crl");
	QDateTime now = nowSeconds();
	pki_crl *crl = CrlPolicy::latestCrl(ca);
	pki_key *key = ca->getRefKey();
	bool canIssue = key && !key->isPubKey() && !o.has("no-reissue");
	QString trigger;

	if (canIssue && (!crl || policy.reissueDue(crl, now))) {
		trigger = crl ? "reissue_due" : "missing";
		crl = issueCrl(ctx, ca, policy, trigger, QDateTime(), false);
		if (!crl) {
			/* --plan */
			(*report)["ca_id"] = ca->getSqlItemId().toLongLong();
			(*report)["ca_name"] = ca->getIntName();
			(*report)["crl_id"] = QJsonValue();
			(*report)["trigger"] = trigger;
			(*report)["reissued"] = true;
			return nullptr;
		}
	}
	if (!crl) {
		if (!allowStale)
			throw serviceError("crl_missing", QObject::tr(
				"The CA '%1' has no CRL%2; every CA of a trust "
				"list needs one (--allow-stale-crl exports "
				"without)")
				.arg(ca->getIntName()).arg(canIssue ? QString() :
				QObject::tr(" and none can be issued here")));
		ctx.result->warning("crl_missing", QObject::tr(
			"The CA '%1' has no CRL").arg(ca->getIntName()));
		(*report)["ca_id"] = ca->getSqlItemId().toLongLong();
		(*report)["ca_name"] = ca->getIntName();
		(*report)["crl_id"] = QJsonValue();
		return nullptr;
	}
	*report = crlReport(crl, policy, now);
	(*report)["reissued"] = !trigger.isEmpty();
	if (!trigger.isEmpty())
		(*report)["trigger"] = trigger;
	QString code, why;
	if (CrlPolicy::expired(crl, now)) {
		code = "crl_expired";
		why = QObject::tr("The CRL %1 of '%2' expired on %3")
			.arg(crl->getSqlItemId().toString(), ca->getIntName(),
			crl->getNextUpdate().toPrettyGMT());
	} else if (policy.reissueDue(crl, now)) {
		code = "crl_reissue_due";
		why = QObject::tr("The CRL %1 of '%2' is past its re-issue "
			"point %3 and expires on %4")
			.arg(crl->getSqlItemId().toString(), ca->getIntName(),
			a1time(policy.reissueAt(crl)).toPrettyGMT(),
			crl->getNextUpdate().toPrettyGMT());
	}
	if (!code.isEmpty()) {
		if (!allowStale)
			throw serviceError(code, why + QObject::tr(
				"; a new CRL needs the CA key (without "
				"--no-reissue), or --allow-stale-crl exports it "
				"as it is"));
		ctx.result->warning(code, why);
	}
	return crl;
}

static void addCa(QList<pki_x509 *> &l, pki_x509 *ca)
{
	if (!l.contains(ca))
		l << ca;
}

static void exportTrustList(CommandContext &ctx)
{
	const Options &o = ctx.opts;
	const TrustListFormat format = trustListFormat(
			o.value("target-format", "opcua-dir"));
	QString action = o.value("on-budget-exceeded",
				format.onBudgetExceeded);
	if (action != "warning" && action != "error")
		throw usageError("invalid_value", QObject::tr(
			"--on-budget-exceeded '%1' is not one of warning, error")
			.arg(action));
	qint64 listBudget = CrlPolicy::defaultTrustListBudget;
	if (o.has("trust-list-budget")) {
		listBudget = o.value("trust-list-budget").toLongLong();
		if (listBudget < 1024)
			throw usageError("invalid_value", QObject::tr(
				"--trust-list-budget must be at least 1024"));
	}
	/* the trust list owns --out: empty, or exactly an earlier trust
	 * list (replaced with --force); anything else is refused */
	const QString out = o.value("out");
	ctx.files->addDirectory(out, manifestName, manifestSchema);

	/* trusted: the given CAs; issuer: their chains and --issuer-ca */
	QList<pki_x509 *> trusted, issuers;
	for (const QString &ref : o.args()) {
		pki_x509 *ca = resolveAs<pki_x509>(ref, "certificate",
						"<ca>");
		if (!ca->isCA())
			throw serviceError("issuer_not_ca", QObject::tr(
				"'%1' is not a CA certificate; a trust list "
				"holds CAs (leaves: --leaf)")
				.arg(ca->getIntName()));
		addCa(trusted, ca);
	}
	for (pki_x509 *ca : trusted) {
		pki_x509 *s = ca->getSigner();
		while (s && s != ca && !trusted.contains(s)) {
			addCa(issuers, s);
			if (s->getSigner() == s)
				break;
			s = s->getSigner();
		}
	}
	for (const QString &ref : o.all("issuer-ca")) {
		pki_x509 *ca = resolveAs<pki_x509>(ref, "certificate",
						"--issuer-ca");
		if (!ca->isCA())
			throw serviceError("issuer_not_ca", QObject::tr(
				"--issuer-ca '%1' is not a CA certificate")
				.arg(ca->getIntName()));
		if (!trusted.contains(ca))
			addCa(issuers, ca);
	}
	QList<pki_x509 *> leaves;
	for (const QString &ref : o.all("leaf"))
		leaves << resolveAs<pki_x509>(ref, "certificate", "--leaf");

	/* manifest order: CA certificates, then CRLs, then leaves (OPC UA
	 * push: the trust list before CreateSigningRequest and
	 * UpdateCertificate) */
	QList<TrustListItem> items;
	auto role = [&trusted](pki_x509 *ca) {
		return trusted.contains(ca) ? QString("trusted") :
						QString("issuer");
	};
	QList<pki_x509 *> cas = trusted + issuers;
	for (pki_x509 *ca : cas)
		items << certItem(ca, "ca_certificate", role(ca));
	qint64 size = 0;
	for (const TrustListItem &i : items)
		size += i.der.size();
	QStringList over;
	for (pki_x509 *ca : cas) {
		CrlPolicy policy = crlPolicy(o, ca);
		QJsonObject r;
		pki_crl *crl = trustListCrl(ctx, ca, policy, &r);
		r["role"] = role(ca);
		if (crl || ctx.plan) {
			TrustListItem i = crlItem(crl, ca, role(ca));
			size += i.der.size();
			items << i;
		}
		if (r.contains("within_budget") &&
		    !r["within_budget"].toBool())
			over << QObject::tr("the CRL of '%1' has %2 bytes, "
				"budget %3").arg(ca->getIntName())
				.arg(r["der_size"].toVariant().toString())
				.arg(policy.sizeBudget);
		ctx.result->append("crls", r);
	}
	for (pki_x509 *leaf : leaves)
		items << certItem(leaf, "leaf_certificate", "own");
	if (size > listBudget)
		over << QObject::tr("the trust list has %1 bytes, budget %2")
			.arg(size).arg(listBudget);

	QJsonObject tl;
	tl["target_format"] = format.name;
	tl["size"] = size;
	tl["budget"] = listBudget;
	tl["within_budget"] = size <= listBudget;
	tl["on_budget_exceeded"] = action;
	tl["ca_count"] = (qint64)cas.size();
	tl["leaf_count"] = (qint64)leaves.size();
	ctx.result->set("trust_list", tl);
	if (!over.isEmpty()) {
		QString why = over.join("; ");
		if (action == "error")
			throw serviceError("budget_exceeded", QObject::tr(
				"The %1 trust list exceeds its budget: %2")
				.arg(format.name, why));
		ctx.result->warning("budget_exceeded", why);
	}

	/* the files, then the manifest */
	QList<TrustListFile> files = format.layout(items);
	QJsonArray entries;
	int position = 0;
	for (const TrustListFile &f : files) {
		for (const TrustListItem *i : f.items) {
			QJsonObject e;
			e["position"] = ++position;
			e["kind"] = i->kind;
			e["role"] = i->role;
			e["path"] = f.path;
			e["name"] = i->name;
			e["object_id"] = i->id ? QJsonValue(i->id) : QJsonValue();
			if (!ctx.plan) {
				e["der_size"] = i->der.size();
				e["sha256"] = QString::fromLatin1(
					QCryptographicHash::hash(i->der,
					QCryptographicHash::Sha256).toHex());
			}
			pki_crl *crl = dynamic_cast<pki_crl *>(i->object);
			if (crl) {
				a1int no(0L);
				if (crl->getCrlNumber(&no))
					e["crl_number"] = no.toDec().toLongLong();
				e["this_update"] = JsonReport::timestamp(
						crl->getLastUpdate());
				e["next_update"] = JsonReport::timestamp(
						crl->getNextUpdate());
			}
			entries.append(e);
		}
	}
	QJsonObject manifest;
	manifest["schema"] = manifestSchema;
	manifest["target_format"] = format.name;
	manifest["created"] = JsonReport::timestamp(a1time(nowSeconds()));
	manifest["order"] = QString("ca_certificate, crl, leaf_certificate");
	manifest["size"] = size;
	manifest["budget"] = listBudget;
	manifest["entries"] = entries;

	/* --out was checked and staged by addDirectory(): the files go to
	 * its sibling, which replaces it as a whole after the commit; no
	 * file of an earlier export stays (review of xca#62) */
	if (ctx.plan) {
		for (const TrustListFile &f : files)
			ctx.files->planned(QDir(out).filePath(f.path), f.kind,
				QString(), QString(), false);
		ctx.files->planned(QDir(out).filePath(manifestName),
			"manifest", QString(), QString(), false);
		return;
	}
	for (const TrustListFile &f : files)
		ctx.files->add(QDir(out).filePath(f.path), f.kind,
			f.items.size() == 1 ? f.items[0]->object : nullptr,
			f.data, false);
	ctx.files->add(QDir(out).filePath(manifestName), "manifest",
		nullptr, QJsonDocument(manifest).toJson(), false);

	AuditParams p;
	p.set("format", format.name);
	p.set("file", out);
	p.set("count", (qint64)items.size());
	p.set("der_size", size);
	p.set("trust_list_budget", listBudget);
	QStringList names;
	for (pki_x509 *ca : trusted)
		names << ca->getIntName();
	p.set("name", names.join(","));
	if (!over.isEmpty())
		p.warn("budget_exceeded");
	AuditLog::append(ctx.svc, "trustlist.export", "object", QString(), p);
}

/* --- export ------------------------------------------------------------- */

static void cmdExport(CommandContext &ctx)
{
	const Options &o = ctx.opts;
	QString format = o.value("format");
	if (!exportFormats.contains(format))
		throw usageError("invalid_value", QObject::tr(
			"--format '%1' is not one of %2").arg(format)
			.arg(exportFormats.join(", ")));
	static const QStringList trustListOnly { "target-format", "leaf",
		"issuer-ca", "no-reissue", "allow-stale-crl",
		"trust-list-budget", "on-budget-exceeded", "crl-validity",
		"crl-reissue-fraction", "crl-size-budget" };
	if (format != "trustlist")
		for (const QString &n : trustListOnly)
			if (o.has(n))
				throw usageError("conflicting_options",
					QObject::tr("--%1 needs --format "
					"trustlist").arg(n));
	if (o.has("mldsa-key-format") &&
	    !pki_evp::mlDsaFormats.contains(o.value("mldsa-key-format")))
		throw usageError("invalid_value", QObject::tr(
			"--mldsa-key-format '%1' is not one of %2")
			.arg(o.value("mldsa-key-format"))
			.arg(pki_evp::mlDsaFormats.join(", ")));
	checkOutOptions(ctx, false);

	if (format == "trustlist") {
		for (const QString &n : { QString("key-unencrypted"),
				QString("legacy-key-pem"),
				QString("pkcs12-algorithm"),
				QString("mldsa-key-format"), QString("type") })
			if (o.has(n))
				throw usageError("conflicting_options",
					QObject::tr("--%1 does not apply to "
					"--format trustlist").arg(n));
		try {
			exportTrustList(ctx);
		} catch (serviceError &err) {
			AuditParams p;
			p.set("format", o.value("target-format", "opcua-dir"));
			p.set("file", o.value("out"));
			AuditLog::appendFailure(ctx.svc, "trustlist.export",
				"object", QString(), p, err.code);
			throw;
		}
		return;
	}
	QStringList kinds { "certificate", "key", "request", "crl" };
	if (o.has("type")) {
		if (!kinds.contains(o.value("type")))
			throw usageError("invalid_value", QObject::tr(
				"--type '%1' is not one of %2")
				.arg(o.value("type")).arg(kinds.join(", ")));
		kinds = QStringList(o.value("type"));
	}
	for (const QString &ref : o.args()) {
		/* the refusals before the export service, audited like its
		 * own (review of xca#62) */
		pki_base *pki = nullptr;
		try {
			pki = resolve(ref, kinds, "<object>");
			choose(o, pki, format);
		} catch (serviceError &err) {
			AuditParams p;
			p.set("format", format);
			p.set("name", pki ? pki->getIntName() : ref);
			auditRefusal(ctx, "object.export", pki, p, err.code);
			throw;
		}
		exportObject(ctx, pki);
	}
}

/* --- Registration ------------------------------------------------------- */

void registerExportCommands(Registry &r)
{
	QStringList tf;
	for (const TrustListFormat &f : trustListFormats())
		tf << QString("%1 (%2)").arg(f.name, f.description);
	Command c;
	c.name = "export";
	c.usage = "<object>...";
	c.summary = QObject::tr("write objects or a trust list to files");
	c.description = QObject::tr(
		"  certificate: pem (.crt), der (.der), chain (.chain.pem), p12 "
		"(certificate, key\n  and chain, AES-256-CBC with PBKDF2), pkcs8 "
		"(its private key). key: pem and der\n  (public key), pkcs8 "
		"(encrypted PKCS#8 with PBES2). request, crl: pem, der.\n  "
		"Encrypted formats take the password from --export-pass only. "
		"trustlist: the\n  given CAs are trusted, their chains issuers; "
		"every CA comes with its CRL,\n  renewed when it is past its "
		"re-issue point; manifest.json lists CAs, then\n  CRLs, then "
		"leaves.");
	c.options = QList<OptionSpec> {
		opt("format", OptionSpec::string, "<format>", QObject::tr(
			"%1").arg(exportFormats.join(", ")), false, true),
		opt("out", OptionSpec::string, "<dir>", QObject::tr(
			"existing directory for the files"), false, true),
		opt("type", OptionSpec::string, "<type>", QObject::tr(
			"the reference names a certificate, key, request or "
			"crl")),
		opt("layout", OptionSpec::string, "<layout>", QObject::tr(
			"file names: id (default, <name>-<id>.<ext>) or "
			"certstrap (<name>.<ext>)")),
		opt("force", OptionSpec::flag, QString(), QObject::tr(
			"replace existing files; trustlist: replace the trust "
			"list in --out")),
		opt("key-unencrypted", OptionSpec::flag, QString(),
			QObject::tr("pkcs8: unencrypted PKCS#8 (legacy, "
			"explicit only)")),
		opt("legacy-key-pem", OptionSpec::flag, QString(),
			QObject::tr("pkcs8: OpenSSL traditional PEM with RFC "
			"1423 encryption, PKCS#1 for RSA (legacy, explicit "
			"only)")),
		opt("pkcs12-algorithm", OptionSpec::string, "<algorithm>",
			QObject::tr("p12: another encryption, e.g. "
			"PBE-SHA1-3DES for a legacy reader (default "
			"AES-256-CBC)")),
		opt("mldsa-key-format", OptionSpec::string, "<encoding>",
			QObject::tr("ML-DSA private key encoding of pkcs8 and "
			"p12 (RFC 9881): both, seed, expanded (default: both, "
			"or expanded for a key without seed)")),
		opt("target-format", OptionSpec::string, "<format>",
			QObject::tr("trustlist: %1; default opcua-dir")
			.arg(tf.join(", "))),
		opt("issuer-ca", OptionSpec::reference, "<ca>", QObject::tr(
			"trustlist: one more CA only for chain building "
			"(issuer/)"), true),
		opt("leaf", OptionSpec::reference, "<certificate>",
			QObject::tr("trustlist: a leaf certificate, after the "
			"CAs and CRLs (own/)"), true),
		opt("no-reissue", OptionSpec::flag, QString(), QObject::tr(
			"trustlist: issue no CRL; export the stored ones (an "
			"expired one or one past its re-issue point only with "
			"--allow-stale-crl)")),
		opt("allow-stale-crl", OptionSpec::flag, QString(),
			QObject::tr("trustlist: also export a CA without CRL, "
			"with an expired CRL or one past its re-issue point, "
			"with a warning (a device may refuse the whole list)")),
		opt("trust-list-budget", OptionSpec::integer, "<bytes>",
			QObject::tr("trustlist: size budget of the whole list, "
			"at least 1024 (default %1)")
			.arg(CrlPolicy::defaultTrustListBudget)),
		opt("on-budget-exceeded", OptionSpec::string, "<action>",
			QObject::tr("trustlist: warning (default) or error")),
	} + crlOptions(QObject::tr("; for this export target"));
	c.conflicts = QList<QPair<QString, QString> > {
		{ "key-unencrypted", "legacy-key-pem" } };
	c.minArgs = 1;
	c.maxArgs = 100;
	c.writes = true;
	c.handler = cmdExport;
	r.add(c);
}

} // namespace bxcpki
