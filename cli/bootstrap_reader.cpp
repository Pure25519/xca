/* vi: set sw=4 ts=4:
 *
 * The strict reader of the bootstrap file (BTD-166, cli/bootstrap.h):
 * the members of this phase (database, cas, profiles, policies) are
 * checked as bxc-pki schemas/bootstrap.schema.json checks them (types,
 * enums, patterns, required and unknown members); the elements of later
 * phases only for their type and for literal secrets. Every error is
 * invalid_bootstrap_file with the JSON pointer of the member in front of
 * the detail. The patterns are those of the schema (ECMA-262) written for
 * PCRE: '$' as \z (PCRE's $ also matches before a final line feed) and
 * '.' as a class without the line terminators.
 */

#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QRegularExpression>
#include <QSet>

#include <cmath>

#include "lib/crl_policy.h"
#include "bootstrap.h"

namespace bxcpki {

QString jsonMember(const QString &ptr, const QString &key)
{
	QString k = key;
	k.replace("~", "~0").replace("/", "~1");
	return ptr + "/" + k;
}

QString jsonItem(const QString &ptr, int i)
{
	return ptr + "/" + QString::number(i);
}

QString shownPointer(const QString &ptr)
{
	return ptr.isEmpty() ? QString("/") : ptr;
}

serviceError located(const QString &ptr, const errorEx &err,
		const QString &code)
{
	const serviceError *s = dynamic_cast<const serviceError *>(&err);
	QString c = code;
	if (c.isEmpty())
		c = s ? s->code : QString("internal_error");
	if (dynamic_cast<const secretError *>(&err))
		c = "missing_password";
	return serviceError(c, QString("%1: %2").arg(shownPointer(ptr))
			.arg(err.getString()));
}

namespace {

QString tr(const char *s)
{
	return QObject::tr(s);
}

[[noreturn]] void bad(const QString &ptr, const QString &why)
{
	throw serviceError("invalid_bootstrap_file",
		QString("%1: %2").arg(shownPointer(ptr), why));
}

#define DOT "[^\\n\\r\\x{2028}\\x{2029}]"
#define LABEL "[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
#define OCTET "(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
#define IPV6 "(([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|" \
	"([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0,6})?::" \
	"([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0,6})?)"

QRegularExpression pattern(const char *p)
{
	return QRegularExpression(QString::fromLatin1(p),
		QRegularExpression::UseUnicodePropertiesOption);
}

const QRegularExpression &idRe()
{
	static const QRegularExpression r = pattern("^[a-z0-9][a-z0-9-]{0,62}\\z");
	return r;
}

const QRegularExpression &durationRe()
{
	static const QRegularExpression r = pattern("^P(?!\\z)([0-9]+Y)?"
		"([0-9]+M)?([0-9]+W)?([0-9]+D)?(T(?=[0-9])([0-9]+H)?"
		"([0-9]+M)?([0-9]+S)?)?\\z");
	return r;
}

const QRegularExpression &secretRe()
{
	static const QRegularExpression r = pattern("^(env:[A-Za-z_]"
		"[A-Za-z0-9_]*|file:" DOT "+|op://[^/]+/[^/]+/" DOT "+)\\z");
	return r;
}

const QRegularExpression &timestampRe()
{
	static const QRegularExpression r = pattern("^[0-9]{4}-[0-9]{2}-"
		"[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,9})?Z\\z");
	return r;
}

const QRegularExpression &uriRe()
{
	static const QRegularExpression r =
		pattern("^[A-Za-z][A-Za-z0-9+.-]*:[^\\s]+\\z");
	return r;
}

const QStringList keyUsageNames {
	"digitalSignature", "nonRepudiation", "contentCommitment",
	"keyEncipherment", "dataEncipherment", "keyAgreement",
	"keyCertSign", "cRLSign", "encipherOnly", "decipherOnly",
};

/* --- typed values --------------------------------------------------------- */

QJsonObject asObject(const QJsonValue &v, const QString &ptr)
{
	if (!v.isObject())
		bad(ptr, tr("must be an object"));
	return v.toObject();
}

QJsonArray asArray(const QJsonValue &v, const QString &ptr, int minItems)
{
	if (!v.isArray())
		bad(ptr, tr("must be an array"));
	QJsonArray a = v.toArray();
	if (a.size() < minItems)
		bad(ptr, tr("needs at least %1 item(s)").arg(minItems));
	return a;
}

QString asString(const QJsonValue &v, const QString &ptr, int minLength = 0)
{
	if (!v.isString())
		bad(ptr, tr("must be a string"));
	QString s = v.toString();
	if (s.size() < minLength)
		bad(ptr, tr("must not be empty"));
	return s;
}

qint64 asInteger(const QJsonValue &v, const QString &ptr, qint64 min,
		qint64 max)
{
	double d = v.toDouble();
	/* JSON Schema: a number without a fraction is an integer */
	if (!v.isDouble() || std::floor(d) != d)
		bad(ptr, tr("must be an integer"));
	if (d < (double)min || d > (double)max)
		bad(ptr, tr("must be from %1 to %2").arg(min).arg(max));
	return (qint64)d;
}

bool asBool(const QJsonValue &v, const QString &ptr)
{
	if (!v.isBool())
		bad(ptr, tr("must be true or false"));
	return v.toBool();
}

QString matching(const QJsonValue &v, const QString &ptr,
		const QRegularExpression &re, const QString &what)
{
	QString s = asString(v, ptr);
	if (!re.match(s).hasMatch())
		bad(ptr, tr("'%1' is no %2").arg(s, what));
	return s;
}

QString oneOf(const QJsonValue &v, const QString &ptr,
		const QStringList &values)
{
	QString s = asString(v, ptr);
	if (!values.contains(s))
		bad(ptr, tr("'%1' is not one of %2").arg(s, values.join(", ")));
	return s;
}

void onlyMembers(const QJsonObject &o, const QString &ptr,
		const QStringList &allowed)
{
	for (const QString &k : o.keys())
		if (!allowed.contains(k))
			bad(jsonMember(ptr, k), tr("unknown member (allowed: "
				"%1)").arg(allowed.join(", ")));
}

void requireMembers(const QJsonObject &o, const QString &ptr,
		const QStringList &required)
{
	for (const QString &k : required)
		if (!o.contains(k))
			bad(jsonMember(ptr, k),
				tr("required member is missing"));
}

QString duration(const QJsonValue &v, const QString &ptr)
{
	QString s = matching(v, ptr, durationRe(),
		tr("ISO 8601 duration (e.g. P20Y, P90D)"));
	if (!IsoDuration::parse(s).isValid())
		bad(ptr, tr("'%1' is no ISO 8601 duration").arg(s));
	return s;
}

/* RFC 3339 in UTC; a fraction of a second only when it is zero,
 * because the certificate times have whole seconds */
QString timestamp(const QJsonValue &v, const QString &ptr)
{
	QString s = matching(v, ptr, timestampRe(),
		tr("RFC 3339 date-time in UTC (e.g. 2026-11-01T00:00:00Z)"));
	int dot = s.indexOf('.');
	if (dot > 0) {
		QString frac = s.mid(dot + 1).chopped(1);
		if (frac.count('0') != frac.size())
			throw serviceError("invalid_value", QString("%1: %2")
				.arg(ptr, tr("'%1' has a fraction of a second; "
				"certificate times are whole seconds").arg(s)));
		s = s.left(dot) + "Z";
	}
	if (!QDateTime::fromString(s, Qt::ISODate).isValid())
		throw serviceError("invalid_value", QString("%1: %2").arg(ptr,
			tr("'%1' is no valid date-time").arg(s)));
	return s;
}

/* Never shows the value: it may be the secret itself */
QString secretRef(const QJsonValue &v, const QString &ptr)
{
	if (!v.isString())
		bad(ptr, tr("must be a secret reference (a string)"));
	if (!secretRe().match(v.toString()).hasMatch())
		bad(ptr, tr("is no secret reference: a secret field takes "
			"env:<VARIABLE>, file:<path> or op://<vault>/<item>/"
			"<field>, never the secret itself (the value is not "
			"shown and never used)"));
	return v.toString();
}

/* --- database ------------------------------------------------------------- */

void readDatabase(FileDef &f, const QJsonValue &v)
{
	const QString ptr = "/database";
	QJsonObject o = asObject(v, ptr);
	requireMembers(o, ptr, { "type" });
	f.dbType = oneOf(o["type"], jsonMember(ptr, "type"),
			{ "sqlite", "postgresql", "mariadb" });
	if (f.dbType == "sqlite") {
		onlyMembers(o, ptr, { "type", "path", "password" });
		requireMembers(o, ptr, { "path", "password" });
		f.dbPath = asString(o["path"], jsonMember(ptr, "path"), 1);
	} else {
		onlyMembers(o, ptr, { "type", "host", "port", "name", "user",
				"password", "key_password" });
		requireMembers(o, ptr, { "host", "name", "user", "password" });
		f.dbHost = asString(o["host"], jsonMember(ptr, "host"), 1);
		f.dbName = asString(o["name"], jsonMember(ptr, "name"), 1);
		f.dbUser = asString(o["user"], jsonMember(ptr, "user"), 1);
		if (o.contains("port"))
			f.dbPort = (int)asInteger(o["port"],
				jsonMember(ptr, "port"), 1, 65535);
		if (o.contains("key_password")) {
			f.dbKeyPassword.pointer =
				jsonMember(ptr, "key_password");
			f.dbKeyPassword.value = secretRef(o["key_password"],
				f.dbKeyPassword.pointer);
		}
	}
	f.dbPassword.pointer = jsonMember(ptr, "password");
	f.dbPassword.value = secretRef(o["password"], f.dbPassword.pointer);
}

/* --- CAs ------------------------------------------------------------------ */

void readDn(CaDef &c, const QJsonValue &v, const QString &ptr)
{
	static const QRegularExpression text =
		pattern("^[^=,+]+=[^\\s]" DOT "*\\z");
	static const QRegularExpression type = pattern(
		"^([A-Za-z][A-Za-z0-9-]*|[0-2](\\.(0|[1-9][0-9]*))+)\\z");
	if (v.isString()) {
		matching(v, ptr, text, tr("RFC 4514 distinguished name"));
	} else if (v.isArray()) {
		QJsonArray rdns = asArray(v, ptr, 1);
		for (int i = 0; i < rdns.size(); i++) {
			QString rp = jsonItem(ptr, i);
			QJsonArray rdn = asArray(rdns[i], rp, 1);
			for (int k = 0; k < rdn.size(); k++) {
				QString ap = jsonItem(rp, k);
				QJsonObject a = asObject(rdn[k], ap);
				onlyMembers(a, ap, { "type", "value" });
				requireMembers(a, ap, { "type", "value" });
				matching(a["type"], jsonMember(ap, "type"), type,
					tr("attribute type (short name or "
					"dotted OID)"));
				asString(a["value"], jsonMember(ap, "value"), 1);
			}
		}
	} else {
		bad(ptr, tr("must be an RFC 4514 string or a list of RDNs"));
	}
	c.dn = v;
}

void readNameSet(const QJsonValue &v, const QString &ptr)
{
	static const QRegularExpression host =
		pattern("^\\.?(" LABEL "\\.)*" LABEL "\\z");
	static const QRegularExpression mail =
		pattern("^([^@\\s]+@)?\\.?(" LABEL "\\.)*" LABEL "\\z");
	static const QRegularExpression net = pattern("^((" OCTET "\\.){3}"
		OCTET "/(3[0-2]|[12]?[0-9])|" IPV6
		"/(12[0-8]|1[01][0-9]|[1-9]?[0-9]))\\z");
	QJsonObject o = asObject(v, ptr);
	onlyMembers(o, ptr, { "dns", "ip", "uri", "email" });
	if (o.isEmpty())
		bad(ptr, tr("needs at least one of dns, ip, uri, email"));
	const QMap<QString, QPair<const QRegularExpression *, QString> > kinds {
		{ "dns", { &host, tr("host name or domain with a leading "
			"dot") } },
		{ "ip", { &net, tr("IP network in CIDR notation") } },
		{ "uri", { &host, tr("host or domain with a leading dot") } },
		{ "email", { &mail, tr("mailbox, host or domain with a "
			"leading dot") } },
	};
	for (const QString &k : o.keys()) {
		QString kp = jsonMember(ptr, k);
		QJsonArray a = asArray(o[k], kp, 1);
		for (int i = 0; i < a.size(); i++)
			matching(a[i], jsonItem(kp, i), *kinds[k].first,
				kinds[k].second);
	}
}

void readCrl(CaDef &c, const QJsonValue &v, const QString &ptr)
{
	QJsonObject o = asObject(v, ptr);
	onlyMembers(o, ptr, { "validity", "reissue_fraction", "size_budget",
			"distribution_points" });
	c.crl = CrlPolicy();
	if (o.contains("validity")) {
		QString vp = jsonMember(ptr, "validity");
		IsoDuration d = IsoDuration::parse(duration(o["validity"], vp));
		/* whole days of at least P1D (BTD-211) */
		QString why = CrlPolicy::validityError(d);
		if (!why.isEmpty())
			throw serviceError("invalid_validity",
				QString("%1: %2").arg(vp, why));
		c.crl.validity = d;
	}
	if (o.contains("reissue_fraction")) {
		QString fp = jsonMember(ptr, "reissue_fraction");
		if (!o["reissue_fraction"].isDouble())
			bad(fp, tr("must be a number"));
		double f = o["reissue_fraction"].toDouble();
		if (!(f > 0 && f < 0.5))
			bad(fp, tr("must be greater than 0 and less than 0.5"));
		c.crl.reissueFraction = f;
	}
	if (o.contains("size_budget"))
		c.crl.sizeBudget = asInteger(o["size_budget"],
			jsonMember(ptr, "size_budget"), CrlPolicy::minSizeBudget,
			(qint64)1 << 53);
	if (o.contains("distribution_points")) {
		QString dp = jsonMember(ptr, "distribution_points");
		QJsonArray a = asArray(o["distribution_points"], dp, 0);
		for (int i = 0; i < a.size(); i++) {
			QString ip = jsonItem(dp, i);
			QString uri = matching(a[i], ip, uriRe(),
				tr("absolute URI"));
			/* parsed strictly in addition (rule 4) */
			try {
				checkUri(uri);
			} catch (errorEx &err) {
				throw located(ip, err);
			}
			c.distributionPoints << uri;
		}
	}
}

void readKeyUsage(CaDef &c, const QJsonValue &v, const QString &ptr)
{
	QJsonArray a = asArray(v, ptr, 1);
	QStringList seen;
	for (int i = 0; i < a.size(); i++) {
		QString ku = oneOf(a[i], jsonItem(ptr, i), keyUsageNames);
		if (seen.contains(ku))
			bad(ptr, tr("names %1 twice").arg(ku));
		seen << ku;
	}
	if (seen.contains("nonRepudiation") &&
	    seen.contains("contentCommitment"))
		bad(ptr, tr("names nonRepudiation and contentCommitment, two "
			"names of the same bit"));
	for (const QString &ku : seen)
		c.keyUsage << (ku == "contentCommitment" ?
				QString("nonRepudiation") : ku);
}

void readCa(FileDef &f, const QJsonValue &v, int index)
{
	const QString ptr = jsonItem("/cas", index);
	auto mp = [&ptr](const char *m) { return jsonMember(ptr, m); };
	CaDef c;
	c.index = index;
	c.pointer = ptr;
	QJsonObject o = asObject(v, ptr);
	onlyMembers(o, ptr, { "id", "cn", "dn", "subject", "parent", "key",
		"key_password", "hash", "rsa_padding", "validity",
		"not_before", "not_after", "path_len", "name_constraints",
		"key_usage", "profile", "crl", "rollover" });
	requireMembers(o, ptr, { "id", "key" });
	c.id = matching(o["id"], mp("id"), idRe(), tr("id (lower case "
		"letters, digits and '-', at most 63 characters)"));
	if (o.contains("cn"))
		c.cn = asString(o["cn"], mp("cn"), 1);
	if (o.contains("dn"))
		readDn(c, o["dn"], mp("dn"));
	if (o.contains("subject")) {
		static const QRegularExpression country = pattern("^[A-Z]{2}\\z");
		QJsonObject s = asObject(o["subject"], mp("subject"));
		onlyMembers(s, mp("subject"), { "O", "OU", "C", "L", "ST" });
		for (const QString &k : s.keys()) {
			QString sp = jsonMember(mp("subject"), k);
			if (k == "C")
				matching(s[k], sp, country,
					tr("country code (two capital letters)"));
			else
				asString(s[k], sp);
		}
		c.subject = s;
	}
	if (o.contains("parent")) {
		c.parent = asString(o["parent"], mp("parent"));
		if (c.parent == "external")
			c.external = true;
		else
			matching(o["parent"], mp("parent"), idRe(),
				tr("CA id or \"external\""));
	}
	c.key = oneOf(o["key"], mp("key"), keyTypeNames());
	if (o.contains("key_password")) {
		c.keyPassword.pointer = mp("key_password");
		c.keyPassword.value = secretRef(o["key_password"],
						c.keyPassword.pointer);
	}
	if (o.contains("hash"))
		c.hash = oneOf(o["hash"], mp("hash"),
				{ "sha256", "sha384", "sha512" });
	if (o.contains("rsa_padding"))
		c.rsaPadding = oneOf(o["rsa_padding"], mp("rsa_padding"),
				{ "pkcs1v15", "pss" });
	if (o.contains("validity"))
		c.validity = duration(o["validity"], mp("validity"));
	if (o.contains("not_before"))
		c.notBefore = timestamp(o["not_before"], mp("not_before"));
	if (o.contains("not_after"))
		c.notAfter = timestamp(o["not_after"], mp("not_after"));
	if (o.contains("path_len"))
		c.pathLen = (int)asInteger(o["path_len"], mp("path_len"),
						0, 255);
	if (o.contains("name_constraints")) {
		QString np = mp("name_constraints");
		QJsonObject nc = asObject(o["name_constraints"], np);
		onlyMembers(nc, np, { "critical", "permitted", "excluded" });
		if (nc.contains("critical"))
			asBool(nc["critical"], jsonMember(np, "critical"));
		if (!nc.contains("permitted") && !nc.contains("excluded"))
			bad(np, tr("needs permitted or excluded"));
		for (const char *k : { "permitted", "excluded" })
			if (nc.contains(k))
				readNameSet(nc[k], jsonMember(np, k));
		/* the default of critical is true (RFC 5280) */
		if (!nc.contains("critical"))
			nc["critical"] = true;
		c.nameConstraints = nc;
	}
	if (o.contains("key_usage"))
		readKeyUsage(c, o["key_usage"], mp("key_usage"));
	if (o.contains("profile"))
		c.profile = matching(o["profile"], mp("profile"), idRe(),
					tr("profile id"));
	c.crl = CrlPolicy();
	if (o.contains("crl"))
		readCrl(c, o["crl"], mp("crl"));
	if (o.contains("rollover")) {
		QString rp = mp("rollover");
		QJsonObject r = asObject(o["rollover"], rp);
		onlyMembers(r, rp, { "before", "switch_after" });
		requireMembers(r, rp, { "before" });
		for (const QString &k : r.keys())
			duration(r[k], jsonMember(rp, k));
		f.skipped << qMakePair(rp, tr("CA rollover comes in Phase 4 "
			"(PLAN.md E12); nothing is set up for it"));
	}

	/* The subject is cn (with subject) or dn; the end validity or
	 * not_after (the two oneOf of $defs/ca) */
	bool hasCn = o.contains("cn"), hasDn = o.contains("dn");
	if (hasCn && hasDn)
		bad(ptr, tr("cn and dn exclude each other; give the whole "
			"name in dn or cn with subject"));
	if (hasDn && o.contains("subject"))
		bad(ptr, tr("subject belongs to cn; with dn give every "
			"attribute in dn"));
	if (!hasCn && !hasDn)
		bad(ptr, tr("needs cn or dn"));
	bool hasValidity = o.contains("validity");
	if (hasValidity && o.contains("not_after"))
		bad(ptr, tr("validity and not_after exclude each other"));
	if (!hasValidity && !o.contains("not_after"))
		bad(ptr, tr("needs validity or not_after"));
	f.cas << c;
}

/* --- profiles and policies ------------------------------------------------ */

void loadDocument(FileDef &f, const QString &kind, const QString &ptr,
		const QString &path, const QString &shown)
{
	QFile file(path);
	if (!file.open(QIODevice::ReadOnly))
		bad(ptr, tr("cannot read the %1 file '%2': %3").arg(kind,
			shown, file.errorString()));
	QJsonParseError e;
	QJsonDocument d = QJsonDocument::fromJson(file.readAll(), &e);
	if (e.error != QJsonParseError::NoError || !d.isObject())
		bad(ptr, tr("the %1 file '%2' is no JSON object%3").arg(kind,
			shown, e.error != QJsonParseError::NoError ?
			QString(": %1 at offset %2").arg(e.errorString())
				.arg(e.offset) : QString()));
	DocDef doc;
	doc.kind = kind;
	doc.pointer = ptr;
	doc.source = shown;
	doc.doc = d.object();
	if (!doc.doc["id"].isString() ||
	    !idRe().match(doc.doc["id"].toString()).hasMatch())
		bad(ptr, tr("the %1 file '%2' has no valid id").arg(kind, shown));
	doc.id = doc.doc["id"].toString();
	f.docs << doc;
}

void readDocuments(FileDef &f, const QString &kind, const QJsonValue &v,
		const QString &ptr)
{
	static const QRegularExpression path = pattern("(\\.json|/)\\z");
	QJsonArray a = asArray(v, ptr, 0);
	QDir base(f.dir);
	for (int i = 0; i < a.size(); i++) {
		QString ip = jsonItem(ptr, i);
		if (a[i].isObject()) {
			QJsonObject o = a[i].toObject();
			if (!o.contains("id"))
				bad(ip, tr("an inline %1 needs an id")
					.arg(kind));
			DocDef doc;
			doc.kind = kind;
			doc.pointer = ip;
			doc.source = "inline";
			doc.id = matching(o["id"], jsonMember(ip, "id"),
				idRe(), tr("%1 id").arg(kind));
			doc.doc = o;
			f.docs << doc;
			continue;
		}
		if (!a[i].isString())
			bad(ip, tr("must be a path or an inline %1").arg(kind));
		QString rel = matching(a[i], ip, path, tr("path of a .json "
			"file or a directory ending in '/'"));
		QString full = base.filePath(rel);
		if (rel.endsWith('/')) {
			QDir dir(full);
			if (!QFileInfo(full).isDir())
				bad(ip, tr("'%1' is no directory").arg(rel));
			for (const QString &name : dir.entryList(
					QStringList("*.json"), QDir::Files,
					QDir::Name))
				loadDocument(f, kind, ip, dir.filePath(name),
					rel + name);
		} else {
			if (!QFileInfo(full).isFile())
				bad(ip, tr("the %1 file '%2' does not exist")
					.arg(kind, rel));
			loadDocument(f, kind, ip, full, rel);
		}
	}
}

/* --- elements of later phases --------------------------------------------- */

/* Literal secrets are refused everywhere (property 3), also in elements
 * that are not set up yet */
void secretsOfLater(const QJsonObject &top)
{
	auto check = [](const QJsonValue &v, const QString &ptr) {
		if (!v.isUndefined())
			secretRef(v, ptr);
	};
	QJsonArray pub = top["publishers"].toArray();
	for (int i = 0; i < pub.size(); i++) {
		QString p = jsonItem("/publishers", i);
		check(pub[i].toObject().value("token"), jsonMember(p, "token"));
		check(pub[i].toObject().value("private_key"),
			jsonMember(p, "private_key"));
	}
	QJsonObject ext = top.value("server").toObject()
		.value("tls_external").toObject();
	check(ext.value("private_key"), "/server/tls_external/private_key");
	QJsonArray enr = top["enrollment"].toArray();
	for (int i = 0; i < enr.size(); i++) {
		QJsonArray regs = enr[i].toObject().value("registrations").toArray();
		for (int k = 0; k < regs.size(); k++)
			check(regs[k].toObject().value("secret"), jsonMember(jsonItem(
				jsonMember(jsonItem("/enrollment", i),
				"registrations"), k), "secret"));
	}
	QJsonArray roles = top["roles"].toArray();
	for (int i = 0; i < roles.size(); i++) {
		QJsonValue keys = roles[i].toObject().value("api_keys");
		if (!keys.isArray())
			continue;
		QJsonArray a = keys.toArray();
		for (int k = 0; k < a.size(); k++)
			check(a[k], jsonItem(jsonMember(jsonItem("/roles", i),
				"api_keys"), k));
	}
}

/* --- references between the CAs ------------------------------------------- */

void orderCas(FileDef &f)
{
	QMap<QString, int> byId;
	for (int i = 0; i < f.cas.size(); i++) {
		const CaDef &c = f.cas[i];
		if (byId.contains(c.id))
			bad(jsonMember(c.pointer, "id"), tr("the id '%1' is used "
				"by %2 already").arg(c.id)
				.arg(f.cas[byId[c.id]].pointer));
		byId[c.id] = i;
	}
	for (const CaDef &c : f.cas) {
		if (c.parent.isEmpty() || c.external)
			continue;
		if (c.parent == c.id)
			bad(jsonMember(c.pointer, "parent"),
				tr("a CA cannot be its own parent"));
		if (!byId.contains(c.parent))
			bad(jsonMember(c.pointer, "parent"), tr("there is no CA "
				"'%1' in this file").arg(c.parent));
	}
	/* dependency order: a parent before its children */
	QList<int> order;
	QSet<QString> placed;
	while (order.size() < f.cas.size()) {
		bool progress = false;
		for (int i = 0; i < f.cas.size(); i++) {
			const CaDef &c = f.cas[i];
			if (placed.contains(c.id))
				continue;
			if (!c.parent.isEmpty() && !c.external &&
			    !placed.contains(c.parent))
				continue;
			order << i;
			placed << c.id;
			progress = true;
		}
		if (!progress)
			for (const CaDef &c : f.cas)
				if (!placed.contains(c.id))
					bad(jsonMember(c.pointer, "parent"),
						tr("the parents of the CAs "
						"form a cycle"));
	}
	QList<CaDef> sorted;
	for (int i : order)
		sorted << f.cas[i];
	f.cas = sorted;
	/* offline roots (Phase 4): the CA and everything below it */
	QMap<QString, QString> skippedIds;
	for (CaDef &c : f.cas) {
		if (c.external) {
			c.skipReason = tr("parent \"external\": the offline "
				"root and bootstrap --import-ca come in Phase 4 "
				"(PLAN.md 8.2 item 7)");
		} else if (skippedIds.contains(c.parent)) {
			c.skipReason = tr("its parent '%1' is skipped")
					.arg(c.parent);
		} else {
			continue;
		}
		skippedIds[c.id] = c.skipReason;
		f.skipped << qMakePair(c.pointer, c.skipReason);
	}
}

} // namespace

const CaDef *FileDef::ca(const QString &id) const
{
	for (const CaDef &c : cas)
		if (c.id == id)
			return &c;
	return nullptr;
}

FileDef readBootstrapFile(const QString &path)
{
	FileDef f;
	QFile file(path);
	if (!file.open(QIODevice::ReadOnly))
		bad(QString(), tr("cannot read the bootstrap file '%1': %2")
			.arg(path, file.errorString()));
	QByteArray bytes = file.readAll();
	f.path = path;
	f.dir = QFileInfo(path).absolutePath();
	f.sha256 = QString::fromLatin1(QCryptographicHash::hash(bytes,
			QCryptographicHash::Sha256).toHex());

	QJsonParseError e;
	QJsonDocument d = QJsonDocument::fromJson(bytes, &e);
	if (e.error != QJsonParseError::NoError)
		bad(QString(), tr("no JSON: %1 at offset %2")
			.arg(e.errorString()).arg(e.offset));
	if (!d.isObject())
		bad(QString(), tr("the file must be a JSON object"));
	QJsonObject o = d.object();
	onlyMembers(o, QString(), { "schema", "database", "cas", "profiles",
		"policies", "ocsp", "publishers", "server", "enrollment",
		"roles" });
	requireMembers(o, QString(), { "schema", "database", "cas" });
	if (o["schema"].toString() != bootstrapSchemaId || !o["schema"].isString())
		bad("/schema", tr("must be \"%1\"").arg(bootstrapSchemaId));
	f.schema = bootstrapSchemaId;
	readDatabase(f, o["database"]);
	QJsonArray cas = asArray(o["cas"], "/cas", 1);
	for (int i = 0; i < cas.size(); i++)
		readCa(f, cas[i], i);
	for (const char *kind : { "profile", "policy" }) {
		QString member = kind == QString("profile") ? "profiles" :
								"policies";
		if (o.contains(member))
			readDocuments(f, kind, o[member], "/" + member);
	}

	/* Elements of later phases: their type, the literal secrets in
	 * them, and a skipped entry each */
	static const struct {
		const char *name;
		bool array;
		const char *reason;
	} later[] = {
		{ "ocsp", false, "the OCSP responder comes in Phase 4" },
		{ "publishers", true, "CRL and CA certificate publishers come "
			"in Phase 4" },
		{ "server", false, "the server TLS of xca-server comes in "
			"Phase 3 (BTD-160)" },
		{ "enrollment", true, "EST and CMP access points come in "
			"Phase 4" },
		{ "roles", true, "roles and API keys of the REST API come in "
			"Phase 3 (BTD-160)" },
	};
	for (const auto &l : later) {
		if (!o.contains(l.name))
			continue;
		QString p = QString("/") + l.name;
		if (l.array)
			asArray(o[l.name], p, 0);
		else
			asObject(o[l.name], p);
		f.skipped << qMakePair(p, tr(l.reason));
	}
	secretsOfLater(o);

	orderCas(f);
	/* one definition per id and kind */
	for (int i = 0; i < f.docs.size(); i++)
		for (int k = 0; k < i; k++)
			if (f.docs[i].kind == f.docs[k].kind &&
			    f.docs[i].id == f.docs[k].id)
				bad(f.docs[i].pointer, tr("the %1 '%2' is "
					"defined twice (also %3)").arg(
					f.docs[i].kind, f.docs[i].id,
					f.docs[k].pointer));
	return f;
}

} // namespace bxcpki
