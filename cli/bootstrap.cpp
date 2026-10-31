/* vi: set sw=4 ts=4:
 *
 * bxc-pki bootstrap (BTD-166, bxc-pki PLAN.md 8.2, Phase 2): CAs,
 * profiles and policies from one file, idempotent, in one transaction.
 *
 * The file is read and checked first (bootstrap_reader.cpp), its secret
 * references resolved, then the database is opened (or created) and
 * every object is evaluated: create, keep, update, skip or (--plan
 * only) error. An existing object is found by its bootstrap id through
 * a settings row (rowKey()), never by its name. The run writes the
 * audit entry bootstrap.apply first, then every object through the
 * service layer (ProfileStore of BTD-167, createCa() of init,
 * CrlPolicy::store()); any error rolls the whole run back. --plan opens
 * the database without its password, writes nothing and lists what it
 * could not check (unchecked).
 */

#include <cmath>

#include <QCryptographicHash>
#include <QDir>
#include <QFileInfo>
#include <QJsonDocument>

#include <openssl/objects.h>

#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/json_report.h"
#include "lib/pki_crl.h"
#include "lib/pki_key.h"
#include "lib/pki_x509.h"
#include "lib/policy.h"
#include "lib/profile.h"
#include "lib/profile_store.h"
#include "lib/PwDialogCore.h"
#include "lib/sql.h"
#include "bootstrap.h"

namespace bxcpki {

namespace {

const char actionApply[] = "bootstrap.apply";

QString tr(const char *s)
{
	return QObject::tr(s);
}

QString compact(const QJsonValue &v)
{
	return QString::fromUtf8(QJsonDocument(QJsonArray { v })
			.toJson(QJsonDocument::Compact));
}

/* Two values of the file or of a stored definition; by their JSON text,
 * so that 0 and 0.0 are equal */
bool same(const QJsonValue &a, const QJsonValue &b)
{
	return compact(a) == compact(b);
}

QString sha256Hex(const QByteArray &data)
{
	return QString::fromLatin1(QCryptographicHash::hash(data,
			QCryptographicHash::Sha256).toHex());
}

/* --- mapping rows: bootstrap id -> database object ------------------------ */

/* settings.key_ is CHAR(20): "bootstrap_" and the first 10 hex digits of
 * the SHA-256 of "<kind>:<bootstrap id>" (a bootstrap id has up to 63
 * characters). The value names kind and id, so a collision is an error,
 * never another object. */
QString rowKey(const QString &kind, const QString &id)
{
	return "bootstrap_" + sha256Hex((kind + ":" + id).toUtf8()).left(10);
}

void checkSql(XSqlQuery &q)
{
	if (q.lastError().isValid())
		throwSqlError(q.lastError(), QObject::tr("The bootstrap "
			"state could not be read or written"));
}

QJsonObject readRow(const QString &kind, const QString &id,
		const QString &ptr)
{
	XSqlQuery q;
	SQL_PREPARE(q, "SELECT value FROM settings WHERE key_=?");
	q.bindValue(0, rowKey(kind, id));
	q.exec();
	checkSql(q);
	if (!q.next())
		return QJsonObject();
	QJsonObject row = QJsonDocument::fromJson(
			q.value(0).toString().toUtf8()).object();
	if (row["kind"].toString() != kind ||
	    row["bootstrap_id"].toString() != id)
		throw serviceError("bootstrap_conflict", QString("%1: %2")
			.arg(ptr, tr("the settings row %1 of the %2 '%3' holds "
			"something else (%4 '%5'); repair or remove the row")
			.arg(rowKey(kind, id), kind, id,
				row["kind"].toString(),
				row["bootstrap_id"].toString())));
	return row;
}

void writeRow(const QString &kind, const QString &id, QJsonObject row)
{
	row["kind"] = kind;
	row["bootstrap_id"] = id;
	XSqlQuery q;
	SQL_PREPARE(q, "DELETE FROM settings WHERE key_=?");
	q.bindValue(0, rowKey(kind, id));
	q.exec();
	checkSql(q);
	SQL_PREPARE(q, "INSERT INTO settings (key_, value) VALUES (?, ?)");
	q.bindValue(0, rowKey(kind, id));
	q.bindValue(1, QString::fromUtf8(QJsonDocument(row)
			.toJson(QJsonDocument::Compact)));
	q.exec();
	checkSql(q);
}

/* --- CA definitions ------------------------------------------------------- */

/* RFC 4514 2.4 */
QString escapeValue(const QString &v)
{
	static const QString special("\\\"+,;<>=");
	QString r;
	for (int i = 0; i < v.size(); i++) {
		QChar c = v[i];
		if (special.contains(c) || (i == 0 && (c == '#' || c == ' ')) ||
		    (i == v.size() - 1 && c == ' '))
			r += '\\';
		r += c;
	}
	return r;
}

/* parseDn() with the JSON pointer as the source of the DN, so that the
 * detail starts with "<pointer>: " (never --subject); as a serviceError,
 * so that the exit code is that of every other error of the file */
x509name parsedDn(const QString &text, const QString &ptr)
{
	try {
		return parseDn(text, ptr);
	} catch (serviceError &err) {
		throw serviceError(err.code, err.getString());
	}
}

/* The subject: dn as given (a list of RDNs in encoding order becomes
 * RFC 4514, most significant last), or cn with the attributes of subject
 * in the order C, ST, L, O, OU, CN; parsed by parseDn() (rule 12). An
 * error names /cas/<i>/dn, /cas/<i>/cn or, for an attribute of subject,
 * /cas/<i>/subject. */
x509name subjectOf(const CaDef &c)
{
	if (c.dn.isString())
		return parsedDn(c.dn.toString(), jsonMember(c.pointer, "dn"));
	if (c.dn.isArray()) {
		QStringList rdns;
		for (const QJsonValue &rdn : c.dn.toArray()) {
			QStringList attrs;
			for (const QJsonValue &a : rdn.toArray())
				attrs << a.toObject()["type"].toString() + "=" +
					escapeValue(a.toObject()["value"]
							.toString());
			rdns.prepend(attrs.join("+"));
		}
		return parsedDn(rdns.join(","), jsonMember(c.pointer, "dn"));
	}
	QString cn = "CN=" + escapeValue(c.cn);
	x509name name = parsedDn(cn, jsonMember(c.pointer, "cn"));
	if (c.subject.isEmpty())
		return name;
	QStringList l(cn);
	for (const char *k : { "OU", "O", "L", "ST", "C" })
		if (c.subject.contains(k))
			l << QString(k) + "=" + escapeValue(
				c.subject[k].toString());
	return parsedDn(l.join(","), jsonMember(c.pointer, "subject"));
}

/* What a certificate of the CA was made from; a stored CA whose
 * definition differs in one of conflictMembers needs a new certificate */
QJsonObject definition(const CaDef &c, const FileDef &f)
{
	QJsonObject d;
	d["key"] = c.key;
	if (!c.cn.isEmpty())
		d["cn"] = c.cn;
	if (!c.subject.isEmpty())
		d["subject"] = c.subject;
	if (c.dn.isString() || c.dn.isArray())
		d["dn"] = c.dn;
	if (!c.parent.isEmpty())
		d["parent"] = c.parent;
	if (c.pathLen >= 0)
		d["path_len"] = c.pathLen;
	if (!c.nameConstraints.isEmpty())
		d["name_constraints"] = c.nameConstraints;
	if (!c.keyUsage.isEmpty())
		d["key_usage"] = QJsonArray::fromStringList(c.keyUsage);
	if (!c.hash.isEmpty())
		d["hash"] = c.hash;
	if (!c.rsaPadding.isEmpty() && c.rsaPadding != "pkcs1v15")
		d["rsa_padding"] = c.rsaPadding;
	if (!c.validity.isEmpty())
		d["validity"] = c.validity;
	if (!c.notBefore.isEmpty())
		d["not_before"] = c.notBefore;
	if (!c.notAfter.isEmpty())
		d["not_after"] = c.notAfter;
	/* the CDP of the certificate: where its parent publishes its CRL */
	const CaDef *p = f.ca(c.parent);
	if (p && !p->distributionPoints.isEmpty())
		d["cdp"] = QJsonArray::fromStringList(p->distributionPoints);
	if (c.keyPassword.isSet())
		d["own_password"] = true;
	/* recorded, not applied: the certificate is made from the members
	 * above (cli/README.md, issued_with) */
	if (!c.issuedWith.isEmpty())
		d["issued_with"] = c.issuedWith;
	return d;
}

const QStringList conflictMembers { "key", "cn", "subject", "dn", "parent",
	"path_len", "name_constraints", "key_usage", "hash", "rsa_padding",
	"validity", "not_before", "not_after", "cdp", "own_password",
	"issued_with" };

/* The assignments of a CA: the member of the file and the BTD-167 kind */
const QList<QPair<QString, QString> > assignmentKinds {
	{ "profiles", "profile" }, { "policies", "policy" } };

const QStringList &assignedIn(const CaDef &c, const QString &member)
{
	return member == "profiles" ? c.profiles : c.policies;
}

/* A CIDR network as OpenSSL's name constraint wants it: address/mask */
QString ipMask(const QString &cidr)
{
	QString addr = cidr.section('/', 0, 0);
	int prefix = cidr.section('/', 1).toInt();
	if (!addr.contains(':')) {
		quint32 m = prefix ? 0xffffffffu << (32 - prefix) : 0;
		return QString("%1/%2.%3.%4.%5").arg(addr).arg(m >> 24)
			.arg((m >> 16) & 255).arg((m >> 8) & 255).arg(m & 255);
	}
	QStringList groups;
	for (int g = 0; g < 8; g++) {
		int bits = qBound(0, prefix - g * 16, 16);
		quint32 v = bits ? (0xffffu << (16 - bits)) & 0xffffu : 0;
		groups << QString::number(v, 16);
	}
	return addr + "/" + groups.join(":");
}

QString nameConstraintsConfig(const QJsonObject &nc)
{
	static const QList<QPair<QString, QString> > forms { { "dns", "DNS" },
		{ "ip", "IP" }, { "uri", "URI" }, { "email", "email" } };
	if (nc.isEmpty())
		return QString();
	QStringList l;
	if (nc["critical"].toBool(true))
		l << "critical";
	for (const char *kind : { "permitted", "excluded" }) {
		QJsonObject set = nc[kind].toObject();
		for (const auto &form : forms)
			for (const QJsonValue &v : set[form.first].toArray())
				l << QString("%1;%2:%3").arg(kind, form.second,
					form.first == "ip" ?
					ipMask(v.toString()) : v.toString());
	}
	return l.join(", ");
}

bool samePolicy(const CrlPolicy &a, const CrlPolicy &b)
{
	return a.validity.toString() == b.validity.toString() &&
		std::fabs(a.reissueFraction - b.reissueFraction) < 1e-9 &&
		a.sizeBudget == b.sizeBudget;
}

QJsonObject unchecked(const QString &object, const QString &check)
{
	QJsonObject o;
	o["object"] = object;
	o["check"] = check;
	return o;
}

/* --- the run -------------------------------------------------------------- */

class Decision
{
  public:
	QString kind{}, id{}, pointer{};
	QString action{};               // create, keep, update, skip, error
	QStringList changed{};          // update: the members applied
	QString reason{};               // skip
	QJsonObject error{};            // --plan: code and detail
	int ca{ -1 }, doc{ -1 };        // index in FileDef::cas / docs
	x509name subject{};
	QJsonObject def{};              // CA definition
	pki_x509 *existing{};           // the CA, also after create
	/* update: per kind (profile, policy) what is assigned and what is
	 * taken back */
	QMap<QString, QStringList> assign{}, unassign{};
	ProfileStore::Document stored{};
	bool hasRow{};
};

class Run
{
	CommandContext &ctx;
	const FileDef &f;
	QList<Decision> decisions{};
	QJsonArray uncheckedList{};
	QList<QPair<QString, QString> > warningList{};  // code, detail
	QMap<QString, pki_x509 *> made{};

	void record(Decision &d, const serviceError &err);
	bool known(const QString &kind, const QString &id,
		bool *retired = nullptr) const;
	void references(const CaDef &c) const;
	void issuedWithFits(const CaDef &c);
	void evaluateDoc(Decision &d);
	void evaluateCa(Decision &d);
	void applyDoc(Decision &d);
	void applyCa(Decision &d);
	QJsonObject entry(const Decision &d) const;

  public:
	bool dbOpen{};
	QString defaultKeySource{};

	Run(CommandContext &c, const FileDef &file) : ctx(c), f(file)
	{
	}
	QList<SecretField> secrets() const;
	void evaluate();
	int count(const QString &action) const;
	AuditParams auditParams(bool counts) const;
	void apply(const AuditParams &params);
	QJsonObject report() const;
};

/* The secrets the run uses: the database password(s) and the own key
 * passwords of the CAs that are set up */
QList<SecretField> Run::secrets() const
{
	QList<SecretField> l;
	for (const SecretField &s : { f.dbPassword, f.dbKeyPassword })
		if (s.isSet())
			l << s;
	for (const CaDef &c : f.cas)
		if (c.keyPassword.isSet() && c.skipReason.isEmpty())
			l << c.keyPassword;
	return l;
}

serviceError unresolvedReference(const SecretField &s)
{
	return serviceError("unresolved_secret_reference", QString("%1: %2")
		.arg(s.pointer, tr("holds the 1Password reference %1, which "
		"bxc-pki does not resolve (the fork contains no 1Password "
		"code); resolve it outside with `op run` or `op inject` into "
		"an environment variable and write env:<VARIABLE> in the file")
		.arg(s.value)));
}

/* The real run reads every secret before it opens the database: an
 * unresolvable reference changes nothing */
void resolveSecrets(const QList<SecretField> &secrets)
{
	for (const SecretField &s : secrets) {
		if (s.value.startsWith("op://"))
			throw unresolvedReference(s);
		try {
			PwDialogHeadless::readSource(s.value);
		} catch (errorEx &err) {
			throw located(s.pointer, err);
		}
	}
}

void Run::record(Decision &d, const serviceError &err)
{
	if (!ctx.plan)
		throw err;
	d.action = "error";
	d.error = QJsonObject();
	d.error["code"] = err.code;
	d.error["detail"] = err.getString();
}

void Run::evaluate()
{
	decisions.clear();
	uncheckedList = QJsonArray();
	warningList.clear();
	if (ctx.plan) {
		for (const SecretField &s : secrets()) {
			if (s.value.startsWith("op://")) {
				Decision d;
				d.kind = "secret";
				d.id = d.pointer = s.pointer;
				record(d, unresolvedReference(s));
				decisions << d;
				continue;
			}
			uncheckedList << unchecked(s.pointer, tr("the secret "
				"reference %1 was not read: --plan reads no "
				"secrets; the real run reads it before it "
				"opens the database").arg(
				PwDialogHeadless::sourceName(s.value)));
		}
		uncheckedList << unchecked("database", dbOpen ? tr("opened "
			"without its password: whether the password is right "
			"and the private keys were not checked") : tr("'%1' "
			"does not exist: every object would be created, "
			"nothing was compared with a database")
			.arg(ctx.database));
	}
	for (int i = 0; i < f.docs.size(); i++) {
		Decision d;
		d.kind = f.docs[i].kind;
		d.id = f.docs[i].id;
		d.pointer = f.docs[i].pointer;
		d.doc = i;
		try {
			evaluateDoc(d);
		} catch (serviceError &err) {
			record(d, err);
		}
		decisions << d;
	}
	for (int i = 0; i < f.cas.size(); i++) {
		Decision d;
		d.kind = "ca";
		d.id = f.cas[i].id;
		d.pointer = f.cas[i].pointer;
		d.ca = i;
		try {
			evaluateCa(d);
		} catch (serviceError &err) {
			record(d, err);
		}
		decisions << d;
		if (!ctx.plan || d.action == "skip" || d.action == "error")
			continue;
		uncheckedList << unchecked("ca:" + d.id, d.action == "create" ?
			tr("key generation, the signatures of the certificate "
			"and of the empty CRL, the checks of the issuance "
			"service (issuer chain, key usage by key type) and the "
			"profile and policy assignments (a profile needs a "
			"signature for the key of the CA) run only in the real "
			"run") :
			tr("the private key of the CA (present and unlocked "
			"by its password) needs the database password"));
		if (!d.assign.value("profile").isEmpty())
			uncheckedList << unchecked("ca:" + d.id, tr("the "
				"assignment of the profile(s) %1 (a profile "
				"needs a signature for the key of the CA) runs "
				"only in the real run").arg(d.assign
				.value("profile").join(", ")));
	}
}

void Run::evaluateDoc(Decision &d)
{
	const DocDef &doc = f.docs[d.doc];
	try {
		if (doc.kind == "profile")
			Profile::fromJson(doc.doc);
		else
			Policy::fromJson(doc.doc);
	} catch (errorEx &err) {
		throw located(doc.pointer, serviceError(QString(),
			QString("%1: %2").arg(doc.source, err.getString())),
			JsonReport::error(err)["code"].toString());
	}
	if (!dbOpen) {
		d.action = "create";
		return;
	}
	d.hasRow = !readRow(doc.kind, doc.id, doc.pointer).isEmpty();
	try {
		d.stored = ProfileStore::show(doc.kind, doc.id);
	} catch (serviceError &err) {
		if (err.code != "document_not_found")
			throw located(doc.pointer, err);
		d.action = "create";
		return;
	}
	if (d.stored.retired)
		d.changed << "retired";
	else if (!same(d.stored.document, doc.doc))
		d.changed << "document";
	d.action = d.changed.isEmpty() ? "keep" : "update";
}

void Run::evaluateCa(Decision &d)
{
	const CaDef &c = f.cas[d.ca];
	if (!c.skipReason.isEmpty()) {
		d.action = "skip";
		d.reason = c.skipReason;
		return;
	}
	d.subject = subjectOf(c);
	d.def = definition(c, f);
	references(c);
	issuedWithFits(c);
	/* rule 1: a CA whose parent (or a CA above it) forbids it by its
	 * path_len is refused */
	int below = 1;
	for (const CaDef *p = f.ca(c.parent); p; p = f.ca(p->parent)) {
		if (p->pathLen >= 0 && below > p->pathLen)
			throw serviceError("path_length_exceeded",
				QString("%1: %2").arg(jsonMember(c.pointer,
				"parent"), tr("the CA '%1' allows %2 CA "
				"certificate(s) below it (path_len %2); '%3' "
				"would be number %4").arg(p->id)
				.arg(p->pathLen).arg(c.id).arg(below)));
		below++;
	}

	QJsonObject row = dbOpen ? readRow("ca", c.id, c.pointer) :
				QJsonObject();
	if (row.isEmpty()) {
		d.action = "create";
		try {
			keyJobText(c.key);
		} catch (errorEx &err) {
			throw located(jsonMember(c.pointer, "key"), err);
		}
		if (c.rsaPadding == "pss")
			throw serviceError("not_supported", QString("%1: %2")
				.arg(jsonMember(c.pointer, "rsa_padding"),
				tr("RSASSA-PSS signatures are not supported by "
				"the signing service of this build; use "
				"pkcs1v15")));
		return;
	}
	d.hasRow = true;
	qint64 item = row["item"].toVariant().toLongLong();
	for (pki_x509 *x : Store.getAll<pki_x509>())
		if (x->getSqlItemId().toLongLong() == item)
			d.existing = x;
	if (!d.existing || !d.existing->isCA())
		throw serviceError("bootstrap_conflict", QString("%1: %2")
			.arg(c.pointer, tr("the CA '%1' was set up by an "
			"earlier bootstrap as certificate %2 '%3', which is no "
			"CA of the database (anymore); bootstrap never makes "
			"another one in its place: remove the settings row %4 "
			"or give the CA another id").arg(c.id).arg(item)
			.arg(row["name"].toString(), rowKey("ca", c.id))));

	QJsonObject old = row["definition"].toObject();
	for (const QString &m : conflictMembers) {
		if (same(old.value(m), d.def.value(m)))
			continue;
		QString ptr = jsonMember(c.pointer, m);
		QString what = m;
		if (m == "own_password") {
			ptr = jsonMember(c.pointer, "key_password");
			what = "key_password";
		} else if (m == "cdp") {
			const CaDef *p = f.ca(c.parent);
			ptr = jsonMember(jsonMember(p ? p->pointer : c.pointer,
				"crl"), "distribution_points");
			what = tr("cdp (crl.distribution_points of the parent)");
		}
		auto text = [](const QJsonValue &v) {
			return v.isUndefined() ? tr("(none)") : compact(v)
				.mid(1).chopped(1);
		};
		throw serviceError("bootstrap_conflict", QString("%1: %2")
			.arg(ptr, tr("the CA '%1' exists (certificate %2 "
			"'%3') with %4 %5; the file has %6. That change needs "
			"a new CA certificate, which bootstrap never issues in "
			"place of an existing one: give the new CA another id, "
			"or keep %4 as it is").arg(c.id)
			.arg(d.existing->getSqlItemId().toString(),
				d.existing->getIntName(), what,
				text(old.value(m)), text(d.def.value(m)))));
	}

	/* applicable without a new certificate: CRL settings, assignments */
	try {
		if (!samePolicy(CrlPolicy::of(d.existing), c.crl))
			d.changed << "crl";
	} catch (serviceError &) {
		/* an invalid stored setting is replaced (BTD-211) */
		d.changed << "crl";
	}
	/* Assigned is what the file lists and the CA lacks; taken back is
	 * what an earlier run assigned (its row) and the file no longer
	 * lists. An assignment made outside bootstrap stays. */
	for (const auto &k : assignmentKinds) {
		const QStringList &want = assignedIn(c, k.first);
		QStringList now = ProfileStore::assigned(d.existing, k.second);
		QStringList add, remove;
		for (const QString &id : want)
			if (!now.contains(id))
				add << id;
		for (const QJsonValue &v : row[k.first].toArray())
			if (!want.contains(v.toString()) &&
			    now.contains(v.toString()))
				remove << v.toString();
		if (add.isEmpty() && remove.isEmpty())
			continue;
		d.assign[k.second] = add;
		d.unassign[k.second] = remove;
		d.changed << k.first;
	}
	d.action = d.changed.isEmpty() ? "keep" : "update";
}

/* A profile or policy id of the file, or (database open) of the
 * database */
/* retired: set when the document exists only in the database and its
 * newest version is retired; a document of the file is stored as a new,
 * not retired version (evaluateDoc) */
bool Run::known(const QString &kind, const QString &id, bool *retired) const
{
	if (retired)
		*retired = false;
	for (const DocDef &doc : f.docs)
		if (doc.kind == kind && doc.id == id)
			return true;
	if (!dbOpen)
		return false;
	try {
		bool r = ProfileStore::show(kind, id).retired;
		if (retired)
			*retired = r;
	} catch (serviceError &err) {
		if (err.code != "document_not_found")
			throw;
		return false;
	}
	return true;
}

/* issued_with, profiles and policies name documents of the file or the
 * database: unknown_reference at the pointer of the id. profiles and
 * policies are assigned, so a retired database document is refused with
 * the code of ProfileStore::assign (document_retired, BTD-232);
 * issued_with only records how the CA was issued, a profile retired since
 * then stays a valid record */
void Run::references(const CaDef &c) const
{
	auto check = [this](const QString &kind, const QString &id,
			const QString &ptr, bool assigned) {
		bool retired;
		if (!known(kind, id, &retired))
			throw serviceError("unknown_reference",
				QString("%1: %2").arg(ptr, tr("there is no %1 "
				"'%2' in the file or the database")
				.arg(kind, id)));
		if (assigned && retired)
			throw serviceError("document_retired",
				QString("%1: %2").arg(ptr, tr("the %1 '%2' "
				"of the database is retired").arg(kind, id)));
	};
	if (!c.issuedWith.isEmpty())
		check("profile", c.issuedWith,
			jsonMember(c.pointer, "issued_with"), false);
	for (const auto &k : assignmentKinds) {
		const QStringList &ids = assignedIn(c, k.first);
		for (int i = 0; i < ids.size(); i++)
			check(k.second, ids[i], jsonItem(jsonMember(c.pointer,
				k.first), i), true);
	}
}

/* issued_with is not applied, but a profile that contradicts the CA would
 * be a misleading record: every mismatch of the profile (from the file or
 * the database) with the CA's key type, path_len and validity is a
 * warning issued_with_mismatch at the pointer of issued_with (BTD-233).
 * The validity is the one the CA is made with: not_before or now, then
 * not_after or validity (default P10Y for a root, P5Y below) */
void Run::issuedWithFits(const CaDef &c)
{
	if (c.issuedWith.isEmpty())
		return;
	QJsonObject doc;
	for (const DocDef &d : f.docs)
		if (d.kind == "profile" && d.id == c.issuedWith)
			doc = d.doc;
	if (doc.isEmpty())
		doc = ProfileStore::show("profile", c.issuedWith).document;
	Profile p;
	QDateTime from, to;
	try {
		p = Profile::fromJson(doc);
		from = c.notBefore.isEmpty() ? QDateTime::currentDateTimeUtc() :
			(QDateTime)parseTimestamp(c.notBefore, "not_before");
		to = !c.notAfter.isEmpty() ?
			(QDateTime)parseTimestamp(c.notAfter, "not_after") :
			parseDuration(!c.validity.isEmpty() ? c.validity :
				c.parent.isEmpty() ? "P10Y" : "P5Y", "validity")
				.addTo(from);
	} catch (errorEx &) {
		return;  // the profile entry or the CA reports it
	}
	QString ptr = jsonMember(c.pointer, "issued_with");
	for (const auto &m : p.caMismatches(c.key, c.pathLen, from, to))
		warningList << qMakePair(QString("issued_with_mismatch"),
			QString("%1: %2 (%3)").arg(ptr, m.second, m.first));
}

int Run::count(const QString &action) const
{
	int n = 0;
	for (const Decision &d : decisions)
		if (d.action == action && d.kind != "secret")
			n++;
	return n;
}

AuditParams Run::auditParams(bool counts) const
{
	AuditParams p;
	p.set("file_sha256", f.sha256);
	p.set("schema", f.schema);
	if (counts) {
		p.set("created", count("create"));
		p.set("kept", count("keep"));
		p.set("updated", count("update"));
		p.set("skipped", (int)f.skipped.size());
	}
	return p;
}

void Run::apply(const AuditParams &params)
{
	runInTransaction(ctx, { [this, params](CommandContext &) {
		/* the first entry of the run, so on a new database seq 1 */
		AuditLog::append(ctx.svc, actionApply, "database", QString(),
				params);
		for (Decision &d : decisions) {
			try {
				if (d.kind == "ca")
					applyCa(d);
				else
					applyDoc(d);
			} catch (errorEx &err) {
				QString step = ctx.step;
				ctx.step.clear();
				QString detail = err.getString();
				if (!step.isEmpty())
					detail = tr("%1 was not written: %2")
						.arg(step, detail);
				throw serviceError(JsonReport::error(err)["code"]
					.toString(), QString("%1: %2")
					.arg(d.pointer, detail));
			}
		}
		ctx.step.clear();
	} });
}

void Run::applyDoc(Decision &d)
{
	const DocDef &doc = f.docs[d.doc];
	ctx.step = tr("%1 '%2'").arg(doc.kind, doc.id);
	if (d.action == "create")
		d.stored = ProfileStore::create(ctx.svc, doc.kind, doc.doc);
	else if (d.action == "update")
		d.stored = ProfileStore::update(ctx.svc, doc.kind, doc.doc);
	if (d.action != "keep" || !d.hasRow) {
		QJsonObject row;
		row["name"] = d.stored.name;
		row["version"] = d.stored.version;
		writeRow(doc.kind, doc.id, row);
	}
}

/* The row of a CA: its certificate, the definition it was made from, and
 * the profiles and policies the file assigns (what a later run may take
 * back) */
QJsonObject caRow(const pki_x509 *cert, const QJsonObject &def,
		const CaDef &c)
{
	QJsonObject row;
	row["item"] = cert->getSqlItemId().toLongLong();
	row["name"] = cert->getIntName();
	row["definition"] = def;
	row["sha256"] = sha256Hex(QJsonDocument(def)
				.toJson(QJsonDocument::Compact));
	for (const auto &k : assignmentKinds)
		row[k.first] = QJsonArray::fromStringList(
				assignedIn(c, k.first));
	return row;
}

void Run::applyCa(Decision &d)
{
	const CaDef &c = f.cas[d.ca];
	if (d.action == "skip")
		return;
	if (d.action == "keep") {
		made[c.id] = d.existing;
		return;
	}
	if (d.action == "update") {
		pki_x509 *ca = d.existing;
		if (d.changed.contains("crl")) {
			ctx.step = tr("CRL settings of '%1'")
					.arg(ca->getIntName());
			c.crl.store(ctx.svc, ca);
		}
		for (const auto &k : assignmentKinds) {
			ctx.step = tr("%1 assignment of '%2'").arg(k.second,
					ca->getIntName());
			for (const QString &id : d.unassign.value(k.second))
				ProfileStore::unassign(ctx.svc, ca, k.second,
							id);
			for (const QString &id : d.assign.value(k.second))
				ProfileStore::assign(ctx.svc, ca, k.second, id);
		}
		writeRow("ca", c.id, caRow(ca, d.def, c));
		made[c.id] = ca;
		return;
	}

	/* create: init's code path with the values of the file */
	Options o;
	o.add("key", c.key);
	if (!c.validity.isEmpty())
		o.add("validity", c.validity);
	if (!c.notBefore.isEmpty())
		o.add("not-before", c.notBefore);
	if (!c.notAfter.isEmpty())
		o.add("not-after", c.notAfter);
	if (!c.hash.isEmpty())
		o.add("hash", c.hash);
	if (c.pathLen >= 0)
		o.add("path-len", QString::number(c.pathLen));
	CaExtras x;
	x.subject = d.subject;
	const CaDef *parent = f.ca(c.parent);
	if (parent) {
		x.parent = made.value(parent->id);
		if (!x.parent)
			throw serviceError("internal_error", tr("the parent "
				"'%1' was not set up before").arg(parent->id));
		x.crlDistPoints = parent->distributionPoints.isEmpty() ?
			QString() : "URI:" + parent->distributionPoints
						.join(", URI:");
		x.signerPassword = parent->keyPassword.value;
	}
	x.keyUsage = c.keyUsage;
	x.nameConstraints = nameConstraintsConfig(c.nameConstraints);
	x.hasCrlPolicy = true;
	x.crlPolicy = c.crl;
	x.passwords = true;
	x.keyPassword = c.keyPassword.value;
	x.defaultPassword = defaultKeySource;

	Options saved = ctx.opts;
	ctx.opts = o;
	CaCreated ca;
	try {
		ca = createCa(ctx, x);
	} catch (...) {
		ctx.opts = saved;
		throw;
	}
	ctx.opts = saved;
	for (const auto &k : assignmentKinds) {
		ctx.step = tr("%1 assignment of '%2'").arg(k.second,
				ca.cert->getIntName());
		for (const QString &id : assignedIn(c, k.first))
			ProfileStore::assign(ctx.svc, ca.cert, k.second, id);
	}
	writeRow("ca", c.id, caRow(ca.cert, d.def, c));
	d.existing = ca.cert;
	made[c.id] = ca.cert;
}

QJsonObject Run::entry(const Decision &d) const
{
	QJsonObject e;
	e["kind"] = d.kind;
	e["bootstrap_id"] = d.id;
	e["pointer"] = d.pointer;
	e["action"] = d.action;
	if (!d.changed.isEmpty())
		e["changed"] = QJsonArray::fromStringList(d.changed);
	if (!d.reason.isEmpty())
		e["reason"] = d.reason;
	if (!d.error.isEmpty())
		e["error"] = d.error;
	if (d.kind == "secret")
		return e;
	if (d.kind != "ca") {
		const DocDef &doc = f.docs[d.doc];
		e["type"] = doc.kind;
		e["name"] = doc.id;
		e["source"] = doc.source;
		e["version"] = d.stored.version ?
			QJsonValue(d.stored.version) : QJsonValue();
		return e;
	}
	const CaDef &c = f.cas[d.ca];
	e["type"] = QString("certificate");
	e["key_type"] = c.key;
	e["issuer_bootstrap_id"] = c.parent.isEmpty() ? QJsonValue() :
					QJsonValue(c.parent);
	e["issued_with"] = c.issuedWith.isEmpty() ? QJsonValue() :
					QJsonValue(c.issuedWith);
	e["profiles"] = QJsonArray::fromStringList(c.profiles);
	e["policies"] = QJsonArray::fromStringList(c.policies);
	if (!d.def.isEmpty())
		e["definition_sha256"] = sha256Hex(QJsonDocument(d.def)
				.toJson(QJsonDocument::Compact));
	const pki_x509 *cert = d.existing;
	for (const char *m : { "id", "serial", "fingerprint", "issuer",
			"not_before", "not_after", "crl_id", "crl_number",
			"next_update" })
		e[m] = QJsonValue();
	e["name"] = d.subject.entryCount() > 0 ? QJsonValue(
		d.subject.getEntryByNid(NID_commonName).isEmpty() ?
		d.subject.getEntry(d.subject.entryCount() - 1) :
		d.subject.getEntryByNid(NID_commonName)) : QJsonValue();
	if (!cert)
		return e;
	QJsonObject doc = JsonReport::certificate(cert);
	e["id"] = cert->getSqlItemId().toLongLong();
	e["name"] = cert->getIntName();
	e["serial"] = doc["serial"];
	e["fingerprint"] = doc["fingerprints"].toObject()["sha256"];
	e["issuer"] = doc["issuer"].toObject()["rfc4514"];
	e["subject"] = doc["subject"].toObject()["rfc4514"];
	e["not_before"] = doc["not_before"];
	e["not_after"] = doc["not_after"];
	pki_crl *crl = CrlPolicy::latestCrl(cert);
	if (crl) {
		e["crl_id"] = crl->getSqlItemId().toLongLong();
		a1int no(0L);
		if (crl->getCrlNumber(&no))
			e["crl_number"] = no.toDec().toLongLong();
		e["next_update"] = JsonReport::timestamp(crl->getNextUpdate());
	}
	return e;
}

QJsonObject Run::report() const
{
	for (const auto &w : warningList)
		ctx.result->warning(w.first, w.second);
	QJsonObject b, counts;
	b["file"] = f.path;
	b["file_sha256"] = f.sha256;
	b["schema"] = f.schema;
	b["database"] = ctx.database;
	counts["created"] = count("create");
	counts["kept"] = count("keep");
	counts["updated"] = count("update");
	counts["skipped"] = (int)f.skipped.size();
	int errors = 0;
	for (const Decision &d : decisions)
		if (d.action == "error")
			errors++;
	counts["errors"] = errors;
	b["counts"] = counts;
	QJsonArray entries, skipped;
	for (const Decision &d : decisions)
		entries << entry(d);
	b["entries"] = entries;
	for (const auto &s : f.skipped) {
		QJsonObject o;
		o["element"] = s.first;
		o["reason"] = s.second;
		skipped << o;
	}
	b["skipped"] = skipped;
	if (ctx.plan)
		b["unchecked"] = uncheckedList;
	return b;
}

/* --- the command ---------------------------------------------------------- */

void cmdBootstrap(CommandContext &ctx)
{
	const Options &o = ctx.opts;
	PwDialogHeadless *h = PwDialogCore::headless();
	FileDef f = readBootstrapFile(o.value("file"));
	Run run(ctx, f);

	/* The database: --db, else the file's; its password from the
	 * file unless --password (--sqlpass) is given. SQLite: password is
	 * the database password; a server: password is the server's, the
	 * database password is key_password. */
	bool server = f.dbType != "sqlite";
	if (o.has("db"))
		ctx.database = o.value("db");
	else if (!server)
		ctx.database = QDir(f.dir).absoluteFilePath(f.dbPath);
	else
		ctx.database = QString("%1@%2%3/%4:%5").arg(f.dbUser, f.dbHost,
			f.dbPort ? QString(":%1").arg(f.dbPort) : QString(),
			f.dbType == "postgresql" ? "QPSQL" : "QMARIADB",
			f.dbName);
	SecretField dbPw = server ? f.dbKeyPassword : f.dbPassword;
	SecretField sqlPw = server ? f.dbPassword : SecretField();
	if (ctx.plan) {
		/* --plan reads no secret and opens the database without
		 * its password: public objects and settings rows only */
		h->setSource(pass_info::DatabasePassword, QString());
		h->setSource(pass_info::KeyPassword, QString());
	} else {
		resolveSecrets(run.secrets());
		if (!o.has("password") && dbPw.isSet()) {
			h->setSource(pass_info::DatabasePassword, dbPw.value);
			h->setSource(pass_info::KeyPassword, dbPw.value);
		}
		if (!o.has("sqlpass") && sqlPw.isSet())
			h->setSource(pass_info::SqlPassword, sqlPw.value);
		run.defaultKeySource = o.has("password") ?
				o.value("password") : dbPw.value;
	}
	bool exists = database_model::isRemoteDB(ctx.database) ||
			QFileInfo::exists(ctx.database);

	if (ctx.plan) {
		if (exists) {
			ctx.openDatabase();
			run.dbOpen = true;
		}
		run.evaluate();
		ctx.result->set("bootstrap", run.report());
		return;
	}
	/* a file with an error creates no database */
	if (!exists)
		run.evaluate();
	ctx.openDatabase();
	run.dbOpen = true;
	AuditParams params = run.auditParams(false);
	try {
		run.evaluate();
		params = run.auditParams(true);
		run.apply(params);
	} catch (errorEx &err) {
		/* after the rollback (runInTransaction() wrote the failure
		 * entries of the service calls again) */
		ctx.step.clear();
		AuditLog::appendFailure(ctx.svc, actionApply, "database",
			QString(), params,
			JsonReport::error(err)["code"].toString());
		throw;
	}
	ctx.result->set("bootstrap", run.report());
}

} // namespace

void registerBootstrapCommand(Registry &r)
{
	Command c;
	c.name = "bootstrap";
	c.summary = QObject::tr("set up CAs, profiles and policies from a "
				"bootstrap file (idempotent)");
	c.description = QObject::tr(
		"  The file (urn:bxc-pki:schema:bootstrap:v1) is checked "
		"first; an error names its\n  JSON pointer. Phase 2 sets up "
		"database, cas, profiles and policies; server,\n  roles, "
		"enrollment, ocsp, publishers, rollover and parent "
		"\"external\" are\n  reported as skipped. Objects are found "
		"by their bootstrap id: a second run\n  keeps them; changed "
		"CRL settings, profiles, policies and the profiles and "
		"policies\n  assigned to a CA are updates, a change that "
		"needs a new CA certificate\n  (issued_with included) is "
		"bootstrap_conflict. One transaction: all or nothing.\n  "
		"Secrets only as env: or file: references (op:// is "
		"resolved outside\n  with op run or op inject). --db "
		"replaces the file's database, --password its\n  password. "
		"--plan opens the database without its password, writes "
		"nothing and\n  lists create/keep/update/skip/error per "
		"object and what it could not check.");
	c.options = QList<OptionSpec> {
		opt("file", OptionSpec::string, "<file>", QObject::tr(
			"the bootstrap file; relative paths in it are relative "
			"to its directory"), false, true),
	};
	c.writes = true;
	c.needsDatabase = false;
	c.createsDatabase = true;
	c.ownTransaction = true;
	c.handler = cmdBootstrap;
	r.add(c);
}

} // namespace bxcpki
