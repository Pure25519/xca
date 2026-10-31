/* vi: set sw=4 ts=4:
 *
 * Profiles and name policies as stored documents (BTD-167), see
 * profile_store.h.
 */

#include "profile_store.h"

#include <functional>

#include <QCoreApplication>
#include <QFile>
#include <QJsonDocument>

#include "audit.h"
#include "database_model.h"
#include "db_x509.h"
#include "exception.h"
#include "issuance.h"
#include "pki_x509.h"
#include "policy.h"
#include "profile.h"
#include "sql.h"
#include "template.h"

static QString tr(const char *text)
{
	return QCoreApplication::translate("ProfileStore", text);
}

static void throwOnError(XSqlQuery &q)
{
	QSqlError e = q.lastError();
	if (e.isValid())
		throwSqlError(e, tr("The profile store could not be read "
			"or written"));
}

/* The table of a kind; anything else is refused before it reaches SQL */
static QString table(const QString &kind)
{
	if (kind == "profile")
		return "profiles";
	if (kind == "policy")
		return "policies";
	throw serviceError("invalid_kind",
		tr("'%1' is neither profile nor policy").arg(kind));
}

/* The name of a document that passes the checks of its kind */
static QString checked(const QString &kind, const QJsonObject &doc)
{
	if (table(kind) == "profiles")
		return Profile::fromJson(doc).id;
	return Policy::fromJson(doc).id;
}

static QString json(const QJsonObject &doc)
{
	return QString::fromUtf8(QJsonDocument(doc).toJson(QJsonDocument::Compact));
}

static ProfileStore::Document read(XSqlQuery &q, const QString &kind)
{
	ProfileStore::Document d;
	d.kind = kind;
	d.name = q.value(0).toString();
	d.version = q.value(1).toInt();
	d.document = QJsonDocument::fromJson(q.value(2).toString().toUtf8()).object();
	d.created = q.value(3).toString();
	d.retired = q.value(4).toInt();
	return d;
}

static int newestVersion(const QString &kind, const QString &name)
{
	XSqlQuery q;
	SQL_PREPARE(q, QString("SELECT MAX(version) FROM %1 WHERE name=?")
			.arg(table(kind)));
	q.bindValue(0, name);
	q.exec();
	throwOnError(q);
	return q.next() ? q.value(0).toInt() : 0;
}

static ProfileStore::Document store(const ServiceContext &ctx,
		const QString &kind, const QJsonObject &doc, const QString &action,
		bool newName, const QString &file = QString(),
		const QString &templateName = QString(),
		const QStringList &dropped = QStringList())
{
	ProfileStore::Document d;
	d.dropped = dropped;
	AuditParams params;
	params.set("name", doc["id"].toString());
	if (!file.isEmpty())
		params.set("file", file);
	if (!templateName.isEmpty())
		params.set("template", templateName);
	if (!dropped.isEmpty())
		params.set("dropped_extensions", dropped.join(","));
	auditedTransaction(ctx, kind + "." + action, kind, doc["id"].toString(),
			params, [&]() {
		d.kind = kind;
		d.name = checked(kind, doc);
		int newest = newestVersion(kind, d.name);
		if (newName && newest)
			throw serviceError("document_exists",
				tr("The %1 '%2' exists already; update it for a new version")
				.arg(kind, d.name));
		if (!newName && !newest)
			throw serviceError("document_not_found",
				tr("There is no %1 '%2' to update").arg(kind, d.name));
		d.version = newest + 1;
		d.document = doc;
		d.created = AuditLog::rfc3339(QDateTime::currentDateTimeUtc());
		XSqlQuery q;
		SQL_PREPARE(q, QString("INSERT INTO %1 (name, version, document, "
			"created, retired) VALUES (?, ?, ?, ?, 0)").arg(table(kind)));
		q.bindValue(0, d.name);
		q.bindValue(1, d.version);
		q.bindValue(2, json(doc));
		q.bindValue(3, d.created);
		q.exec();
		throwOnError(q);
		params.set("version", d.version);
		AuditLog::append(ctx, kind + "." + action, kind, d.name, params);
	});
	return d;
}

ProfileStore::Document ProfileStore::create(const ServiceContext &ctx,
		const QString &kind, const QJsonObject &document)
{
	return store(ctx, kind, document, "create", true);
}

ProfileStore::Document ProfileStore::importFile(const ServiceContext &ctx,
		const QString &kind, const QString &path)
{
	QFile f(path);
	QJsonParseError err;
	QJsonDocument d;
	if (f.open(QIODevice::ReadOnly))
		d = QJsonDocument::fromJson(f.readAll(), &err);
	if (!f.isOpen() || err.error != QJsonParseError::NoError ||
	    !d.isObject()) {
		QString code = table(kind) == "profiles" ? "invalid_profile" :
							   "invalid_policy";
		AuditParams params;
		params.set("file", path);
		AuditLog::appendFailure(ctx, kind + ".import", kind, QString(),
				params, code);
		throw serviceError(code, tr("The file '%1' holds no JSON object")
				.arg(path));
	}
	return store(ctx, kind, d.object(), "import", true, path);
}

ProfileStore::Document ProfileStore::migrateTemplate(const ServiceContext &ctx,
		const TemplateSpec &t, const QString &id)
{
	QJsonObject doc;
	try {
		doc = Profile::fromTemplate(t, id);
	} catch (serviceError &err) {
		AuditParams params;
		params.set("template", t.name);
		AuditLog::appendFailure(ctx, "profile.migrate", "profile",
				QString(), params, err.code);
		throw;
	}
	return store(ctx, "profile", doc, "migrate", true, QString(), t.name,
			Profile::droppedFromTemplate(t));
}

ProfileStore::Document ProfileStore::update(const ServiceContext &ctx,
		const QString &kind, const QJsonObject &document)
{
	return store(ctx, kind, document, "update", false);
}

void ProfileStore::retire(const ServiceContext &ctx, const QString &kind,
		const QString &name)
{
	AuditParams params;
	params.set("name", name);
	auditedTransaction(ctx, kind + ".retire", kind, name, params, [&]() {
		if (!newestVersion(kind, name))
			throw serviceError("document_not_found",
				tr("There is no %1 '%2'").arg(kind, name));
		XSqlQuery q;
		SQL_PREPARE(q, QString("UPDATE %1 SET retired=1 WHERE name=?")
				.arg(table(kind)));
		q.bindValue(0, name);
		q.exec();
		throwOnError(q);
		AuditLog::append(ctx, kind + ".retire", kind, name, params);
	});
}

void ProfileStore::remove(const ServiceContext &ctx, const QString &kind,
		const QString &name, int version)
{
	AuditParams params;
	params.set("name", name);
	params.set("version", version);
	auditedTransaction(ctx, kind + ".delete", kind, name, params, [&]() {
		show(kind, name, version);
		/* a version that issued a certificate stays */
		XSqlQuery q;
		if (kind == "profile") {
			SQL_PREPARE(q, "SELECT COUNT(*) FROM issued_profiles "
				"WHERE profile=? AND version=?");
			q.bindValue(0, name);
			q.bindValue(1, version);
		} else {
			/* policies are recorded by name only: any issuance
			 * under the name keeps every version */
			SQL_PREPARE(q, "SELECT policy_names FROM issued_profiles");
		}
		q.exec();
		throwOnError(q);
		int used = 0;
		while (q.next()) {
			used += kind == "profile" ? q.value(0).toInt() :
				q.value(0).toString().split(',').contains(name);
		}
		if (used)
			throw serviceError("profile_in_use",
				tr("Version %1 of the %2 '%3' issued %4 certificates and is kept; retire it instead")
				.arg(version).arg(kind, name).arg(used));
		SQL_PREPARE(q, QString("DELETE FROM %1 WHERE name=? AND version=?")
				.arg(table(kind)));
		q.bindValue(0, name);
		q.bindValue(1, version);
		q.exec();
		throwOnError(q);
		AuditLog::append(ctx, kind + ".delete", kind, name, params);
	});
}

QList<ProfileStore::Document> ProfileStore::list(const QString &kind)
{
	QList<Document> docs;
	XSqlQuery q;
	SQL_PREPARE(q, QString("SELECT name, version, document, created, retired "
		"FROM %1 t WHERE version=(SELECT MAX(version) FROM %1 "
		"WHERE name=t.name) ORDER BY name").arg(table(kind)));
	q.exec();
	throwOnError(q);
	while (q.next())
		docs << read(q, kind);
	return docs;
}

ProfileStore::Document ProfileStore::show(const QString &kind,
		const QString &name, int version)
{
	if (!version)
		version = newestVersion(kind, name);
	XSqlQuery q;
	SQL_PREPARE(q, QString("SELECT name, version, document, created, retired "
		"FROM %1 WHERE name=? AND version=?").arg(table(kind)));
	q.bindValue(0, name);
	q.bindValue(1, version);
	q.exec();
	throwOnError(q);
	if (!q.next())
		throw serviceError("document_not_found",
			tr("There is no version %1 of the %2 '%3'")
			.arg(version).arg(kind, name));
	return read(q, kind);
}

/* The hash a profile names for the key of a CA, empty when it names
 * none; digest-less keys need none (BTD-164) */
static void signatureFits(const QJsonObject &profile, pki_x509 *ca)
{
	const EVP_PKEY *pkey = X509_get0_pubkey(ca->getCert());
	QString type = Profile::keyType(pkey);
	QJsonObject sig = profile["signature"].toObject();
	bool fits;
	if (type.startsWith("rsa-"))
		fits = sig.contains("rsa");
	else if (type.startsWith("ec-"))
		fits = sig["ec"].toObject()["hash_by_curve"].toObject().contains(type);
	else
		fits = true;  // digest-less keys: the digest is ignored, BTD-164
	if (!fits)
		throw serviceError("profile_signature_mismatch",
			tr("The profile '%1' has no signature for the %2 key of the CA '%3'")
			.arg(profile["id"].toString(), type, ca->getIntName()));
}

static bool isAssigned(const QString &ownerType, const QString &owner,
		const QString &kind, const QString &name)
{
	XSqlQuery q;
	SQL_PREPARE(q, "SELECT COUNT(*) FROM assignments WHERE owner_type=? "
		"AND owner=? AND kind=? AND name=?");
	q.bindValue(0, ownerType);
	q.bindValue(1, owner);
	q.bindValue(2, kind);
	q.bindValue(3, name);
	q.exec();
	throwOnError(q);
	return q.next() && q.value(0).toInt() > 0;
}

static void setAssigned(const ServiceContext &ctx, const QString &ownerType,
		const QString &owner, const QString &kind, const QString &name,
		bool on, std::function<void()> check)
{
	QString action = kind + (on ? ".assign" : ".unassign");
	AuditParams params;
	params.set("name", name);
	if (ownerType == "ca")
		params.set("ca_id", owner.toLongLong());
	else
		params.set("profile", owner);
	auditedTransaction(ctx, action, kind, name, params, [&]() {
		/* a retired document never takes effect: issue() refuses a
		 * retired profile, policiesFor() leaves a retired policy out
		 * (BTD-232); unassign stays possible */
		if (ProfileStore::show(kind, name).retired && on)
			throw serviceError("document_retired",
				tr("The %1 '%2' is retired").arg(kind, name));
		if (on && check)
			check();
		if (on == isAssigned(ownerType, owner, kind, name))
			throw serviceError(on ? "already_assigned" : "not_assigned",
				tr("The %1 '%2' is %3 assigned").arg(kind, name,
					on ? tr("already") : tr("not")));
		XSqlQuery q;
		if (on)
			SQL_PREPARE(q, "INSERT INTO assignments (owner_type, owner, "
				"kind, name) VALUES (?, ?, ?, ?)");
		else
			SQL_PREPARE(q, "DELETE FROM assignments WHERE owner_type=? "
				"AND owner=? AND kind=? AND name=?");
		q.bindValue(0, ownerType);
		q.bindValue(1, owner);
		q.bindValue(2, kind);
		q.bindValue(3, name);
		q.exec();
		throwOnError(q);
		AuditLog::append(ctx, action, kind, name, params);
	});
}

void ProfileStore::assign(const ServiceContext &ctx, pki_x509 *ca,
		const QString &kind, const QString &name)
{
	table(kind);
	setAssigned(ctx, "ca", ca->getSqlItemId().toString(), kind, name, true,
		[&]() {
			if (kind == "profile")
				signatureFits(show(kind, name).document, ca);
		});
}

void ProfileStore::unassign(const ServiceContext &ctx, pki_x509 *ca,
		const QString &kind, const QString &name)
{
	table(kind);
	setAssigned(ctx, "ca", ca->getSqlItemId().toString(), kind, name,
			false, nullptr);
}

void ProfileStore::assignToProfile(const ServiceContext &ctx,
		const QString &profile, const QString &policy)
{
	setAssigned(ctx, "profile", profile, "policy", policy, true, [&]() {
		show("profile", profile);
	});
}

static QStringList assignedTo(const QString &ownerType, const QString &owner,
		const QString &kind)
{
	QStringList names;
	XSqlQuery q;
	SQL_PREPARE(q, "SELECT name FROM assignments WHERE owner_type=? "
		"AND owner=? AND kind=? ORDER BY name");
	q.bindValue(0, ownerType);
	q.bindValue(1, owner);
	q.bindValue(2, kind);
	q.exec();
	throwOnError(q);
	while (q.next())
		names << q.value(0).toString();
	return names;
}

QStringList ProfileStore::assigned(const pki_x509 *ca, const QString &kind)
{
	return assignedTo("ca", ca->getSqlItemId().toString(), kind);
}

QList<Policy> ProfileStore::policiesFor(const pki_x509 *ca,
		const QString &profile)
{
	QList<Policy> policies;
	if (!ca)
		return policies;
	QStringList names = assigned(ca, "policy");
	if (!profile.isEmpty())
		names += assignedTo("profile", profile, "policy");
	names.removeDuplicates();
	for (const QString &name : names) {
		Document p = show("policy", name);
		if (!p.retired)
			policies << Policy::fromJson(p.document);
	}
	return policies;
}

pki_x509 *ProfileStore::issue(const ServiceContext &ctx, pki_x509 *ca,
		const QString &profile, pki_x509req *request, pki_key *key,
		const Registration &reg)
{
	IssuanceSpec spec;
	spec.profile = profile;
	try {
		if (!ca || !assigned(ca, "profile").contains(profile))
			throw serviceError("profile_not_assigned",
				tr("The profile '%1' is not assigned to the CA '%2'")
				.arg(profile, ca ? ca->getIntName() : QString()));
		Document d = show("profile", profile);
		if (d.retired)
			throw serviceError("profile_not_assigned",
				tr("The profile '%1' is retired").arg(profile));
		spec = Profile::fromJson(d.document).apply(request, key, reg, ca);
		/* the policies follow in db_x509::newCert() (policiesFor()) */
		spec.profileVersion = d.version;
	} catch (serviceError &err) {
		AuditParams params;
		params.set("profile", profile);
		if (ca)
			params.set("ca_id", ca->getSqlItemId().toLongLong());
		AuditLog::appendFailure(ctx, "certificate.issue", "certificate",
				QString(), params, err.code);
		throw;
	}
	return Database.model<db_x509>()->newCert(ctx, spec);
}
