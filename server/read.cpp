/* vi: set sw=4 ts=4:
 *
 * The read resources of xca-server (BTD-156), see read.h.
 */

#include "read.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QObject>
#include <QSet>
#include <QStringList>

#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/exception.h"
#include "lib/json_report.h"
#include "lib/pkcs11.h"
#include "lib/pki_base.h"
#include "lib/pki_x509.h"
#include "lib/profile_store.h"
#include "lib/sql.h"

namespace xcaserver {

namespace {

void needDatabase()
{
	if (!Database.isOpen())
		throw serviceError("no_database",
			QObject::tr("No database is open"));
}

/* the item types of a collection of the spec */
QList<enum pki_type> typesOf(const QString &collection)
{
	if (collection == "keys")
		return { asym_key, smartCard };
	if (collection == "requests")
		return { x509_req };
	if (collection == "certificates")
		return { x509 };
	if (collection == "crls")
		return { revocation };
	throw serviceError("invalid_value", QObject::tr("'%1' is no "
		"collection (keys, requests, certificates, crls)")
		.arg(collection));
}

QString typeList(const QList<enum pki_type> &types)
{
	QStringList t;
	for (enum pki_type type : types)
		t << QString::number(int(type));
	return t.join(',');
}

/* The item ids of the CA certificates of the scope, as SQL list; only
 * numbers from the database, so they are safe in the statement */
QString caList(const CaScope &scope)
{
	QStringList items;
	for (qint64 item : caItems(scope.cas))
		items << QString::number(item);
	return items.isEmpty() ? QString("NULL") : items.join(',');
}

/* An SQL condition on items.id: the objects of the collection the scope
 * sees (read.h); empty for every CA */
QString scopeCondition(const QString &collection, const CaScope &scope)
{
	if (scope.all)
		return QString();
	QString in = caList(scope);
	QString certs = QString("SELECT c.item FROM certs c JOIN items ci ON "
		"ci.id = c.item WHERE ci.del = 0 AND (c.item IN (%1) OR "
		"c.issuer IN (%1))").arg(in);
	QString keys = QString("SELECT x.pkey FROM x509super x WHERE x.item "
		"IN (%1)").arg(certs);
	if (collection == "certificates")
		return QString("items.id IN (%1)").arg(certs);
	if (collection == "crls")
		return QString("items.id IN (SELECT item FROM crls WHERE issuer "
			"IN (%1))").arg(in);
	if (collection == "keys")
		return QString("items.id IN (%1)").arg(keys);
	/* requests: the request a certificate in the scope was issued
	 * from, the one with its key */
	return QString("items.id IN (SELECT r.item FROM x509super r JOIN "
		"items ri ON ri.id = r.item WHERE ri.type = %1 AND r.pkey IN "
		"(%2))").arg(int(x509_req)).arg(keys);
}

QList<qint64> ids(const QString &sql, const QList<QVariant> &values)
{
	XSqlQuery q;
	SQL_PREPARE(q, sql);
	for (int i = 0; i < values.size(); i++)
		q.bindValue(i, values[i]);
	execOrThrow(q, "read");
	QList<qint64> out;
	while (q.next())
		out << q.value(0).toLongLong();
	return out;
}

QSet<qint64> idSet(const QString &sql, const QList<QVariant> &values)
{
	QSet<qint64> out;
	for (qint64 id : ids(sql, values))
		out << id;
	return out;
}

/* The CAs (item ids of their certificates) a profile or policy is bound
 * to: assigned to a CA, assigned to a profile that is bound, or a
 * certificate was issued under it */
QSet<qint64> boundCas(const QString &kind, const QString &name)
{
	QSet<qint64> cas = idSet("SELECT CAST(owner AS INTEGER) FROM "
		"assignments WHERE owner_type = 'ca' AND kind = ? AND "
		"name = ?", { kind, name });
	if (kind == "profile") {
		cas += idSet("SELECT c.issuer FROM issued_profiles ip JOIN "
			"certs c ON c.item = ip.item WHERE ip.profile = ?",
			{ name });
		return cas;
	}
	XSqlQuery q;
	SQL_PREPARE(q, "SELECT owner FROM assignments WHERE owner_type = "
		"'profile' AND kind = 'policy' AND name = ?");
	q.bindValue(0, name);
	execOrThrow(q, "read");
	QStringList profiles;
	while (q.next())
		profiles << q.value(0).toString();
	for (const QString &profile : profiles)
		cas += boundCas("profile", profile);
	cas += idSet("SELECT c.issuer FROM issued_profiles ip JOIN certs c ON "
		"c.item = ip.item WHERE ',' || ip.policy_names || ',' LIKE ?",
		{ QString("%,%1,%").arg(name) });
	return cas;
}

bool sees(const QString &kind, const QString &name, const CaScope &scope)
{
	if (scope.all)
		return true;
	QSet<qint64> bound = boundCas(kind, name);
	if (bound.isEmpty())
		return true;
	for (qint64 item : caItems(scope.cas))
		if (bound.contains(item))
			return true;
	return false;
}

}

QJsonObject listObjectsJob(const QString &collection, const CaScope &scope,
		qint64 after, int limit)
{
	needDatabase();
	QString cond = scopeCondition(collection, scope);
	/* one more than asked: whether a next page exists */
	QList<qint64> page = ids(QString("SELECT items.id FROM items WHERE "
		"items.del = 0 AND items.type IN (%1) AND items.id > ? %2 "
		"ORDER BY items.id LIMIT ?").arg(typeList(typesOf(collection)),
		cond.isEmpty() ? QString() : "AND " + cond),
		{ after, limit + 1 });
	bool more = page.size() > limit;
	if (more)
		page.removeLast();
	QList<pki_base *> items;
	for (qint64 id : page) {
		pki_base *pki = Store.lookupPki<pki_base>(QVariant(id));
		if (pki)
			items << pki;
	}
	QJsonObject list = JsonReport::itemList(items);
	list["next"] = more && !page.isEmpty() ?
			QJsonValue(page.last()) : QJsonValue();
	return list;
}

QJsonObject getObjectJob(const QString &collection, qint64 id,
		const CaScope &scope)
{
	needDatabase();
	QList<enum pki_type> types = typesOf(collection);
	XSqlQuery q;
	SQL_PREPARE(q, "SELECT type FROM items WHERE id = ? AND del = 0");
	q.bindValue(0, id);
	execOrThrow(q, "read");
	if (!q.next())
		throw serviceError("unknown_reference", QObject::tr(
			"No object with the id %1").arg(id));
	/* outside the scope: the same answer as for no object, before the
	 * type, so that a restricted identity learns nothing of it */
	QString cond = scopeCondition(collection, scope);
	if (!cond.isEmpty() && ids(QString("SELECT items.id FROM items WHERE "
			"items.id = ? AND %1").arg(cond), { id }).isEmpty())
		throw serviceError("unknown_reference", QObject::tr(
			"No object with the id %1").arg(id));
	if (!types.contains(static_cast<enum pki_type>(q.value(0).toInt())))
		throw serviceError("wrong_object_type", QObject::tr(
			"The object %1 is not in %2").arg(id).arg(collection));
	pki_base *pki = Store.lookupPki<pki_base>(QVariant(id));
	if (!pki)
		throw serviceError("unknown_reference", QObject::tr(
			"No object with the id %1").arg(id));
	return JsonReport::object(pki);
}

QJsonObject listDocumentsJob(const QString &kind, const CaScope &scope)
{
	needDatabase();
	QJsonArray docs;
	for (const ProfileStore::Document &d : ProfileStore::list(kind))
		if (sees(kind, d.name, scope))
			docs.append(d.document);
	return QJsonObject{ { "documents", docs } };
}

QJsonObject getDocumentJob(const QString &kind, const QString &name,
		const CaScope &scope)
{
	needDatabase();
	ProfileStore::Document d = ProfileStore::show(kind, name);
	if (!sees(kind, name, scope))
		throw serviceError("document_not_found", QObject::tr(
			"There is no %1 '%2'").arg(kind, name));
	return d.document;
}

QJsonObject indexJob(bool hierarchy, const CaScope &scope)
{
	needDatabase();
	if (scope.all)
		return hierarchy ? JsonReport::hierarchy() : JsonReport::index();
	QSet<qint64> visible = idSet(QString("SELECT items.id FROM items WHERE "
		"%1").arg(scopeCondition("certificates", scope)), {});
	return hierarchy ? JsonReport::hierarchy(&visible) :
			JsonReport::index(&visible);
}

QJsonObject tokensJob()
{
	needDatabase();
	QJsonArray slotArray;
	if (pkcs11::libraries.loaded()) {
		pkcs11 p11;
		for (const slotid &slot : pkcs11::getSlotList()) {
			tkInfo ti;
			QJsonObject s{ { "slot", qint64(slot.id) } };
			if (p11.tokenInfo(slot, &ti) == CKR_OK) {
				s["label"] = ti.label().trimmed();
				s["manufacturer"] = ti.manufacturerID().trimmed();
				s["model"] = ti.model().trimmed();
				s["serial"] = ti.serial().trimmed();
				s["initialized"] = ti.tokenInitialized();
			} else {
				/* a slot without a token */
				s["label"] = s["manufacturer"] = s["model"] =
					s["serial"] = QString();
				s["initialized"] = false;
			}
			slotArray.append(s);
		}
	}
	return QJsonObject{ { "slots", slotArray } };
}

QJsonObject verifyAuditJob()
{
	needDatabase();
	try {
		return QJsonObject{ { "report", QString::fromUtf8(
			AuditLog::verify().toJson()) } };
	} catch (errorEx &err) {
		/* the error form of the report, as --audit-verify writes it */
		QVariantMap m{ { "ok", false }, { "error", err.getString() } };
		return QJsonObject{ { "report", QString::fromUtf8(
			AuditLog::canonicalJson(m)) } };
	}
}

QJsonObject exportAuditJob(const QString &actor, qint64 after)
{
	needDatabase();
	qint64 unanchored = 0;
	QByteArray all = AuditLog::exportJsonLines(ServiceContext(
			ServiceContext::rest, actor), &unanchored, nullptr,
			false);
	/* the lines after the sequence number after, byte for byte */
	QByteArray lines;
	qint64 first = 0, last = 0, count = 0;
	for (const QByteArray &line : all.split('\n')) {
		if (line.isEmpty())
			continue;
		qint64 seq = qint64(QJsonDocument::fromJson(line).object()
				.value("seq").toDouble());
		if (seq <= after)
			continue;
		lines += line + '\n';
		if (!first)
			first = seq;
		last = seq;
		count++;
	}
	appendEntry(actor, AuditLog::actionExport, "database", QString(),
		QVariantMap{ { "after", after }, { "first_seq", first },
			{ "last_seq", last }, { "count", count },
			{ "unanchored_entries", unanchored } },
		"success", QString());
	return QJsonObject{ { "lines", QString::fromUtf8(lines) },
		{ "unanchored", unanchored }, { "count", count } };
}

}
