/* vi: set sw=4 ts=4:
 *
 * Result collector, transaction runner and object references of the
 * bxc-pki command line (BTD-41), see cli.h and cli/README.md.
 */

#include <algorithm>

#include <QDebug>
#include <QJsonDocument>
#include <QRegularExpression>

#include "lib/database_model.h"
#include "lib/db_temp.h"
#include "lib/json_report.h"
#include "lib/pki_key.h"
#include "lib/pki_temp.h"
#include "lib/pki_x509.h"
#include "lib/pki_x509req.h"
#include "lib/sql.h"
#include "cli.h"

namespace bxcpki {

/* --- Result ----------------------------------------------------------- */

QJsonObject ResultCollector::entry(const pki_base *pki) const
{
	QJsonObject o;
	o["type"] = JsonReport::objectType(pki);
	o["id"] = pki->getSqlItemId().toLongLong();
	o["name"] = pki->getIntName();
	o["document"] = JsonReport::object(pki);
	return o;
}

static void addCap(QJsonObject &o, const IssuanceSpec &spec)
{
	bool capped = false;
	spec.effectiveNotAfter(&capped);
	o["validity_capped"] = capped;
	if (capped)
		o["requested_not_after"] =
			JsonReport::timestamp(spec.requestedNotAfter());
}

void ResultCollector::written(const pki_base *pki)
{
	objects.append(entry(pki));
}

void ResultCollector::writtenCertificate(const pki_x509 *cert,
				const IssuanceSpec &spec)
{
	QJsonObject o = entry(cert);
	addCap(o, spec);
	objects.append(o);
}

/* --plan: nothing exists, nothing is signed, so there is no document */
void ResultCollector::planned(const QString &type, const QString &name)
{
	QJsonObject o;
	o["type"] = type;
	o["id"] = QJsonValue();
	o["name"] = name;
	o["document"] = QJsonValue();
	objects.append(o);
}

void ResultCollector::plannedCertificate(const IssuanceSpec &spec)
{
	planned("certificate", spec.name);
	QJsonObject o = objects.last().toObject();
	addCap(o, spec);
	objects.replace(objects.size() - 1, o);
}

QStringList ResultCollector::plannedObjects() const
{
	QStringList l;
	for (const QJsonValue &v : objects)
		l << QString("%1:%2").arg(v.toObject()["type"].toString())
			.arg(v.toObject()["name"].toString());
	return l;
}

QJsonObject ResultCollector::document() const
{
	QJsonObject o;
	o["schema"] = QString("urn:bxc-pki:schema:cli-result:v1");
	o["command"] = command;
	o["plan"] = plan;
	o["objects"] = objects;
	return o;
}

QString ResultCollector::text() const
{
	QString s;
	QString verb = plan ? QObject::tr("would write") :
				QObject::tr("written");
	for (const QJsonValue &v : objects) {
		QJsonObject o = v.toObject();
		QJsonObject d = o["document"].toObject();
		s += QString("%1 %2 %3 '%4'").arg(verb)
			.arg(o["type"].toString())
			.arg(o["id"].isNull() ? QString("-") :
				o["id"].toVariant().toString())
			.arg(o["name"].toString());
		if (d.contains("serial"))
			s += QString(" serial %1").arg(d["serial"].toString());
		if (d.contains("not_after"))
			s += QString(" until %1").arg(d["not_after"].toString());
		if (o["validity_capped"].toBool())
			s += QObject::tr(" (capped at the issuer chain, "
				"requested %1)")
				.arg(o["requested_not_after"].toString());
		s += "\n";
	}
	if (objects.isEmpty())
		s += QObject::tr("nothing written") + "\n";
	return s;
}

/* --- Runner ----------------------------------------------------------- */

/* --plan (BTD-41 review of xca#54): the handlers check and sign nothing;
 * the transaction only guards against a write. One audit entry cli.plan
 * records the run, success or failure, after the rollback. */
static void runPlan(CommandContext &ctx,
		const QList<std::function<void(CommandContext &)> > &steps)
{
	AuditFailureCapture capture;
	auto params = [&ctx]() {
		AuditParams p;
		p.set("command", ctx.command);
		p.set("planned", ctx.result->plannedObjects().join(","));
		p.set("count", ctx.result->count());
		return p;
	};
	auto failed = [&](const QString &code) {
		/* after the rollback: the entries of service calls first,
		 * then the plan's own; best effort, the error wins */
		try {
			capture.replay();
		} catch (errorEx &err) {
			qWarning() << "Audit failure entries lost:"
				<< err.getString();
		}
		AuditLog::appendFailure(ctx.svc, "cli.plan", "object",
				QString(), params(), code);
	};
	try {
		Transaction;
		TransThrow();
		for (const auto &step : steps)
			step(ctx);
		TransRollback();
	} catch (errorEx &err) {
		failed(JsonReport::error(err)["code"].toString());
		throw;
	} catch (...) {
		failed("internal_error");
		throw;
	}
	capture.discard();
	AuditLog::append(ctx.svc, "cli.plan", "object", QString(), params());
}

void runInTransaction(CommandContext &ctx,
		const QList<std::function<void(CommandContext &)> > &steps)
{
	if (ctx.plan) {
		runPlan(ctx, steps);
		return;
	}
	AuditFailureCapture capture;
	try {
		Transaction;
		TransThrow();
		for (const auto &step : steps)
			step(ctx);
		if (!TransCommit())
			throw serviceError("database_error", QObject::tr(
				"Failed to commit the database transaction"));
		/* committed with the objects */
		capture.discard();
	} catch (...) {
		/* The transaction was rolled back when it went out of
		 * scope; the failure entries of the service calls went
		 * with it and are written again, outside of it */
		try {
			capture.replay();
		} catch (errorEx &err) {
			qWarning() << "Audit failure entries lost:"
				<< err.getString();
		}
		throw;
	}
}

/* --- References ------------------------------------------------------- */

static QString describe(const pki_base *pki)
{
	QString type = JsonReport::objectType(pki);
	const pki_temp *t = dynamic_cast<const pki_temp *>(pki);
	if (t && t->isPreDefined())
		return QString("%1 '%2' (predefined)").arg(type)
			.arg(t->comboText());
	return QString("%1 %2 '%3'").arg(type)
		.arg(pki->getSqlItemId().toString()).arg(pki->getIntName());
}

pki_base *resolve(const QString &ref, const QStringList &kinds,
		const QString &option)
{
	static const QRegularExpression number("^[0-9]+$");
	QList<pki_base *> all = Store.getAll<pki_base>(), hits;
	auto wanted = [&kinds](const pki_base *pki) {
		return kinds.isEmpty() ||
			kinds.contains(JsonReport::objectType(pki));
	};
	QList<pki_temp *> predefs;
	if (kinds.isEmpty() || kinds.contains("template"))
		predefs = Database.model<db_temp>()->getPredefs();

	/* An id and a name are equal candidates: "7" that is the id of
	 * one object and the name of another is ambiguous (review of
	 * xca#54) */
	bool numeric = number.match(ref).hasMatch();
	for (pki_base *pki : all) {
		if (!wanted(pki))
			continue;
		if ((numeric && pki->getSqlItemId().toString() == ref) ||
		    pki->getIntName() == ref)
			hits << pki;
	}
	/* predefined templates: "TLS_server" or "[default] TLS_server" */
	for (pki_temp *t : predefs)
		if (t->getIntName() == ref || t->comboText() == ref)
			hits << t;
	QString what = kinds.isEmpty() ? QObject::tr("object") :
				kinds.join(QObject::tr(" or "));
	if (hits.isEmpty())
		throw serviceError("unknown_reference", QObject::tr(
			"%1: no %2 with the id or name '%3'")
			.arg(option).arg(what).arg(ref));
	if (hits.size() > 1) {
		QStringList c;
		std::sort(hits.begin(), hits.end(),
			[](pki_base *a, pki_base *b) {
				return a->getSqlItemId().toLongLong() <
					b->getSqlItemId().toLongLong();
			});
		for (pki_base *pki : hits)
			c << describe(pki);
		throw serviceError("ambiguous_reference", QObject::tr(
			"%1: the name '%2' matches more than one %3: %4; use "
			"the id%5").arg(option).arg(ref).arg(what)
			.arg(c.join(", ")).arg(kinds.size() == 1 ? QString() :
				QObject::tr(" or --type")));
	}
	return hits[0];
}

} // namespace bxcpki
