/* vi: set sw=4 ts=4:
 *
 * CRL lifecycle settings of a CA (BTD-42), see crl_policy.h.
 */

#include "crl_policy.h"

#include <climits>
#include <cmath>

#include <QJsonDocument>
#include <QJsonValue>
#include <QStringList>
#include <QRegularExpression>

#include "audit.h"
#include "exception.h"
#include "pki_crl.h"
#include "pki_x509.h"
#include "sql.h"

const char CrlPolicy::defaultValidity[] = "P7D";
const double CrlPolicy::defaultReissueFraction = 1.0 / 3.0;
const qint64 CrlPolicy::defaultSizeBudget = 4096;
const qint64 CrlPolicy::defaultTrustListBudget = 65535;
const qint64 CrlPolicy::minSizeBudget = 512;
const char CrlPolicy::actionSettings[] = "ca.crl_settings";

static QString settingsKey(const pki_x509 *ca)
{
	/* settings.key_ is CHAR(20): "crlpolicy_" and up to 10 digits */
	return QString("crlpolicy_%1").arg(ca->getSqlItemId().toLongLong());
}

CrlPolicy::CrlPolicy()
	: validity(IsoDuration::parse(defaultValidity))
{
}

/* A stored row that is not a valid setting: an error naming the CA and
 * the member, never the defaults (BTD-211) */
static serviceError settingsInvalid(const pki_x509 *ca,
			const QString &member, const QString &why)
{
	return serviceError("crl_settings_invalid", QObject::tr(
		"The stored CRL settings of the CA '%1' (settings row %2) are "
		"invalid: %3 %4; give all of --crl-validity, "
		"--crl-reissue-fraction and --crl-size-budget to replace them")
		.arg(ca->getIntName(), settingsKey(ca), member, why));
}

CrlPolicy CrlPolicy::of(const pki_x509 *ca)
{
	static const QStringList members { "validity", "reissue_fraction",
		"size_budget" };
	CrlPolicy p;
	if (!ca)
		return p;
	int days = const_cast<pki_x509 *>(ca)->getCrlDays();
	if (days > 0)
		p.validity = IsoDuration::parse(QString("P%1D").arg(days));
	if (!ca->getSqlItemId().isValid() || !QSqlDatabase::database().isOpen())
		return p;

	XSqlQuery q;
	SQL_PREPARE(q, "SELECT value FROM settings WHERE key_=?");
	q.bindValue(0, settingsKey(ca));
	q.exec();
	if (!q.first())
		return p;
	QJsonParseError pe;
	QJsonDocument doc = QJsonDocument::fromJson(
			q.value(0).toString().toUtf8(), &pe);
	if (pe.error != QJsonParseError::NoError)
		throw settingsInvalid(ca, "value", QObject::tr(
			"is no JSON (%1 at offset %2)").arg(pe.errorString())
			.arg(pe.offset));
	if (!doc.isObject())
		throw settingsInvalid(ca, "value",
			QObject::tr("is no JSON object"));
	QJsonObject o = doc.object();
	for (const QString &k : o.keys())
		if (!members.contains(k))
			throw settingsInvalid(ca, k,
				QObject::tr("is no member of the setting"));
	for (const QString &k : members)
		if (!o.contains(k))
			throw settingsInvalid(ca, k, QObject::tr("is missing"));

	/* the checks of the command line options (cli/lifecycle.cpp) */
	QString why;
	IsoDuration v;
	if (!o["validity"].isString())
		why = QObject::tr("is no string");
	else
		v = IsoDuration::parse(o["validity"].toString(), &why);
	if (why.isEmpty())
		why = validityError(v);
	if (!why.isEmpty())
		throw settingsInvalid(ca, "validity", why);
	p.validity = v;

	QJsonValue f = o["reissue_fraction"];
	if (!f.isDouble() || !(f.toDouble() > 0 && f.toDouble() < 0.5))
		throw settingsInvalid(ca, "reissue_fraction", QObject::tr(
			"must be a number greater than 0 and below 1/2"));
	p.reissueFraction = f.toDouble();

	/* an integer that a double holds exactly */
	QJsonValue b = o["size_budget"];
	double bd = b.toDouble();
	if (!b.isDouble() || bd != std::floor(bd) || bd < minSizeBudget ||
	    bd > 9007199254740992.0)
		throw settingsInvalid(ca, "size_budget", QObject::tr(
			"must be a whole number of bytes, at least %1")
			.arg(minSizeBudget));
	p.sizeBudget = (qint64)bd;
	return p;
}

QJsonObject CrlPolicy::toJson() const
{
	QJsonObject o;
	o["validity"] = validity.toString();
	o["reissue_fraction"] = reissueFraction;
	o["size_budget"] = sizeBudget;
	return o;
}

void CrlPolicy::store(const ServiceContext &ctx, pki_x509 *ca) const
{
	AuditParams params;
	QString id = ca ? ca->getSqlItemId().toString() : QString();
	if (ca) {
		params.set("ca_id", ca->getSqlItemId().toLongLong());
		params.set("name", ca->getIntName());
	}
	params.set("crl_validity", validity.toString());
	params.set("reissue_fraction", fractionText(reissueFraction));
	params.set("size_budget", sizeBudget);

	/* crlDays: the validity is whole days (checkValidity()) */
	QDateTime t0(QDate(2000, 1, 1), QTime(0, 0), Qt::UTC);
	qint64 secs = t0.secsTo(validity.addTo(t0));
	int days = (int)qMax<qint64>(1, secs / 86400);

	auditedTransaction(ctx, actionSettings, "certificate", id, params,
				[&]() {
		if (!ca || !ca->isCA() || !ca->getSqlItemId().isValid())
			throw serviceError("issuer_not_ca", QObject::tr(
				"CRL settings need a CA certificate of the "
				"database"));
		XSqlQuery q;
		SQL_PREPARE(q, "DELETE FROM settings WHERE key_=?");
		q.bindValue(0, settingsKey(ca));
		q.exec();
		if (q.lastError().isValid())
			throw serviceError("database_error",
				q.lastError().text());
		SQL_PREPARE(q, "INSERT INTO settings (key_, value) "
				"VALUES (?, ?)");
		q.bindValue(0, settingsKey(ca));
		q.bindValue(1, QString::fromUtf8(QJsonDocument(toJson())
				.toJson(QJsonDocument::Compact)));
		q.exec();
		if (q.lastError().isValid())
			throw serviceError("database_error",
				q.lastError().text());
		SQL_PREPARE(q, "UPDATE authority SET crlDays=? WHERE item=?");
		q.bindValue(0, days);
		q.bindValue(1, ca->getSqlItemId());
		AffectedItems(ca->getSqlItemId());
		q.exec();
		if (q.lastError().isValid())
			throw serviceError("database_error",
				q.lastError().text());
		int old = ca->getCrlDays();
		ca->setCrlDays(days);
		DbTransaction::onRollback([ca, old]() {
			ca->setCrlDays(old);
		});
		AuditLog::append(ctx, actionSettings, "certificate", id,
				params);
	});
}

QDateTime CrlPolicy::nextUpdate(const QDateTime &thisUpdate) const
{
	return validity.addTo(thisUpdate);
}

QDateTime CrlPolicy::reissueAt(const pki_crl *crl) const
{
	QDateTime t = crl->getLastUpdate(), n = crl->getNextUpdate();
	qint64 span = t.secsTo(n);
	return t.addSecs((qint64)std::floor(span * reissueFraction));
}

bool CrlPolicy::reissueDue(const pki_crl *crl, const QDateTime &now) const
{
	return now >= reissueAt(crl);
}

bool CrlPolicy::expired(const pki_crl *crl, const QDateTime &now)
{
	return now >= (QDateTime)crl->getNextUpdate();
}

double CrlPolicy::parseFraction(const QString &text, const QString &option)
{
	static const QRegularExpression ratio("^([0-9]+)/([0-9]+)$");
	static const QRegularExpression dec("^0?\\.[0-9]+$");
	double f = -1;
	QRegularExpressionMatch m = ratio.match(text);
	if (m.hasMatch() && m.captured(2).toLongLong() > 0)
		f = m.captured(1).toDouble() / m.captured(2).toDouble();
	else if (dec.match(text).hasMatch())
		f = text.toDouble();
	if (!(f > 0 && f < 0.5))
		throw serviceError("invalid_value", QObject::tr(
			"--%1 '%2' must be a fraction such as 1/3 or 0.25, "
			"greater than 0 and below 1/2 (IDIAL replaces a CRL "
			"after half of its lifetime)").arg(option, text));
	return f;
}

QString CrlPolicy::validityError(const IsoDuration &d)
{
	if (!d.isValid())
		return QObject::tr("is no ISO 8601 duration");
	/* years and months have no fixed number of days */
	qint64 secs = (d.weeks * 7 + d.days) * 86400 + d.hours * 3600 +
		d.minutes * 60 + d.seconds;
	if (d.years || d.months || secs < 86400 || secs % 86400)
		return QObject::tr("must be a whole number of days, at least "
			"P1D, e.g. P7D or P1W: the GUI issues the CRLs of the "
			"CA for its CRL days (no years, months or parts of a "
			"day)");
	if (secs / 86400 > INT_MAX)
		return QObject::tr("is too long");
	return QString();
}

IsoDuration CrlPolicy::checkValidity(const IsoDuration &d,
			const QString &option)
{
	QString why = validityError(d);
	if (!why.isEmpty())
		throw serviceError("invalid_validity",
			QString("--%1 '%2' %3").arg(option)
			.arg(d.isValid() ? d.toString() : QString(), why));
	return d;
}

QString CrlPolicy::fractionText(double f)
{
	if (std::fabs(f - 1.0 / 3.0) < 1e-12)
		return "1/3";
	return QString::number(f, 'g', 6);
}

pki_crl *CrlPolicy::latestCrl(const pki_x509 *ca)
{
	pki_crl *best = nullptr;
	a1int bestNo;
	if (!ca)
		return nullptr;
	for (pki_crl *crl : Store.getAll<pki_crl>()) {
		if (crl->getIssuer() != ca)
			continue;
		/* without a CRL number: 0 */
		a1int no(0L);
		crl->getCrlNumber(&no);
		if (!best || no > bestNo || (no == bestNo &&
		    crl->getLastUpdate() > best->getLastUpdate())) {
			best = crl;
			bestNo = no;
		}
	}
	return best;
}

QString CrlPolicy::durationText(qint64 seconds)
{
	if (seconds <= 0)
		return "PT0S";
	IsoDuration d;
	d.valid = true;
	d.days = seconds / 86400;
	d.hours = (seconds % 86400) / 3600;
	d.minutes = (seconds % 3600) / 60;
	d.seconds = seconds % 60;
	return d.toString();
}
