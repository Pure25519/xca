/* vi: set sw=4 ts=4:
 *
 * Tamper-evident audit log of the bxc-pki fork (BTD-29, PLAN.md section 6).
 */

#include "audit.h"
#include "audit_key.h"
#include "asn1time.h"
#include "exception.h"
#include "settings.h"
#include "sql.h"

#include <QCryptographicHash>
#include <QJsonDocument>
#include <QMap>
#include <QPair>
#include <QSet>
#include <cmath>

#if !defined(Q_OS_WIN32)
#include <pwd.h>
#include <unistd.h>
#endif

const QByteArray AuditLog::genesisHash = QByteArray(64, '0');
const char AuditLog::actionRevoke[] = "certificate.revoke";
const char AuditLog::actionUnrevoke[] = "certificate.unrevoke";
const char AuditLog::actionCrlGenerate[] = "crl.generate";
const char AuditLog::actionRevocationBaseline[] = "revocation.baseline";
const char AuditLog::actionInit[] = "audit.init";
const char AuditLog::actionCheckpoint[] = "audit.checkpoint";
const char AuditLog::actionKeyCreate[] = "audit.key_create";
const int AuditLog::defaultCheckpointInterval = 100;

/* Largest integer that RFC 8785 serialises exactly (IEEE 754 double) */
static const qint64 maxSafeInteger = 9007199254740991LL;

enum ServiceContext::channel ServiceContext::processChannel = ServiceContext::gui;
bool ServiceContext::processPasswordVerified = false;

ServiceContext::ServiceContext(enum channel c, const QString &actor)
	: chan(c), actorId(actor)
{
}

QString ServiceContext::osUser()
{
	QString user;
#if defined(Q_OS_WIN32)
	user = qEnvironmentVariable("USERNAME");
#else
	struct passwd *pw = getpwuid(geteuid());
	if (pw && pw->pw_name)
		user = QString::fromLocal8Bit(pw->pw_name);
	if (user.isEmpty())
		user = qEnvironmentVariable("USER");
#endif
	return user.isEmpty() ? QString("unknown") : user;
}

void ServiceContext::confirm(const QString &id, const QString &source)
{
	QString c = id + ":" + source;
	if (!confirmed.contains(c))
		confirmed << c;
}

ServiceContext ServiceContext::localUser(enum channel c)
{
	ServiceContext ctx(c, "os:" + osUser());
	ctx.pwVerified = processPasswordVerified;
	return ctx;
}

QString ServiceContext::channelName(enum channel c)
{
	switch (c) {
	case gui: return "gui";
	case cli: return "cli";
	case rest: return "rest";
	case est: return "est";
	case cmp: return "cmp";
	}
	return "unknown";
}

/* No key of this list may carry a secret (PLAN.md 6.4) */
const QStringList &AuditParams::allowList()
{
	static const QStringList list {
		"ca_id", "confirmed", "count", "crl_number", "curve",
		"db_unlock_verified", "der_size", "file", "fingerprint",
		"format", "hash_algo", "invalidity_date", "issuer", "item_id",
		"key_size", "key_type", "name", "next_update", "not_after",
		"not_before", "question", "reason", "reason_bit",
		"revocation_date", "serial", "subject", "template",
		"this_update",
	};
	/* Signed checkpoints and the audit keys (BTD-37) */
	static const QStringList withCheckpoints = list + QStringList {
		"checkpoint_hash", "checkpoint_seq", "checkpoint_time",
		"key_id", "next_key_id", "public_key", "signature",
	};
	return withCheckpoints;
}

bool AuditParams::allowed(const QString &key)
{
	return allowList().contains(key);
}

AuditParams &AuditParams::store(const QString &key, const QVariant &v)
{
	if (allowed(key))
		values[key] = v;
	else if (!droppedKeys.contains(key))
		droppedKeys << key;
	return *this;
}

AuditParams &AuditParams::set(const QString &key, const QString &v)
{
	return store(key, v);
}

AuditParams &AuditParams::set(const QString &key, const char *v)
{
	return store(key, QString(v));
}

AuditParams &AuditParams::set(const QString &key, qint64 v)
{
	return store(key, v);
}

AuditParams &AuditParams::set(const QString &key, int v)
{
	return store(key, (qint64)v);
}

AuditParams &AuditParams::set(const QString &key, bool v)
{
	return store(key, v);
}

/* Invalid dates and the RFC 5280 "undefined" date of a1time become null */
AuditParams &AuditParams::set(const QString &key, const QDateTime &v)
{
	if (!v.isValid() || v.toSecsSinceEpoch() == 0)
		return store(key, QVariant());
	return store(key, AuditLog::rfc3339(v));
}

AuditParams AuditParams::fromMap(const QVariantMap &map)
{
	AuditParams p;

	for (auto i = map.constBegin(); i != map.constEnd(); ++i) {
		const QVariant &v = i.value();
		switch (v.metaType().id()) {
		case QMetaType::QString:
			p.set(i.key(), v.toString());
			break;
		case QMetaType::Bool:
			p.set(i.key(), v.toBool());
			break;
		case QMetaType::Int:
		case QMetaType::UInt:
		case QMetaType::LongLong:
			p.set(i.key(), v.toLongLong());
			break;
		case QMetaType::QDateTime:
			p.set(i.key(), v.toDateTime());
			break;
		default:
			/* QByteArray (raw key material), Passwd, ... */
			if (!p.droppedKeys.contains(i.key()))
				p.droppedKeys << i.key();
		}
	}
	return p;
}

AuditParams AuditParams::revocation(qint64 caId, const QString &serial,
		int reasonBit, const QDateTime &date, const QDateTime &invalDate)
{
	AuditParams p;
	p.set("ca_id", caId).set("serial", serial.toUpper())
	 .set("reason_bit", reasonBit).set("revocation_date", date)
	 .set("invalidity_date", invalDate);
	return p;
}

AuditParams AuditParams::unrevocation(qint64 caId, const QString &serial)
{
	AuditParams p;
	p.set("ca_id", caId).set("serial", serial.toUpper());
	return p;
}

AuditParams AuditParams::crl(qint64 caId, qint64 crlNumber)
{
	AuditParams p;
	p.set("ca_id", caId).set("crl_number", crlNumber);
	return p;
}

QVariantMap AuditEntry::toMap(bool withHashes) const
{
	QVariantMap m;
	m["seq"] = seq;
	m["time"] = time;
	m["actor"] = actor;
	m["channel"] = channel;
	m["action"] = action;
	m["object_type"] = objectType;
	m["object_id"] = objectId;
	m["params"] = params;
	m["result"] = result;
	m["error_code"] = errorCode.isEmpty() ? QVariant() : errorCode;
	if (withHashes) {
		m["prev_hash"] = QString::fromLatin1(prevHash);
		m["hash"] = QString::fromLatin1(hash);
	}
	return m;
}

QByteArray AuditEntry::canonical() const
{
	return AuditLog::canonicalJson(toMap(false));
}

QByteArray AuditEntry::computeHash() const
{
	return AuditLog::chainHash(prevHash, canonical());
}

QVariantMap AuditStateMismatch::toMap() const
{
	QVariantMap m;
	m["ca_id"] = caId;
	m["serial"] = serial;
	m["field"] = field;
	m["expected"] = expected;
	m["actual"] = actual;
	m["seq"] = seq;
	return m;
}

QVariantMap AuditVerifyResult::toMap() const
{
	QVariantMap m;
	QVariantList list;

	for (const AuditStateMismatch &mm : mismatches)
		list << mm.toMap();
	m["ok"] = ok();
	m["chain_ok"] = chainOk();
	m["entries"] = entries;
	m["verified_entries"] = verifiedEntries;
	m["first_broken_seq"] = firstBrokenSeq ? QVariant(firstBrokenSeq)
						: QVariant();
	m["reason"] = reason.isEmpty() ? QVariant() : reason;
	m["state_mismatches"] = list;
	m["unaudited_revocations"] = unauditedRevocations;
	m["checkpoints"] = checkpoints;
	m["last_checkpoint_seq"] = lastCheckpointSeq ?
				QVariant(lastCheckpointSeq) : QVariant();
	m["failed_checkpoint_seq"] = failedCheckpointSeq ?
				QVariant(failedCheckpointSeq) : QVariant();
	m["unanchored_entries"] = unanchoredEntries;
	m["audit_keys"] = auditKeys;
	return m;
}

QByteArray AuditVerifyResult::toJson() const
{
	return AuditLog::canonicalJson(toMap());
}

/* RFC 8785 section 3.2.2.2: escape only '"', '\' and control characters */
static QByteArray canonicalString(const QString &s)
{
	static const char hex[] = "0123456789abcdef";
	QString out = "\"";

	for (QChar c : s) {
		ushort u = c.unicode();
		switch (u) {
		case '"': out += "\\\""; break;
		case '\\': out += "\\\\"; break;
		case '\b': out += "\\b"; break;
		case '\f': out += "\\f"; break;
		case '\n': out += "\\n"; break;
		case '\r': out += "\\r"; break;
		case '\t': out += "\\t"; break;
		default:
			if (u < 0x20) {
				out += "\\u00";
				out += QLatin1Char(hex[u >> 4]);
				out += QLatin1Char(hex[u & 0xf]);
			} else {
				out += c;
			}
		}
	}
	out += "\"";
	return out.toUtf8();
}

static QByteArray canonicalInteger(qint64 i)
{
	if (i > maxSafeInteger || i < -maxSafeInteger)
		throw errorEx(QString("Audit value out of the safe "
				"integer range: %1").arg(i));
	return QByteArray::number(i);
}

QByteArray AuditLog::canonicalJson(const QVariant &v)
{
	QByteArray out;

	switch (v.metaType().id()) {
	case QMetaType::UnknownType:
	case QMetaType::Nullptr:
		return "null";
	case QMetaType::Bool:
		return v.toBool() ? "true" : "false";
	case QMetaType::Int:
	case QMetaType::UInt:
	case QMetaType::LongLong:
		return canonicalInteger(v.toLongLong());
	case QMetaType::ULongLong:
		if (v.toULongLong() > (qulonglong)maxSafeInteger)
			throw errorEx(QString("Audit value out of the safe "
				"integer range: %1").arg(v.toULongLong()));
		return canonicalInteger(v.toLongLong());
	case QMetaType::Double: {
		/* Only integral values: QJsonDocument reads every number
		 * back as double or qlonglong */
		double d = v.toDouble();
		if (!std::isfinite(d) || std::floor(d) != d)
			throw errorEx(QString("Audit value is not an integer: %1")
					.arg(d));
		/* Range first: casting an out-of-range double is undefined */
		if (std::fabs(d) > (double)maxSafeInteger)
			throw errorEx(QString("Audit value out of the safe "
					"integer range: %1").arg(d));
		return canonicalInteger((qint64)d);
	}
	case QMetaType::QString:
		return canonicalString(v.toString());
	case QMetaType::QVariantList:
	case QMetaType::QStringList: {
		QVariantList list = v.toList();
		out = "[";
		for (int i = 0; i < list.size(); i++) {
			if (i)
				out += ",";
			out += canonicalJson(list[i]);
		}
		return out + "]";
	}
	case QMetaType::QVariantMap: {
		/* QMap sorts by QString::operator<, which compares UTF-16
		 * code units like RFC 8785 section 3.2.3 demands */
		QVariantMap map = v.toMap();
		out = "{";
		for (auto i = map.constBegin(); i != map.constEnd(); ++i) {
			if (i != map.constBegin())
				out += ",";
			out += canonicalString(i.key()) + ":" +
				canonicalJson(i.value());
		}
		return out + "}";
	}
	default:
		throw errorEx(QString("Audit value of type %1 has no "
				"canonical JSON form").arg(v.typeName()));
	}
}

QByteArray AuditLog::chainHash(const QByteArray &prevHashHex,
		const QByteArray &canonical)
{
	QCryptographicHash h(QCryptographicHash::Sha256);
	h.addData(QByteArray::fromHex(prevHashHex));
	h.addData(canonical);
	return h.result().toHex();
}

QString AuditLog::rfc3339(const QDateTime &t)
{
	QDateTime utc = t.toUTC();
	return utc.toString(utc.time().msec() ? Qt::ISODateWithMs
					     : Qt::ISODate);
}

static void throwOnError(XSqlQuery &q)
{
	QSqlError e = q.lastError();
	if (e.isValid())
		throw errorEx(QObject::tr("Database error: %1").arg(e.text()));
}

/* append() without the checkpoint check */
static AuditEntry insertEntry(const ServiceContext &ctx,
		const QString &action, const QString &objectType,
		const QString &objectId, const AuditParams &params,
		const QString &result = "success",
		const QString &errorCode = QString())
{
	static const QStringList results { "success", "failure", "denied" };
	XSqlQuery q;
	AuditEntry e;

	if (action.isEmpty())
		throw errorEx("Audit entry without action");
	if (!results.contains(result))
		throw errorEx(QString("Invalid audit result '%1'").arg(result));

	Transaction;
	TransThrow();

	SQL_PREPARE(q, "SELECT seq, hash FROM audit_log "
			"ORDER BY seq DESC LIMIT 1");
	q.exec();
	throwOnError(q);
	e.seq = 1;
	e.prevHash = AuditLog::genesisHash;
	if (q.next()) {
		e.seq = q.value(0).toLongLong() + 1;
		e.prevHash = q.value(1).toString().toLatin1();
	}
	e.time = AuditLog::rfc3339(QDateTime::currentDateTimeUtc());
	e.actor = ctx.actor();
	e.channel = ctx.channelName();
	e.action = action;
	e.objectType = objectType;
	e.objectId = objectId;
	e.params = params.getValues();
	e.result = result;
	e.errorCode = errorCode;
	e.hash = e.computeHash();

	SQL_PREPARE(q, "INSERT INTO audit_log (seq, created, actor, channel, "
			"action, object_type, object_id, params, result, "
			"error_code, prev_hash, hash) "
			"VALUES (?,?,?,?,?,?,?,?,?,?,?,?)");
	q.bindValue(0, e.seq);
	q.bindValue(1, e.time);
	q.bindValue(2, e.actor);
	q.bindValue(3, e.channel);
	q.bindValue(4, e.action);
	q.bindValue(5, e.objectType);
	q.bindValue(6, e.objectId);
	q.bindValue(7, QString::fromUtf8(AuditLog::canonicalJson(e.params)));
	q.bindValue(8, e.result);
	q.bindValue(9, e.errorCode.isEmpty() ? QVariant() : e.errorCode);
	q.bindValue(10, QString::fromLatin1(e.prevHash));
	q.bindValue(11, QString::fromLatin1(e.hash));
	q.exec();
	throwOnError(q);
	TransCommit();
	return e;
}

/* seq of the newest checkpoint entry, 0 if there is none */
static qint64 lastCheckpointSeq()
{
	XSqlQuery q;

	SQL_PREPARE(q, "SELECT MAX(seq) FROM audit_log WHERE action=?");
	q.bindValue(0, QString(AuditLog::actionCheckpoint));
	q.exec();
	throwOnError(q);
	return q.next() ? q.value(0).toLongLong() : 0;
}

int AuditLog::checkpointInterval()
{
	int n = Settings["audit_checkpoint_interval"];
	return n > 0 ? n : defaultCheckpointInterval;
}

AuditEntry AuditLog::append(const ServiceContext &ctx,
		const QString &action, const QString &objectType,
		const QString &objectId, const AuditParams &params,
		const QString &result, const QString &errorCode)
{
	if (action == actionCheckpoint || action == actionKeyCreate)
		throw errorEx(QString("Audit action '%1' is reserved")
				.arg(action));
	/* The questions confirmed for this operation (BTD-71) and whether
	 * the database password was checked on open (BTD-78). Only here:
	 * a checkpoint signs exactly the params it stores. */
	AuditParams p = params;
	if (!ctx.confirmations().isEmpty())
		p.set("confirmed", ctx.confirmations().join(","));
	p.set("db_unlock_verified", ctx.passwordVerified());
	AuditEntry e = insertEntry(ctx, action, objectType, objectId,
				p, result, errorCode);
	if (e.seq - lastCheckpointSeq() < checkpointInterval())
		return e;
	try {
		checkpoint(ctx);
	} catch (serviceError &err) {
		/* Thrown before anything was written: the entry stays,
		 * the next append() tries again */
		qWarning() << "No audit checkpoint after entry" << e.seq
			<< err.code << err.getString();
	}
	return e;
}

/* True if the stored params text is exactly the canonical JSON of an
 * object, as append() writes it */
static bool canonicalParams(const QString &stored, QVariantMap *params)
{
	QJsonDocument doc = QJsonDocument::fromJson(stored.toUtf8());
	if (!doc.isObject())
		return false;
	*params = doc.toVariant().toMap();
	try {
		return AuditLog::canonicalJson(*params) == stored.toUtf8();
	} catch (errorEx &) {
		return false;
	}
}

/* badParams collects the entries whose params column is not the
 * canonical JSON of an object */
static QList<AuditEntry> readEntries(QSet<qint64> *badParams,
					qint64 fromSeq = 1)
{
	XSqlQuery q;
	QList<AuditEntry> list;

	SQL_PREPARE(q, "SELECT seq, created, actor, channel, action, "
			"object_type, object_id, params, result, error_code, "
			"prev_hash, hash FROM audit_log WHERE seq >= ? "
			"ORDER BY seq");
	q.bindValue(0, fromSeq);
	q.exec();
	throwOnError(q);
	while (q.next()) {
		AuditEntry e;
		e.seq = q.value(0).toLongLong();
		e.time = q.value(1).toString();
		e.actor = q.value(2).toString();
		e.channel = q.value(3).toString();
		e.action = q.value(4).toString();
		e.objectType = q.value(5).toString();
		e.objectId = q.value(6).toString();
		if (!canonicalParams(q.value(7).toString(), &e.params) &&
		    badParams)
			*badParams << e.seq;
		e.result = q.value(8).toString();
		e.errorCode = q.value(9).toString();
		e.prevHash = q.value(10).toString().toLatin1();
		e.hash = q.value(11).toString().toLatin1();
		list << e;
	}
	return list;
}

QList<AuditEntry> AuditLog::entries()
{
	return readEntries(nullptr);
}

QByteArray AuditLog::checkpointPayload(const QVariantMap &params)
{
	QVariantMap signedPart = params;
	signedPart.remove("signature");
	return canonicalJson(signedPart);
}

/* The entries from the last checkpoint on must chain before they are
 * signed: a checkpoint never anchors a chain that is already broken */
static qint64 checkUnsignedTail(qint64 fromSeq)
{
	QSet<qint64> badParams;
	QByteArray prev = fromSeq == 1 ? AuditLog::genesisHash : QByteArray();
	qint64 expected = fromSeq;

	for (const AuditEntry &e : readEntries(&badParams, fromSeq)) {
		bool ok = e.seq == expected && !badParams.contains(e.seq) &&
			(prev.isEmpty() || e.prevHash == prev);
		try {
			ok = ok && e.computeHash() == e.hash;
		} catch (errorEx &) {
			ok = false;
		}
		if (!ok)
			throw serviceError("audit_chain_broken", QObject::tr(
				"Audit entry %1 does not chain, no checkpoint "
				"is signed; run --audit-verify").arg(expected));
		prev = e.hash;
		expected++;
	}
	return expected - fromSeq;
}

/* Announces a new audit key in the chain */
static QString announceKey(const ServiceContext &ctx, const Passwd &pass)
{
	QByteArray pem;
	QString id = AuditKey::create(pass, &pem);
	AuditParams p;
	p.set("key_id", id).set("key_type", AuditKey::typeEd25519)
	 .set("public_key", QString::fromLatin1(pem));
	insertEntry(ctx, AuditLog::actionKeyCreate, "audit_key", id, p);
	return id;
}

/* Signs the newest entry with key; next names the key that signs the
 * following checkpoints */
static AuditEntry signHead(const ServiceContext &ctx, const QString &key,
			const QString &next, const Passwd &pass)
{
	XSqlQuery q;
	AuditParams p;

	SQL_PREPARE(q, "SELECT seq, hash FROM audit_log "
			"ORDER BY seq DESC LIMIT 1");
	q.exec();
	throwOnError(q);
	if (!q.next())
		throw errorEx("No audit entry to sign");
	p.set("checkpoint_seq", q.value(0).toLongLong());
	p.set("checkpoint_hash", q.value(1).toString());
	p.set("checkpoint_time", QDateTime::currentDateTimeUtc());
	p.set("key_id", key);
	if (!next.isEmpty())
		p.set("next_key_id", next);
	QByteArray sig = AuditKey::sign(key,
			AuditLog::checkpointPayload(p.getValues()), pass);
	p.set("signature", QString::fromLatin1(sig.toBase64()));
	return insertEntry(ctx, AuditLog::actionCheckpoint, "audit_key",
				key, p);
}

/* Every serviceError is thrown before the first write, so that a failed
 * automatic checkpoint does not roll back the caller's transaction */
static AuditEntry writeCheckpoint(const ServiceContext &ctx, bool rotate)
{
	XSqlQuery q;
	SQL_PREPARE(q, "SELECT 1 FROM audit_log LIMIT 1");
	q.exec();
	throwOnError(q);
	if (!q.next())
		throw serviceError("empty_audit_log",
			QObject::tr("The audit log has no entry to sign"));
	/* the password first: without it the export reads only */
	Passwd pass = AuditKey::password();
	qint64 last = lastCheckpointSeq();
	checkUnsignedTail(last ? last : 1);
	QString key = AuditKey::current();
	AuditEntry e;

	Transaction;
	TransThrow();
	if (key.isEmpty()) {
		/* first use */
		key = announceKey(ctx, pass);
		e = signHead(ctx, key, QString(), pass);
	} else if (rotate) {
		QString next = announceKey(ctx, pass);
		e = signHead(ctx, key, next, pass);
		AuditKey::retire(key);
	} else {
		e = signHead(ctx, key, QString(), pass);
	}
	TransCommit();
	return e;
}

AuditEntry AuditLog::checkpoint(const ServiceContext &ctx)
{
	return writeCheckpoint(ctx, false);
}

AuditEntry AuditLog::rotateKey(const ServiceContext &ctx)
{
	return writeCheckpoint(ctx, true);
}

QByteArray AuditLog::exportJsonLines(qint64 *unsignedEntries)
{
	return exportJsonLines(ServiceContext::localUser(
			ServiceContext::processChannel), unsignedEntries);
}

QByteArray AuditLog::exportJsonLines(const ServiceContext &ctx,
				qint64 *unsignedEntries)
{
	QByteArray out;
	QList<AuditEntry> list = entries();
	qint64 lastCheckpoint = 0;

	if (!list.isEmpty() && list.last().action != actionCheckpoint) {
		try {
			checkpoint(ctx);
			list = entries();
		} catch (serviceError &err) {
			/* No password source: a read-only export without a
			 * new checkpoint (BTD-70); nothing was written */
			if (err.code != "audit_key_unavailable")
				throw;
		}
	}
	for (const AuditEntry &e : list)
		if (e.action == actionCheckpoint)
			lastCheckpoint = e.seq;
	if (unsignedEntries)
		*unsignedEntries = list.size() - lastCheckpoint;
	for (const AuditEntry &e : list) {
		try {
			out += canonicalJson(e.toMap(true)) + "\n";
		} catch (errorEx &err) {
			throw errorEx(QString("Audit entry %1 cannot be exported, "
				"run --audit-verify: %2").arg(e.seq)
				.arg(err.getString()));
		}
	}
	return out;
}

void AuditLog::writeBaseline()
{
	XSqlQuery q;
	QList<AuditParams> rows;

	Transaction;
	TransThrow();
	SQL_PREPARE(q, "SELECT caId, serial, date, invaldate, crlNo, reasonBit "
			"FROM revocations ORDER BY caId, serial");
	q.exec();
	throwOnError(q);
	while (q.next()) {
		a1time date, invalDate;
		date.fromPlain(q.value(2).toString());
		invalDate.fromPlain(q.value(3).toString());
		AuditParams p = AuditParams::revocation(q.value(0).toLongLong(),
			q.value(1).toString(), q.value(5).toInt(), date, invalDate);
		if (!q.value(4).isNull())
			p.set("crl_number", q.value(4).toLongLong());
		rows << p;
	}
	ServiceContext ctx = ServiceContext::localUser(
				ServiceContext::processChannel);
	/* No checkpoint here: the database is not unlocked yet */
	for (const AuditParams &p : rows)
		insertEntry(ctx, actionRevocationBaseline, "cert",
			p.getValues().value("serial").toString(), p);
	insertEntry(ctx, actionInit, "database", QString(),
		AuditParams().set("count", (qint64)rows.size()));
	TransCommit();
}

/* RFC 3339 of a date in the revocations table; empty if undefined */
static QString revocationDate(const QVariant &plain)
{
	a1time t;

	if (plain.isNull() || t.fromPlain(plain.toString()) != 0)
		return QString();
	return t.isUndefined() ? QString() : AuditLog::rfc3339(t);
}

/* The same normalisation for a date taken from an audit entry */
static QString auditDate(const QVariant &rfc)
{
	QDateTime t = QDateTime::fromString(rfc.toString(), Qt::ISODate);
	if (!t.isValid() || t.toSecsSinceEpoch() == 0)
		return QString();
	return AuditLog::rfc3339(t);
}

/* Checks the checkpoints of the intact chain list (seq 1, 2, ...) in
 * order: each one signed by the current key over the hash the chain has
 * at its checkpoint_seq. Sets the checkpoint fields of r and, at the
 * first invalid checkpoint, firstBrokenSeq to the entry after the last
 * valid one. */
static void verifyCheckpoints(const QList<AuditEntry> &list,
				AuditVerifyResult &r)
{
	QMap<QString, QByteArray> announced;	// key id -> public PEM
	QString signer;
	qint64 anchored = 0;

	for (const AuditEntry &e : list) {
		QString reason;
		const QVariantMap &p = e.params;

		if (e.action == AuditLog::actionKeyCreate) {
			QString id = p.value("key_id").toString();
			QByteArray pem = p.value("public_key").toString().toLatin1();
			if (id.isEmpty() || AuditKey::keyId(pem) != id) {
				reason = "checkpoint_key";
			} else {
				announced[id] = pem;
				/* the first key is trusted on first use */
				if (signer.isEmpty()) {
					signer = id;
					r.auditKeys << id;
				}
			}
		} else if (e.action == AuditLog::actionCheckpoint) {
			QString key = p.value("key_id").toString();
			QString next = p.value("next_key_id").toString();
			qint64 n = p.value("checkpoint_seq").toLongLong();
			QByteArray hash = p.value("checkpoint_hash").toString().toLatin1();
			QByteArray sig = QByteArray::fromBase64(
				p.value("signature").toString().toLatin1());

			if (key.isEmpty() || key != signer)
				reason = "checkpoint_key";
			else if (!AuditKey::verify(announced[key],
					AuditLog::checkpointPayload(p), sig))
				reason = "checkpoint_signature";
			else if (n < 1 || n >= e.seq || list[n - 1].hash != hash)
				reason = "checkpoint_hash";
			else if (!next.isEmpty() && !announced.contains(next))
				reason = "checkpoint_key";
			if (reason.isEmpty()) {
				anchored = e.seq;
				r.checkpoints++;
				if (!next.isEmpty()) {
					signer = next;
					r.auditKeys << next;
				}
			}
		}
		if (!reason.isEmpty()) {
			r.firstBrokenSeq = anchored + 1;
			r.reason = reason;
			r.failedCheckpointSeq = e.seq;
			break;
		}
	}
	r.lastCheckpointSeq = anchored;
	r.unanchoredEntries = r.entries - anchored;
}

namespace {
class revocationState
{
  public:
	bool present{};
	QString date{}, invaldate{};
	qint64 reasonBit{}, crlNo{};
	qint64 seq{};
};
}

AuditVerifyResult AuditLog::verify()
{
	typedef QPair<qint64, QString> revKey;
	AuditVerifyResult r;
	QSet<qint64> badParams;
	QList<AuditEntry> list = readEntries(&badParams);
	QList<AuditEntry> verified;
	QByteArray prev = genesisHash;
	qint64 expected = 1;

	r.entries = list.size();
	for (const AuditEntry &e : list) {
		if (e.seq != expected) {
			r.firstBrokenSeq = expected;
			r.reason = e.seq > expected ? "missing" : "sequence";
			break;
		}
		if (e.prevHash != prev) {
			r.firstBrokenSeq = e.seq;
			r.reason = "prev_hash";
			break;
		}
		if (badParams.contains(e.seq)) {
			r.firstBrokenSeq = e.seq;
			r.reason = "params";
			break;
		}
		bool hashOk = false;
		try {
			hashOk = e.computeHash() == e.hash;
		} catch (errorEx &) {
			/* fail closed: no canonical form, no valid entry */
		}
		if (!hashOk) {
			r.firstBrokenSeq = e.seq;
			r.reason = "hash";
			break;
		}
		prev = e.hash;
		expected++;
		verified << e;
	}
	r.verifiedEntries = verified.size();
	verifyCheckpoints(verified, r);

	/* Replay what the intact part of the chain says about revocations */
	QMap<revKey, revocationState> state;
	for (const AuditEntry &e : verified) {
		qint64 ca = e.params.value("ca_id").toLongLong();
		revKey key(ca, e.params.value("serial").toString().toUpper());

		if (e.result != "success")
			continue;
		if (e.action == actionRevoke ||
		    e.action == actionRevocationBaseline) {
			revocationState s;
			s.present = true;
			s.date = auditDate(e.params.value("revocation_date"));
			s.invaldate = auditDate(e.params.value("invalidity_date"));
			s.reasonBit = e.params.value("reason_bit").toLongLong();
			/* only a baseline row can already be in a CRL */
			s.crlNo = e.params.value("crl_number").toLongLong();
			s.seq = e.seq;
			state[key] = s;
		} else if (e.action == actionUnrevoke) {
			revocationState s;
			s.seq = e.seq;
			state[key] = s;
		} else if (e.action == actionCrlGenerate) {
			/* db_crl::newCrl(): crlNo=? WHERE crlNo IS NULL */
			qint64 num = e.params.value("crl_number").toLongLong();
			for (auto i = state.begin(); i != state.end(); ++i) {
				if (i.key().first == ca && i->present && !i->crlNo) {
					i->crlNo = num;
					i->seq = e.seq;
				}
			}
		}
	}

	XSqlQuery q;
	QSet<revKey> seen;
	SQL_PREPARE(q, "SELECT caId, serial, date, invaldate, crlNo, reasonBit "
			"FROM revocations");
	q.exec();
	throwOnError(q);
	while (q.next()) {
		revKey key(q.value(0).toLongLong(),
			q.value(1).toString().toUpper());
		seen << key;
		AuditStateMismatch m;
		m.caId = key.first;
		m.serial = key.second;
		if (!state.contains(key)) {
			/* Neither revoked through the service layer nor in the
			 * baseline of the upgrade: inserted behind XCA's back,
			 * or by a build without audit log */
			r.unauditedRevocations++;
			m.field = "row";
			m.expected = "absent";
			m.actual = "present";
			r.mismatches << m;
			continue;
		}
		const revocationState &s = state[key];
		m.seq = s.seq;
		if (!s.present) {
			m.field = "row";
			m.expected = "absent";
			m.actual = "present";
			r.mismatches << m;
			continue;
		}
		QList<QPair<QString, QPair<QString, QString> > > fields {
			{ "date", { s.date, revocationDate(q.value(2)) } },
			{ "invaldate", { s.invaldate, revocationDate(q.value(3)) } },
			{ "crlNo", { QString::number(s.crlNo),
				QString::number(q.value(4).toLongLong()) } },
			{ "reasonBit", { QString::number(s.reasonBit),
				QString::number(q.value(5).toLongLong()) } },
		};
		for (const auto &f : fields) {
			if (f.second.first == f.second.second)
				continue;
			m.field = f.first;
			m.expected = f.second.first;
			m.actual = f.second.second;
			r.mismatches << m;
		}
	}
	for (auto i = state.constBegin(); i != state.constEnd(); ++i) {
		if (!i->present || seen.contains(i.key()))
			continue;
		AuditStateMismatch m;
		m.caId = i.key().first;
		m.serial = i.key().second;
		m.seq = i->seq;
		m.field = "row";
		m.expected = "present";
		m.actual = "absent";
		r.mismatches << m;
	}
	return r;
}
