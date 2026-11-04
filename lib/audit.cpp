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
#include "XcaWarningCore.h"

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
const char AuditLog::actionDelete[] = "object.delete";
const char AuditLog::actionInit[] = "audit.init";
const char AuditLog::actionCheckpoint[] = "audit.checkpoint";
const char AuditLog::actionKeyCreate[] = "audit.key_create";
const char AuditLog::actionSettingsMigrate[] = "settings.migrate";
const char AuditLog::actionSettingsUpdate[] = "settings.update";
const char AuditLog::actionRowsSkipped[] = "database.rows_skipped";
const int AuditLog::defaultCheckpointInterval = 100;
const int AuditLog::maxCheckpointInterval = 1000;

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
		"authority_updated", "ca_id", "confirmed", "count",
		"crl_number", "curve", "db_unlock_verified", "dependents",
		"der_size", "encrypted", "file", "fingerprint", "format",
		"hash_algo", "invalidity_date", "issuer", "item_id",
		/* what secret.export wrote, e.g. openvpn_tls_auth, never
		 * the secret (BTD-90) */
		"kind",
		"key_size", "key_type", "legacy", "ml_dsa_encoding", "name",
		"next_update",
		"not_after",
		"not_before", "old_name", "old_pkcs12_algorithm", "on_token",
		"outcome",
		"pkcs12_algorithm",
		/* the MAC and iteration count of a PKCS#12 (BTD-175) */
		"pkcs12_iterations", "pkcs12_mac",
		"question",
		"reason", "reason_bit", "requested_not_after",
		"revocation_date", "revocations", "serial",
		/* type:id of database rows left out on open (BTD-209) */
		"skipped_items",
		/* the effective algorithm of a signature (BTD-164) */
		"signature_algorithm", "subject",
		"template", "this_update", "validity_capped",
		/* key usage bits the user removed in the New Certificate
		 * dialog because the key cannot use them (BTD-195) */
		"ku_removed",
		/* accepted with a note: issuer without key usage (BTD-55),
		 * SHA-1 CSR (BTD-65) */
		"warning",
		/* device CSRs (BTD-65) */
		"csr_signature_algorithm",
		/* certificate profiles (BTD-54), the profile store and the
		 * name policies (BTD-167) */
		"profile", "profile_version", "policies", "policy_result",
		"version", "dropped_extensions", "profile_warnings",
		/* the merge decision per extension, e.g. "ku=union+csr"
		 * (mr-processor review of xca#47) */
		"merge",
		/* a --plan run of the bxc-pki command line (BTD-41): the
		 * command and the planned objects as "type:name,..." */
		"command", "planned",
		/* CRL lifecycle and trust-list export (BTD-42): the
		 * CRL settings of a CA (ca.crl_settings), why a CRL was
		 * issued (crl.generate), the budgets of a trust list
		 * (trustlist.export) */
		"crl_validity", "reissue_fraction", "size_budget",
		"trigger", "trust_list_budget",
		/* renewal and re-key (BTD-56) */
		"predecessor_id", "predecessor_serial", "rekey",
		"serial_kept",
		/* bxc-pki bootstrap (BTD-166), action bootstrap.apply: the
		 * SHA-256 of the file, its schema id and the number of
		 * objects created, kept, updated and elements skipped */
		"file_sha256", "schema", "created", "kept", "updated",
		"skipped",
		/* settings.update (BTD-224): the setting, and its values
		 * only for the options of the Options dialog, otherwise
		 * redacted */
		"setting", "old_value", "new_value", "redacted",
	};
	/* Signed checkpoints and the audit keys (BTD-37) */
	static const QStringList withCheckpoints = list + QStringList {
		"checkpoint_hash", "checkpoint_seq", "checkpoint_time",
		"key_id", "next_key_id", "public_key", "signature",
		/* BTD-110: an unsigned log adopted by the first key */
		"adopted_entries",
		/* BTD-133: the interval a checkpoint was written with */
		"checkpoint_interval",
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

AuditParams &AuditParams::warn(const QString &code)
{
	QStringList w = values.value("warning").toString()
				.split(',', Qt::SkipEmptyParts);
	if (!w.contains(code))
		w << code;
	return store("warning", w.join(","));
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
	m["adopted_entries"] = adoptedEntries;
	m["pinned_keys"] = pins.keys;
	m["pinned_min_checkpoint"] = pins.minCheckpoint > 0 ?
				QVariant(pins.minCheckpoint) : QVariant();
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

/* seq and hash of the newest entry; seq 0 for an empty log */
static AuditEntry headEntry()
{
	XSqlQuery q;
	AuditEntry e;

	SQL_PREPARE(q, "SELECT seq, hash FROM audit_log "
			"ORDER BY seq DESC LIMIT 1");
	q.exec();
	throwOnError(q);
	if (q.next()) {
		e.seq = q.value(0).toLongLong();
		e.hash = q.value(1).toString().toLatin1();
	}
	return e;
}

/* The entry that follows prev (headEntry() or an entry made before),
 * not written yet */
static AuditEntry makeEntry(const ServiceContext &ctx, const AuditEntry &prev,
		const QString &action, const QString &objectType,
		const QString &objectId, const QVariantMap &params,
		const QString &result = "success",
		const QString &errorCode = QString())
{
	AuditEntry e;

	e.seq = prev.seq + 1;
	e.prevHash = prev.seq ? prev.hash : AuditLog::genesisHash;
	e.time = AuditLog::rfc3339(QDateTime::currentDateTimeUtc());
	e.actor = ctx.actor();
	e.channel = ctx.channelName();
	e.action = action;
	e.objectType = objectType;
	e.objectId = objectId;
	e.params = params;
	e.result = result;
	e.errorCode = errorCode;
	e.hash = e.computeHash();
	return e;
}

static void writeEntry(const AuditEntry &e)
{
	XSqlQuery q;

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
}

/* append() without the checkpoint check */
static AuditEntry insertEntry(const ServiceContext &ctx,
		const QString &action, const QString &objectType,
		const QString &objectId, const AuditParams &params,
		const QString &result = "success",
		const QString &errorCode = QString())
{
	static const QStringList results { "success", "failure", "denied" };

	if (action.isEmpty())
		throw errorEx("Audit entry without action");
	if (!results.contains(result))
		throw errorEx(QString("Invalid audit result '%1'").arg(result));

	Transaction;
	TransThrow();
	AuditEntry e = makeEntry(ctx, headEntry(), action, objectType,
			objectId, params.getValues(), result, errorCode);
	writeEntry(e);
	if (!TransCommit())
		throw errorEx(QObject::tr("Database error: %1")
			.arg("the audit entry was not committed"));
	return e;
}

static AuditEntry writeCheckpoint(const ServiceContext &ctx, bool rotate,
				bool ask, bool adopt = false,
				bool *writing = nullptr);

/* seq of the newest checkpoint entry, 0 if there is none */
/* The longest unsigned tail a writer with the database password leaves
 * after a checkpoint that signed interval (BTD-133): that interval, but
 * the setting is not signed. Without a signed one (no checkpoint yet, or
 * one written before BTD-133, signedInterval 0) the setting is believed
 * only up to the default, so that raising it cannot hide anything. */
static int tailInterval(int signedInterval)
{
	if (signedInterval > 0)
		return qMin(signedInterval, AuditLog::maxCheckpointInterval);
	return qMin(AuditLog::checkpointInterval(),
			AuditLog::defaultCheckpointInterval);
}

static int signedInterval(const QVariantMap &checkpointParams)
{
	return checkpointParams.value("checkpoint_interval").toInt();
}

/* The newest checkpoint: its seq, 0 for none, and the interval it
 * signed, 0 for none */
static qint64 lastCheckpointSeq(int *interval = nullptr)
{
	XSqlQuery q;

	SQL_PREPARE(q, "SELECT seq, params FROM audit_log WHERE action=? "
			"ORDER BY seq DESC LIMIT 1");
	q.bindValue(0, QString(AuditLog::actionCheckpoint));
	q.exec();
	throwOnError(q);
	if (!q.next()) {
		if (interval)
			*interval = 0;
		return 0;
	}
	if (interval)
		*interval = signedInterval(QJsonDocument::fromJson(
			q.value(1).toString().toUtf8()).toVariant().toMap());
	return q.value(0).toLongLong();
}

void AuditLog::setCheckpointInterval(const ServiceContext &ctx,
				int interval)
{
	if (interval < 1 || interval > maxCheckpointInterval)
		throw serviceError("invalid_value", QObject::tr(
			"The audit checkpoint interval must be between 1 and %1, "
			"not %2").arg(maxCheckpointInterval).arg(interval));
	/* Writes only after a verified unlock (BTD-137) */
	if (!ServiceContext::processPasswordVerified)
		throw serviceError("missing_password", QObject::tr(
			"Changing the audit checkpoint interval needs the "
			"database password (--password)"));
	Settings.update(ctx, { { "audit_checkpoint_interval",
				QString::number(interval) } });
}

int AuditLog::checkpointInterval()
{
	/* The setting is not signed: clamped, so that raising it cannot
	 * switch off the tail rule of verify() (BTD-110) */
	int n = Settings["audit_checkpoint_interval"];
	return n > 0 ? qMin(n, maxCheckpointInterval) :
			defaultCheckpointInterval;
}

static QSet<QString> checkpointNotices;

/* The last checkpoint seq over which an automatic checkpoint failed for a
 * reason the next entry cannot change (a broken chain, a key that is
 * missing or does not decrypt), -1 for none. Until the head or the key
 * state changes, append() does not try again: every try scans the whole
 * unsigned tail, an import would be O(n^2) (BTD-144). */
static qint64 failedCheckpointHead = -1;

void AuditLog::retryFailedCheckpoint()
{
	failedCheckpointHead = -1;
}

void AuditLog::resetCheckpointNotices()
{
	checkpointNotices.clear();
	retryFailedCheckpoint();
}

/* The next step for a skipped automatic checkpoint (BTD-148) */
static QString checkpointRemedy(const QString &code)
{
	if (code == "audit_key_unavailable")
		return QObject::tr("Open the database with its password; "
			"the next entry is signed then.");
	if (code == "audit_password_rejected")
		return QObject::tr("Check the password source.");
	if (code == "audit_checkpoint_missing")
		return QObject::tr("Check the log with --audit-verify, then "
			"sign it with --audit-adopt.");
	if (code == "audit_key_missing")
		return QObject::tr("Run --audit-verify and restore the audit "
			"key from a backup of the database.");
	return QObject::tr("Run --audit-verify.");
}

/* A skipped automatic checkpoint: the log line with the code (BTD-144)
 * and, once per code and open database, a notice to the user that does
 * not interrupt the work (BTD-148) */
static void reportSkippedCheckpoint(qint64 seq, const errorEx &err)
{
	const serviceError *se = dynamic_cast<const serviceError *>(&err);
	QString code = se ? se->code : QString("audit_checkpoint_failed");
	qWarning() << "No audit checkpoint after entry" << seq << code
		<< err.getString();
	if (checkpointNotices.contains(code))
		return;
	checkpointNotices << code;
	xcaWarning::notice(QObject::tr("Audit checkpoint skipped (%1): %2 %3")
		.arg(code, checkpointRemedy(code), err.getString()));
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
	/* Inside a caller's transaction a failure may be rolled back with
	 * it (BTD-41, AuditFailureCapture) */
	bool inTransaction = DbTransaction::active();
	AuditEntry e = insertEntry(ctx, action, objectType, objectId,
				p, result, errorCode);
	if (inTransaction && result != "success")
		AuditFailureCapture::record(ctx, action, objectType, objectId,
				params, result, errorCode);
	/* A raised setting takes effect once a checkpoint signed it, a
	 * lowered one at once (BTD-133); a head whose checkpoint failed is
	 * not tried again on every entry (BTD-144) */
	int signedN = 0;
	qint64 head = lastCheckpointSeq(&signedN);
	if (e.seq - head < qMin(checkpointInterval(), tailInterval(signedN)) ||
	    head == failedCheckpointHead)
		return e;
	bool writing = false;
	/* insertEntry() has committed or joined the caller's transaction */
	bool callerTransaction = DbTransaction::active();
	try {
		writeCheckpoint(ctx, false, false, false, &writing);
	} catch (errorEx &err) {
		/* Failed before its first write: the entry and the caller's
		 * transaction stay, the next append() tries again. A failure
		 * while writing rolled the caller's transaction back with
		 * the checkpoint, so it must reach the caller (BTD-111).
		 * Without a caller transaction (a failure entry after the
		 * rollback) the entry is committed: the caller keeps its own
		 * error and the next append() tries again (BTD-143) */
		if (writing && callerTransaction)
			throw;
		/* Without the password (or a wrong source) the next entry
		 * may have it: no scan was made, try again */
		const serviceError *se = dynamic_cast<serviceError *>(&err);
		if (!writing && !(se && (se->code == "audit_key_unavailable" ||
				se->code == "audit_password_rejected")))
			failedCheckpointHead = head;
		reportSkippedCheckpoint(e.seq, err);
	}
	return e;
}

bool AuditLog::appendFailure(const ServiceContext &ctx,
		const QString &action, const QString &objectType,
		const QString &objectId, const AuditParams &params,
		const QString &errorCode, const QString &result)
{
	try {
		append(ctx, action, objectType, objectId, params, result,
			errorCode);
		return true;
	} catch (errorEx &err) {
		qCritical().noquote() << "Audit entry lost:" << action << result
			<< errorCode << "-" << err.getString();
	} catch (...) {
		qCritical().noquote() << "Audit entry lost:" << action << result
			<< errorCode;
	}
	return false;
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

QVariantMap AuditLog::lastParams(const QString &action)
{
	XSqlQuery q;
	QVariantMap params;

	SQL_PREPARE(q, "SELECT params FROM audit_log WHERE action=? "
			"ORDER BY seq DESC LIMIT 1");
	q.bindValue(0, action);
	q.exec();
	throwOnError(q);
	if (q.next())
		canonicalParams(q.value(0).toString(), &params);
	return params;
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

/* seq of the audit.init entry that closes the revocation baseline at the
 * start of the chain (written without a checkpoint, before the database
 * was unlocked), 0 if there is none or its count is not the number of
 * baseline rows before it */
static qint64 baselineEnd(const QList<AuditEntry> &list)
{
	qint64 rows = 0;

	for (const AuditEntry &e : list) {
		if (e.action == AuditLog::actionInit)
			return e.params.value("count").toLongLong() == rows ?
				e.seq : 0;
		if (e.action != AuditLog::actionRevocationBaseline)
			break;
		rows++;
	}
	return 0;
}

/* The entries of list after the anchored ones that count against the
 * unsigned tail: a writer with the database password never leaves more
 * than tailInterval() + 1. The one rule of verify() and of the first
 * checkpoint (BTD-110, BTD-133). */
static qint64 unanchoredTail(const QList<AuditEntry> &list, qint64 anchored)
{
	return list.size() - qMax(anchored, baselineEnd(list));
}

static bool tailTooLong(qint64 tail, int signedInterval)
{
	return tail > tailInterval(signedInterval) + 1;
}

/* The announcement of a generated key after prev, not written yet;
 * adopted: the number of unsigned entries the first key takes over
 * explicitly, 0 for none */
static AuditEntry makeAnnouncement(const ServiceContext &ctx,
		const AuditEntry &prev, const AuditKey::Generated &key,
		qint64 adopted = 0)
{
	AuditParams p;
	p.set("key_id", key.id).set("key_type", AuditKey::typeEd25519)
	 .set("public_key", QString::fromLatin1(key.publicPem));
	if (adopted)
		p.set("adopted_entries", adopted);
	return makeEntry(ctx, prev, AuditLog::actionKeyCreate, "audit_key",
			key.id, p.getValues());
}

/* The checkpoint after prev that signs prev with the stored key, or with
 * fresh if given; next names the key that signs the following
 * checkpoints. Not written yet. */
static AuditEntry makeCheckpoint(const ServiceContext &ctx,
		const AuditEntry &prev, const QString &key,
		const AuditKey::Generated *fresh, const QString &next,
		const Passwd &pass)
{
	AuditParams p;

	p.set("checkpoint_seq", prev.seq);
	p.set("checkpoint_hash", QString::fromLatin1(prev.hash));
	p.set("checkpoint_time", QDateTime::currentDateTimeUtc());
	p.set("key_id", key);
	if (!next.isEmpty())
		p.set("next_key_id", next);
	/* signed: verify() takes the tail limit from here, not from the
	 * setting (BTD-133) */
	p.set("checkpoint_interval", AuditLog::checkpointInterval());
	QByteArray payload = AuditLog::checkpointPayload(p.getValues());
	QByteArray sig = fresh ? AuditKey::sign(*fresh, payload, pass) :
				AuditKey::sign(key, payload, pass);
	p.set("signature", QString::fromLatin1(sig.toBase64()));
	return makeEntry(ctx, prev, AuditLog::actionCheckpoint, "audit_key",
			key, p.getValues());
}

/* True once the chain announced a key or audit_keys holds one: from then
 * on a missing current key is an error, not a first use (BTD-110) */
static bool keyAnnounced()
{
	XSqlQuery q;

	SQL_PREPARE(q, "SELECT 1 FROM audit_log WHERE action=? "
			"UNION ALL SELECT 1 FROM audit_keys LIMIT 1");
	q.bindValue(0, QString(AuditLog::actionKeyCreate));
	q.exec();
	throwOnError(q);
	return q.next();
}

/* Everything that can fail short of a database error happens before the
 * first write: the password, the key generation, the signature. Only
 * then *writing is set and the entries are written; a failure from there
 * on rolls back the caller's transaction too (BTD-111). ask: the password
 * may be asked for (explicit checkpoints, not automatic ones). adopt: a
 * first key may sign a log with too long an unsigned tail (BTD-110). */
static AuditEntry writeCheckpoint(const ServiceContext &ctx, bool rotate,
				bool ask, bool adopt, bool *writing)
{
	if (!headEntry().seq)
		throw serviceError("empty_audit_log",
			QObject::tr("The audit log has no entry to sign"));
	/* the password first: without it the export reads only */
	Passwd pass = AuditKey::password(ask);
	qint64 last = lastCheckpointSeq();
	checkUnsignedTail(last ? last : 1);
	QString key = AuditKey::current();
	if (key.isEmpty() && keyAnnounced())
		throw serviceError("audit_key_missing", QObject::tr(
			"The audit key that signs the checkpoints is missing "
			"or retired; run --audit-verify"));
	/* First use over a log longer than any writer with the password
	 * leaves unsigned: checkpoints and keys may have been deleted. Only
	 * an explicit adoption signs it, and records that it did. */
	qint64 adopted = 0;
	if (key.isEmpty()) {
		qint64 tail = unanchoredTail(AuditLog::entries(), 0);
		/* no key: no checkpoint signed an interval */
		if (tailTooLong(tail, 0) && !adopt)
			throw serviceError("audit_checkpoint_missing",
				QObject::tr("%1 audit entries were never signed by a "
				"checkpoint, more than the checkpoint interval allows; "
				"checkpoints may have been deleted. Check the log, then "
				"sign it explicitly with --audit-adopt").arg(tail));
		if (tailTooLong(tail, 0))
			adopted = tail;
	}

	/* first use: a new key announced and signing itself; rotation: a
	 * new key announced and named by a checkpoint of the old one */
	bool first = key.isEmpty();
	AuditKey::Generated fresh;
	AuditEntry prev = headEntry(), announcement;
	if (first || rotate) {
		fresh = AuditKey::generate(pass);
		announcement = makeAnnouncement(ctx, prev, fresh,
						first ? adopted : 0);
		prev = announcement;
	}
	AuditEntry e = first ?
		makeCheckpoint(ctx, prev, fresh.id, &fresh, QString(), pass) :
		makeCheckpoint(ctx, prev, key, nullptr,
				rotate ? fresh.id : QString(), pass);

	if (writing)
		*writing = true;
	Transaction;
	TransThrow();
	if (announcement.seq) {
		AuditKey::store(fresh);
		writeEntry(announcement);
	}
	writeEntry(e);
	if (rotate && !first)
		AuditKey::retire(key);
	if (!TransCommit())
		throw errorEx(QObject::tr("Database error: %1")
			.arg("the audit checkpoint was not committed"));
	return e;
}

/* An explicit checkpoint always tries; the automatic ones try again
 * afterwards (BTD-144) */
AuditEntry AuditLog::checkpoint(const ServiceContext &ctx)
{
	retryFailedCheckpoint();
	return writeCheckpoint(ctx, false, true);
}

AuditEntry AuditLog::rotateKey(const ServiceContext &ctx)
{
	retryFailedCheckpoint();
	return writeCheckpoint(ctx, true, true);
}

AuditEntry AuditLog::adoptUnanchored(const ServiceContext &ctx)
{
	retryFailedCheckpoint();
	return writeCheckpoint(ctx, false, true, true);
}

QByteArray AuditLog::exportJsonLines(qint64 *unsignedEntries,
				AuditSkippedCheckpoint *skipped)
{
	return exportJsonLines(ServiceContext::localUser(
			ServiceContext::processChannel), unsignedEntries,
			skipped);
}

QByteArray AuditLog::exportJsonLines(const ServiceContext &ctx,
				qint64 *unsignedEntries,
				AuditSkippedCheckpoint *skipped)
{
	QByteArray out;
	QList<AuditEntry> list = entries();
	qint64 lastCheckpoint = 0;

	if (!list.isEmpty() && list.last().action != actionCheckpoint) {
		try {
			checkpoint(ctx);
			list = entries();
		} catch (serviceError &err) {
			/* Read only, without a new checkpoint, and nothing
			 * written: without a password source (BTD-70), and
			 * for a log no checkpoint may sign, which an auditor
			 * needs exported most (BTD-112). A wrong password or
			 * a database error still fails. */
			static const QStringList readOnly {
				"audit_key_unavailable", "audit_chain_broken",
				"audit_key_missing", "audit_checkpoint_missing",
			};
			if (!readOnly.contains(err.code))
				throw;
			if (skipped) {
				skipped->code = err.code;
				skipped->reason = err.getString();
			}
		}
	}
	/* Counted like unanchored_entries of verify(): the entries after
	 * the checkpoint_seq of the last checkpoint, the checkpoint row
	 * itself included (BTD-110, BTD-134) */
	for (const AuditEntry &e : list)
		if (e.action == actionCheckpoint)
			lastCheckpoint = e.params.value("checkpoint_seq")
						.toLongLong();
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
	/* No checkpoint here: the database may be open without its password.
	 * Whether it was checked is recorded as by append() (BTD-135). */
	bool verified = ctx.passwordVerified();
	for (AuditParams &p : rows) {
		p.set("db_unlock_verified", verified);
		insertEntry(ctx, actionRevocationBaseline, "cert",
			p.getValues().value("serial").toString(), p);
	}
	insertEntry(ctx, actionInit, "database", QString(),
		AuditParams().set("count", (qint64)rows.size())
			.set("db_unlock_verified", verified));
	if (!TransCommit())
		throw errorEx(QObject::tr("Database error: %1")
			.arg("the audit baseline was not committed"));
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
 * order: each one signed by the current key over the hash of the entry
 * just before it. An entry is anchored up to the checkpoint_seq of the
 * last valid checkpoint; the checkpoint row itself only by the next one.
 * Sets the checkpoint fields of r and, at the first invalid checkpoint,
 * firstBrokenSeq to the first entry that is not anchored. A chain that
 * passes still fails with checkpoint_missing when audit_keys holds a key
 * the chain never announced, or when more entries are unanchored than a
 * writer with the database password leaves (interval + 1). */
static void verifyCheckpoints(const QList<AuditEntry> &list,
				AuditVerifyResult &r)
{
	QMap<QString, QByteArray> announced;	// key id -> public PEM
	QString signer;
	qint64 anchored = 0, lastValid = 0;
	int interval = 0;	// signed by the last valid checkpoint
	qint64 baseline = baselineEnd(list);

	for (const AuditEntry &e : list) {
		QString reason;
		const QVariantMap &p = e.params;

		if (e.action == AuditLog::actionKeyCreate) {
			QString id = p.value("key_id").toString();
			QByteArray pem = p.value("public_key").toString().toLatin1();
			/* only the first key adopts, exactly the unsigned
			 * entries before it */
			bool adopts = p.contains("adopted_entries");
			if (id.isEmpty() || AuditKey::keyId(pem) != id ||
			    (adopts && (!signer.isEmpty() ||
			     p.value("adopted_entries").toLongLong() !=
					e.seq - 1 - baseline))) {
				reason = "checkpoint_key";
			} else {
				if (adopts)
					r.adoptedEntries = p.value(
						"adopted_entries").toLongLong();
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
			else if (n < 1 || n != e.seq - 1 || list[n - 1].hash != hash)
				reason = "checkpoint_hash";
			else if (!next.isEmpty() && !announced.contains(next))
				reason = "checkpoint_key";
			if (reason.isEmpty()) {
				anchored = n;
				lastValid = e.seq;
				interval = signedInterval(p);
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
	r.lastCheckpointSeq = lastValid;
	r.unanchoredEntries = r.entries - anchored;
	if (!r.reason.isEmpty())
		return;

	XSqlQuery q;
	bool unannounced = false;
	SQL_PREPARE(q, "SELECT key_id FROM audit_keys");
	q.exec();
	throwOnError(q);
	while (q.next())
		unannounced |= !announced.contains(q.value(0).toString());
	if (unannounced ||
	    tailTooLong(unanchoredTail(list, anchored), interval)) {
		r.firstBrokenSeq = anchored + 1;
		r.reason = "checkpoint_missing";
	}
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

AuditVerifyResult AuditLog::verify(const AuditVerifyPins &pins)
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
		} else if (e.action == actionDelete &&
			   e.objectType == "certificate") {
			/* pki_x509::deleteSqlData() removes the revocation
			 * rows of the deleted certificate as a CA (BTD-35) */
			qint64 deleted = e.objectId.toLongLong();
			for (auto i = state.begin(); i != state.end(); ++i) {
				if (i.key().first == deleted && i->present) {
					*i = revocationState();
					i->seq = e.seq;
				}
			}
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
	/* The trust anchor from outside the database (BTD-101): the first
	 * key of the log must be a pinned one (the chain check above makes
	 * every later key lead from it), and the log must still have the
	 * newest checkpoint an earlier export saw. A log rewritten from
	 * scratch with a new key, or cut off with its newest checkpoints,
	 * passes the checks above on its own. */
	r.pins = pins;
	if (!pins.keys.isEmpty() && (r.auditKeys.isEmpty() ||
			!pins.keys.contains(r.auditKeys.first()))) {
		r.pinsOk = false;
		if (r.reason.isEmpty())
			r.reason = "untrusted_key";
	} else if (pins.minCheckpoint > 0 &&
			r.lastCheckpointSeq < pins.minCheckpoint) {
		r.pinsOk = false;
		if (r.reason.isEmpty())
			r.reason = "checkpoint_truncated";
	}
	return r;
}

AuditFailureCapture *AuditFailureCapture::current;

AuditFailureCapture::AuditFailureCapture()
	: outer(current)
{
	current = this;
}

AuditFailureCapture::~AuditFailureCapture()
{
	current = outer;
}

void AuditFailureCapture::record(const ServiceContext &ctx,
		const QString &action, const QString &objectType,
		const QString &objectId, const AuditParams &params,
		const QString &result, const QString &errorCode)
{
	if (current)
		current->captured << entry{ ctx, action, objectType, objectId,
					params, result, errorCode };
}

QList<AuditEntry> AuditFailureCapture::replay()
{
	QList<entry> list;
	QList<AuditEntry> written;

	list.swap(captured);
	for (const entry &e : list)
		written << AuditLog::append(e.ctx, e.action, e.objectType,
				e.objectId, e.params, e.result, e.errorCode);
	return written;
}
