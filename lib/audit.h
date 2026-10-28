/* vi: set sw=4 ts=4:
 *
 * Tamper-evident audit log of the bxc-pki fork (BTD-29, PLAN.md section 6).
 *
 * Entries live in the table audit_log of the XCA database. Each entry is
 * chained to its predecessor:
 *   hash = SHA-256(prev_hash || canonical JSON of the entry)
 * prev_hash is the raw 32 byte hash of the previous entry, the first entry
 * uses AuditLog::genesisHash (32 zero bytes). The canonical JSON follows
 * RFC 8785 (JCS) for the value types an entry may hold: objects, arrays,
 * strings, integers in the IEEE 754 safe range, booleans and null.
 *
 * lib/ offers no function to change or delete an entry.
 *
 * Limit until BTD-37: the chain has no key. Anyone who can write the
 * database can rewrite entry k and recompute the hashes of k and every
 * later entry, cut off the newest entries, or delete the whole log, and
 * verify() still passes. Any rewrite of a suffix of the chain is
 * undetectable until the signed checkpoints of BTD-37 exist; append()
 * then simply continues from the rewritten end.
 *
 * Caller contract (service functions of BTD-31..35):
 *  - Every service function receives a ServiceContext and appends exactly
 *    one entry per operation, with result "success", "failure" or
 *    "denied".
 *  - append() opens a nested transaction. Called inside the caller's
 *    transaction, the entry is committed or rolled back together with
 *    the object change (BTD-50). A "failure" or "denied" entry must
 *    therefore be appended after the caller's transaction was rolled
 *    back, never inside it, or it disappears with the rollback.
 *  - append() throws errorEx on any database error and does not retry.
 *    A concurrent writer that read the same predecessor gets a duplicate
 *    sequence number (or SQLITE_BUSY) and fails; the caller decides
 *    whether the whole operation fails or is retried.
 *
 * Schema version: the fork counts its own migrations under the settings
 * key "bxc_schema" (see lib/database_schema.cpp) and leaves upstream's
 * "schema" counter alone, so that a future upstream schema 9 does not
 * collide with a fork migration.
 */

#ifndef __AUDIT_H
#define __AUDIT_H

#include <QByteArray>
#include <QDateTime>
#include <QList>
#include <QString>
#include <QStringList>
#include <QVariant>
#include <QVariantMap>

#include "exception.h"
#include "sql.h"

class Passwd;

/* Who triggered a service function and through which channel.
 * Every service function receives one and hands it to AuditLog::append() */
class ServiceContext
{
  public:
	enum channel { gui, cli, rest, est, cmp };

  private:
	enum channel chan;
	QString actorId;

  public:
	/* actor: "os:<login>", "apikey:<key id>" or "cert:<SHA-256 fingerprint>" */
	ServiceContext(enum channel c, const QString &actor);
	/* The operating system user running this process */
	static ServiceContext localUser(enum channel c);
	/* Channel of this process for entries without a caller, e.g. the
	 * baseline written on a database upgrade. read_cmdline() sets cli. */
	static enum channel processChannel;
	static QString osUser();
	static QString channelName(enum channel c);

	enum channel getChannel() const
	{
		return chan;
	}
	QString channelName() const
	{
		return channelName(chan);
	}
	QString actor() const
	{
		return actorId;
	}
};

/* Parameter summary of an audit entry (PLAN.md 6.4).
 * Only keys of the allow-list are stored; anything else is dropped.
 * No allow-listed key may carry a password, PIN, private key or
 * challenge password, and binary values are not accepted at all. */
class AuditParams
{
	QVariantMap values{};
	QStringList droppedKeys{};

	AuditParams &store(const QString &key, const QVariant &v);

  public:
	static const QStringList &allowList();
	static bool allowed(const QString &key);

	AuditParams &set(const QString &key, const QString &v);
	AuditParams &set(const QString &key, const char *v);
	AuditParams &set(const QString &key, qint64 v);
	AuditParams &set(const QString &key, int v);
	AuditParams &set(const QString &key, bool v);
	AuditParams &set(const QString &key, const QDateTime &v);
	/* Secrets and raw bytes never reach the log */
	AuditParams &set(const QString &key, const Passwd &v) = delete;
	AuditParams &set(const QString &key, const QByteArray &v) = delete;

	/* Takes the allow-listed keys of a map with string, integer, boolean
	 * or date values and drops the rest */
	static AuditParams fromMap(const QVariantMap &map);

	/* The state verify() needs to recompute a revocation row:
	 * revocations(caId, serial, date, invaldate, reasonBit) */
	static AuditParams revocation(qint64 caId, const QString &serial,
			int reasonBit, const QDateTime &date,
			const QDateTime &invalDate);
	static AuditParams unrevocation(qint64 caId, const QString &serial);
	/* A new CRL of the CA assigns crlNumber to its pending revocations */
	static AuditParams crl(qint64 caId, qint64 crlNumber);

	QVariantMap getValues() const
	{
		return values;
	}
	QStringList dropped() const
	{
		return droppedKeys;
	}
};

class AuditEntry
{
  public:
	qint64 seq{};
	QString time{};          // UTC, RFC 3339
	QString actor{};
	QString channel{};
	QString action{};
	QString objectType{};
	QString objectId{};
	QVariantMap params{};
	QString result{};        // success, failure, denied
	QString errorCode{};     // empty on success
	QByteArray prevHash{};   // lowercase hex
	QByteArray hash{};       // lowercase hex

	/* Field names of PLAN.md 6.2 as written to the export */
	QVariantMap toMap(bool withHashes) const;
	/* RFC 8785 JSON of all fields except prev_hash and hash */
	QByteArray canonical() const;
	QByteArray computeHash() const;
};

/* A revocation row that disagrees with the state the chain recorded */
class AuditStateMismatch
{
  public:
	qint64 caId{};
	QString serial{};
	QString field{};         // row, date, invaldate, reasonBit, crlNo
	QString expected{};
	QString actual{};
	qint64 seq{};            // last audit entry that set the expected state,
	                         // 0 for a row no audit entry knows

	QVariantMap toMap() const;
};

class AuditVerifyResult
{
  public:
	qint64 entries{};
	qint64 verifiedEntries{};
	qint64 firstBrokenSeq{};  // 0: chain intact
	QString reason{};        // missing, sequence, prev_hash, params, hash
	QList<AuditStateMismatch> mismatches{};
	qint64 unauditedRevocations{};   // also listed in mismatches

	bool chainOk() const
	{
		return firstBrokenSeq == 0;
	}
	bool ok() const
	{
		return chainOk() && mismatches.isEmpty();
	}
	QVariantMap toMap() const;
	QByteArray toJson() const;
};

/* Append-only access to the audit_log table of the open database */
class AuditLog
{
  public:
	static const QByteArray genesisHash;  // lowercase hex, 32 zero bytes

	/* Action names whose parameters verify() checks against revocations */
	static const char actionRevoke[];
	static const char actionUnrevoke[];
	static const char actionCrlGenerate[];
	/* Written once when an existing database gets the audit log:
	 * one revocation.baseline entry per revocation row found, then
	 * audit.init with the count */
	static const char actionRevocationBaseline[];
	static const char actionInit[];

	/* Appends one entry in its own (possibly nested) transaction.
	 * The sequence number is the primary key, so two writers that read
	 * the same predecessor cannot fork the chain: the second insert fails.
	 * Throws errorEx on a database error. */
	static AuditEntry append(const ServiceContext &ctx,
			const QString &action, const QString &objectType,
			const QString &objectId,
			const AuditParams &params = AuditParams(),
			const QString &result = "success",
			const QString &errorCode = QString());

	/* Records the revocation rows of a database that existed before the
	 * audit log, so that verify() can tell them from rows added later
	 * without an entry. Called by database_model::initSqlDB(). */
	static void writeBaseline();

	static QList<AuditEntry> entries();
	/* Checks the chain from the first entry, then replays the revocation
	 * and CRL entries of the intact part and compares the result with the
	 * revocations table; a row no entry knows is a mismatch. Never throws
	 * for a tampered entry: an entry without a canonical form is reported
	 * as broken. A rewritten suffix passes (see the limit above). */
	static AuditVerifyResult verify();
	/* One canonical JSON object per line, including prev_hash and hash.
	 * Throws errorEx for an entry without a canonical form. */
	static QByteArray exportJsonLines();

	/* RFC 8785 serialisation; throws errorEx on unsupported values */
	static QByteArray canonicalJson(const QVariant &v);
	static QByteArray chainHash(const QByteArray &prevHashHex,
			const QByteArray &canonical);
	static QString rfc3339(const QDateTime &t);
};

/* The caller contract above for one service operation (BTD-33):
 * work() runs in one transaction and appends its success entries before
 * the commit. When it throws, the transaction is rolled back, one entry
 * "failure" with the serviceError code (internal_error for any other
 * exception) is appended and the exception is rethrown. params is read
 * only then, so work() may complete it. */
template <class Work>
void auditedTransaction(const ServiceContext &ctx, const QString &action,
		const QString &objectType, const QString &objectId,
		const AuditParams &params, Work work)
{
	try {
		Transaction;
		TransThrow();
		work();
		if (!TransCommit())
			throw serviceError("database_error", QObject::tr(
				"Failed to commit the database transaction"));
	} catch (serviceError &err) {
		AuditLog::append(ctx, action, objectType, objectId, params,
				"failure", err.code);
		throw;
	} catch (...) {
		AuditLog::append(ctx, action, objectType, objectId, params,
				"failure", "internal_error");
		throw;
	}
}

#endif
