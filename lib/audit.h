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
 * Signed checkpoints (BTD-37): after every N entries (settings key
 * "audit_checkpoint_interval", default 100) and before each export,
 * append() adds an entry "audit.checkpoint" whose params hold
 *   checkpoint_seq, checkpoint_hash, checkpoint_time, key_id,
 *   [next_key_id,] signature
 * The signature (Base64) covers checkpointPayload(), the canonical JSON
 * of these params without "signature", and is made with the audit key
 * (lib/audit_key.h). checkpoint_seq/checkpoint_hash name the entry just
 * before the checkpoint. A key is announced by an entry "audit.key_create"
 * (key_id, key_type, public_key as PEM); the first announced key signs the
 * first checkpoint, a later one only after a checkpoint of the old key
 * named it next_key_id (rotation). Each export line therefore carries
 * everything needed to check a checkpoint with the OpenSSL CLI
 * (doc/audit-checkpoints.md).
 *
 * verify() checks the checkpoints of the intact chain in order. A chain
 * rewritten with recomputed hashes no longer matches the hash signed by
 * the next checkpoint, so verify() reports it broken after the last
 * valid checkpoint.
 *
 * Checkpoint structure (BTD-110): checkpoint_seq must be the entry just
 * before the checkpoint. The checkpoint row's own fields outside params
 * (created, actor, channel, object_id) are not signed, so an entry counts
 * as anchored only up to the checkpoint_seq of the last valid checkpoint;
 * the checkpoint row itself is anchored by the next checkpoint (decision
 * 2026-10-29: anchor at checkpoint_seq instead of signing the row's
 * metadata, which would change the signed payload and the export). Deleted
 * checkpoints are reported as checkpoint_missing: a key in audit_keys that
 * no audit.key_create of the chain announces, or more than interval + 1
 * unanchored entries (the revocation baseline at the start excepted, when
 * audit.init counts exactly its rows). The interval is the setting
 * audit_checkpoint_interval clamped to maxCheckpointInterval, because the
 * setting is not signed. Once a key was announced, a missing current key
 * fails the checkpoint with audit_key_missing instead of announcing a new
 * key. The first key is not announced over a log with too long an
 * unsigned tail either (audit_checkpoint_missing), so that the next
 * checkpoint does not sign a history whose checkpoints and keys were
 * deleted; adoptUnanchored() signs such a log on explicit request and
 * records the number of adopted entries as adopted_entries in the
 * announcement, which verify() reports.
 *
 * Remaining limits: entries after the last checkpoint (at most N + 1,
 * fewer after an export) are protected by the hash chain only; cutting
 * off the newest entries including their checkpoints (unless that removes
 * a key announcement) still passes verify() (unanchored_entries shows the
 * unsigned tail), and so does deleting the whole log or its checkpoints
 * together with the audit_keys rows when the rest is at most interval + 1
 * entries long; a log adopted with adoptUnanchored() is only as trustworthy
 * as the check before the adoption (adopted_entries in the report); a
 * whole log rewritten with a new key passes too, only the audit key id
 * pinned from an earlier export reveals it. Without the database password
 * append() writes no checkpoint (the next append() tries again) and the
 * export exports without a new checkpoint; a log written that way for
 * more than interval + 1 entries fails verify() with checkpoint_missing
 * and needs adoptUnanchored() unless a key was announced before.
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
	QStringList confirmed{};
	bool pwVerified{};

  public:
	/* actor: "os:<login>", "apikey:<key id>" or "cert:<SHA-256 fingerprint>" */
	ServiceContext(enum channel c, const QString &actor);
	/* The operating system user running this process */
	static ServiceContext localUser(enum channel c);
	/* Channel of this process for entries without a caller, e.g. the
	 * baseline written on a database upgrade. read_cmdline() sets cli. */
	static enum channel processChannel;
	/* Whether this process checked the database password against
	 * pwhash when it opened the database: always in the GUI, in
	 * xca --no-gui only with a password source (BTD-78). localUser()
	 * copies it; append() records it as parameter "db_unlock_verified" */
	static bool processPasswordVerified;
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
	bool passwordVerified() const
	{
		return pwVerified;
	}
	/* The caller answered question id (XCA_YESNO) with "yes", source:
	 * "dialog", "--yes" or "--confirm" (BTD-71). append() records the
	 * confirmations as parameter "confirmed", e.g. "key.size:--yes". */
	void confirm(const QString &id, const QString &source);
	QStringList confirmations() const
	{
		return confirmed;
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
	/* Adds code to the comma list "warning": something the service
	 * accepted but the log must show (BTD-55, BTD-65) */
	AuditParams &warn(const QString &code);
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

/* The checkpoint an export could not sign (BTD-112): the error code and
 * its text; an empty code if it signed one or none was due */
class AuditSkippedCheckpoint {
  public:
	QString code{};
	QString reason{};
};

/* A trust anchor from outside the database (BTD-101): the audit key ids
 * of an earlier export and the newest checkpoint seen then */
class AuditVerifyPins
{
  public:
	QStringList keys{};          // the first key of the log is one of them
	qint64 minCheckpoint{};      // 0: none; else the log has a valid
	                             // checkpoint at this seq or later
	bool isEmpty() const
	{
		return keys.isEmpty() && minCheckpoint <= 0;
	}
};

class AuditVerifyResult
{
  public:
	qint64 entries{};
	qint64 verifiedEntries{};
	qint64 firstBrokenSeq{};  // 0: chain intact
	QString reason{};        // missing, sequence, prev_hash, params, hash,
	                         // checkpoint_key, checkpoint_signature,
	                         // checkpoint_hash, checkpoint_missing
	qint64 checkpoints{};    // valid checkpoints
	qint64 lastCheckpointSeq{};    // seq of the last valid checkpoint
	qint64 failedCheckpointSeq{};  // seq of the first invalid one, 0 for
	                               // checkpoint_missing
	qint64 unanchoredEntries{};    // entries after the checkpoint_seq of
	                               // the last valid checkpoint, the
	                               // checkpoint row itself included
	QStringList auditKeys{};       // key ids, in the order they signed
	QList<AuditStateMismatch> mismatches{};
	qint64 unauditedRevocations{};   // also listed in mismatches
	qint64 adoptedEntries{};   // unsigned entries the first key adopted
	/* The trust anchor of the call (BTD-101) and whether the log meets
	 * it: reason untrusted_key or checkpoint_truncated otherwise */
	AuditVerifyPins pins{};
	bool pinsOk{ true };

	bool chainOk() const
	{
		return firstBrokenSeq == 0;
	}
	bool ok() const
	{
		return chainOk() && mismatches.isEmpty() && pinsOk;
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
	/* Deleting a certificate removes its revocation rows as a CA */
	static const char actionDelete[];
	/* Written once when an existing database gets the audit log:
	 * one revocation.baseline entry per revocation row found, then
	 * audit.init with the count */
	static const char actionRevocationBaseline[];
	static const char actionInit[];
	/* Signed checkpoints and their keys (BTD-37, see above) */
	static const char actionCheckpoint[];
	static const char actionKeyCreate[];
	/* A stored setting changed by an upgrade, not by the user: the
	 * PKCS#12 default of BTD-52 (old_pkcs12_algorithm, pkcs12_algorithm) */
	static const char actionSettingsMigrate[];
	/* one changed setting (BTD-224) */
	static const char actionSettingsUpdate[];
	/* Rows of the database left out on open because they did not
	 * decode (BTD-209): count, skipped_items, warning rows_skipped */
	static const char actionRowsSkipped[];
	static const int defaultCheckpointInterval;
	static const int maxCheckpointInterval;   // bound of the setting

	/* Appends one entry in its own (possibly nested) transaction.
	 * The sequence number is the primary key, so two writers that read
	 * the same predecessor cannot fork the chain: the second insert fails.
	 * Throws errorEx on a database error. A checkpoint that is due
	 * follows the entry in the same transaction. It never asks for the
	 * password; when it fails before its first write (no password, no
	 * usable key) it is skipped with a warning and the next append()
	 * tries again, a database error while it writes is thrown, because
	 * the rollback includes the caller's transaction (BTD-111). */
	static AuditEntry append(const ServiceContext &ctx,
			const QString &action, const QString &objectType,
			const QString &objectId,
			const AuditParams &params = AuditParams(),
			const QString &result = "success",
			const QString &errorCode = QString());
	/* The failure (or denied) entry of a service function, after its
	 * rollback: best effort, it never throws. When the database is the
	 * reason of the failure the entry may not be writable either; then
	 * it is lost and logged, and the caller rethrows its own error,
	 * which always wins (BTD-138). Returns whether it was written. */
	static bool appendFailure(const ServiceContext &ctx,
			const QString &action, const QString &objectType,
			const QString &objectId, const AuditParams &params,
			const QString &errorCode,
			const QString &result = "failure");

	/* Records the revocation rows of a database that existed before the
	 * audit log, so that verify() can tell them from rows added later
	 * without an entry. Called by database_model::initSqlDB(). */
	static void writeBaseline();
	/* A skipped automatic checkpoint is shown to the user once per
	 * error code (BTD-148); a newly opened database shows it again */
	static void resetCheckpointNotices();
	/* The next automatic checkpoint is tried again even if the last
	 * one failed over the same head (BTD-144): after a change of the
	 * audit keys or the password, and on open */
	static void retryFailedCheckpoint();

	/* Signs the newest entry; the first call creates the audit key.
	 * Throws serviceError: audit_key_unavailable (no database password),
	 * audit_key_missing (a key was announced, but no usable current key
	 * is left; no new key is created), audit_checkpoint_missing (no key
	 * yet and too long an unsigned tail, see adoptUnanchored()),
	 * audit_chain_broken (the entries
	 * since the last checkpoint do not chain, nothing is signed),
	 * empty_audit_log. */
	static AuditEntry checkpoint(const ServiceContext &ctx);
	/* Creates a new audit key, announces it and signs a checkpoint with
	 * the old key that names the new one; the old key is retired */
	static AuditEntry rotateKey(const ServiceContext &ctx);
	/* checkpoint() for a log without audit key whose unsigned tail is
	 * longer than the interval allows, which checkpoint() refuses with
	 * audit_checkpoint_missing: announces the first key with
	 * adopted_entries and signs. Only after the log was checked. */
	static AuditEntry adoptUnanchored(const ServiceContext &ctx);
	/* The setting audit_checkpoint_interval, default 100, at most
	 * maxCheckpointInterval (1000) */
	static int checkpointInterval();
	/* The bytes a checkpoint signature covers */
	static QByteArray checkpointPayload(const QVariantMap &params);

	static QList<AuditEntry> entries();
	/* The parameters of the newest entry of action, empty without one
	 * (BTD-221) */
	static QVariantMap lastParams(const QString &action);
	/* Checks the chain from the first entry and the signed checkpoints
	 * of its intact part, then replays the revocation and CRL entries of
	 * the intact part and compares the result with the revocations
	 * table; a row no entry knows is a mismatch. Never throws for a
	 * tampered entry: an entry without a canonical form is reported as
	 * broken. */
	static AuditVerifyResult verify(const AuditVerifyPins &pins =
				AuditVerifyPins());
	/* Signs a checkpoint unless the newest entry is one, then writes
	 * one canonical JSON object per line, including prev_hash and hash.
	 * Without a database password source it signs nothing and writes
	 * nothing to the database (BTD-70); *unsignedEntries receives the
	 * number of entries after the checkpoint_seq of the last
	 * checkpoint, the checkpoint row included, as unanchored_entries of
	 * verify() counts them (BTD-134).
	 * A log that no checkpoint may sign (audit_chain_broken,
	 * audit_key_missing, audit_checkpoint_missing) is exported read-only
	 * too (BTD-112); *skipped receives the code and its text, also for
	 * the missing password source (audit_key_unavailable). Throws
	 * errorEx for an entry without a canonical form and serviceError
	 * for a wrong password source (audit_password_rejected) or a
	 * database error. */
	static QByteArray exportJsonLines(const ServiceContext &ctx,
			qint64 *unsignedEntries = nullptr,
			AuditSkippedCheckpoint *skipped = nullptr);
	/* The same for the local user on the channel of this process */
	static QByteArray exportJsonLines(qint64 *unsignedEntries = nullptr,
			AuditSkippedCheckpoint *skipped = nullptr);

	/* RFC 8785 serialisation; throws errorEx on unsupported values */
	static QByteArray canonicalJson(const QVariant &v);
	static QByteArray chainHash(const QByteArray &prevHashHex,
			const QByteArray &canonical);
	static QString rfc3339(const QDateTime &t);
};

/* Failure entries of service calls inside a caller-owned transaction
 * (BTD-41). A service function appends its "failure" or "denied" entry
 * after its own rollback; when the caller holds an outer transaction,
 * that entry sits in the outer transaction and vanishes with its
 * rollback. While a capture lives, append() keeps a copy of every such
 * entry written inside a transaction; after rolling the outer
 * transaction back, the caller calls replay() and the entries are
 * written again, now outside any transaction. After a successful
 * commit they are stored already: the caller calls discard(). Used by
 * the bxc-pki command runner, which runs one command (or, with
 * bootstrap, many) in one transaction and with --plan rolls back on
 * purpose (then discard(): a plan writes nothing). Captures nest; create
 * them on the stack only. */
class AuditFailureCapture
{
	struct entry
	{
		ServiceContext ctx;
		QString action, objectType, objectId;
		AuditParams params;
		QString result, errorCode;
	};
	QList<entry> captured{};
	AuditFailureCapture *outer{};
	static AuditFailureCapture *current;

  public:
	AuditFailureCapture();
	~AuditFailureCapture();
	AuditFailureCapture(const AuditFailureCapture &) = delete;
	AuditFailureCapture &operator=(const AuditFailureCapture &) = delete;

	/* Called by AuditLog::append() */
	static void record(const ServiceContext &ctx, const QString &action,
			const QString &objectType, const QString &objectId,
			const AuditParams &params, const QString &result,
			const QString &errorCode);
	int size() const
	{
		return captured.size();
	}
	/* Appends the captured entries again and forgets them; call it
	 * outside any transaction. Throws errorEx like append(). */
	QList<AuditEntry> replay();
	void discard()
	{
		captured.clear();
	}
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
		TransCommitThrow();
	} catch (serviceError &err) {
		AuditLog::appendFailure(ctx, action, objectType, objectId,
				params, err.code);
		throw;
	} catch (...) {
		AuditLog::appendFailure(ctx, action, objectType, objectId,
				params, "internal_error");
		throw;
	}
}

#endif
