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
	qint64 seq{};            // last audit entry that set the expected state

	QVariantMap toMap() const;
};

class AuditVerifyResult
{
  public:
	qint64 entries{};
	qint64 verifiedEntries{};
	qint64 firstBrokenSeq{};  // 0: chain intact
	QString reason{};        // missing, sequence, prev_hash, hash
	QList<AuditStateMismatch> mismatches{};
	qint64 unauditedRevocations{};

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

	static QList<AuditEntry> entries();
	/* Checks the chain from the first entry, then replays the revocation
	 * and CRL entries of the intact part and compares the result with the
	 * revocations table. Deleting the newest entries is only detected with
	 * the signed checkpoints of BTD-37. */
	static AuditVerifyResult verify();
	/* One canonical JSON object per line, including prev_hash and hash */
	static QByteArray exportJsonLines();

	/* RFC 8785 serialisation; throws errorEx on unsupported values */
	static QByteArray canonicalJson(const QVariant &v);
	static QByteArray chainHash(const QByteArray &prevHashHex,
			const QByteArray &canonical);
	static QString rfc3339(const QDateTime &t);
};

#endif
