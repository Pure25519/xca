/* vi: set sw=4 ts=4:
 *
 * The database session of xca-server (BTD-154): everything here calls
 * lib/ and runs on the DB worker only (worker.h).
 */

#ifndef __XCA_SERVER_SESSION_H
#define __XCA_SERVER_SESSION_H

#include <QJsonObject>
#include <QMap>
#include <QJsonValue>
#include <QString>
#include <QStringList>
#include <QVariantMap>

namespace xcaserver {

class Config;

/* The warning and progress hooks of lib/ for a server: text on stderr,
 * no questions answered, no spinner; call once at start */
void installHooks();

/* Initialises lib/ (OIDs, settings), opens the database of the
 * configuration with the password of the worker's password source and
 * writes server.start (httpLibrary: name and version of the HTTP
 * library). Throws errorEx (serviceError, secretError). */
QJsonObject openSession(const Config &config,
		const QString &httpLibrary);
/* The CA scope of a request (auth.h, Access): every CA, or the objects of
 * these bootstrap CA ids */
class CaScope
{
  public:
	bool all{};
	QStringList cas{};
};
/* GET /v1/status: database, schema versions, object counts, the CA scope
 * and whether it ran on the DB worker; actor is the caller. For a scope of
 * some CAs (BTD-311) the counts are those of their CA certificates, the
 * certificates they issued, the keys of these and their CRLs; requests,
 * templates and the audit log belong to no CA and are left out. */
QJsonObject statusJob(const QString &actor, const CaScope &scope);
/* One audit entry of the server on the channel rest (BTD-155: auth.login,
 * auth.denied, config.reload); an empty actor is the server's user. The
 * parameters go through the allow-list of AuditParams. */
QJsonObject appendEntry(const QString &actor, const QString &action,
		const QString &objectType, const QString &objectId,
		const QVariantMap &params, const QString &result,
		const QString &errorCode);
/* The CA a request names, for the CA scope of a role (auth.h): reference
 * is an item id (number, or a string of digits), the name of a
 * certificate or its SHA-256 fingerprint (hex, colons allowed); with
 * issuerOf its issuer is the CA. Answers {item, bootstrap_ids}: the item
 * id of the CA certificate and the bootstrap CA ids whose settings row
 * (bootstrap_<hash>, kind ca) has that item. Throws unknown_reference or
 * ambiguous_reference. */
QJsonObject caScopeJob(const QJsonValue &reference, bool issuerOf);
/* The bootstrap settings rows of kind ca: bootstrap CA id -> item id of
 * the CA certificate (written by bxc-pki bootstrap) */
QMap<QString, qint64> bootstrapCas();
/* GET /ready (BTD-163): takes and gives back the write lock an audit entry
 * needs (BEGIN IMMEDIATE, ROLLBACK) and answers {read_only}; throws when
 * the database is not open or another process holds its lock past the
 * busy timeout */
QJsonObject readyJob();
/* Whether the last audit entry of the server (appendEntry) was written;
 * any thread */
bool lastAuditWriteOk();
/* server.stop, then the database is closed, also when the entry fails;
 * throws its error then. Nothing without an open database. */
QJsonObject closeSession();

}

#endif
