/* vi: set sw=4 ts=4:
 *
 * The database session of xca-server (BTD-154): everything here calls
 * lib/ and runs on the DB worker only (worker.h).
 */

#ifndef __XCA_SERVER_SESSION_H
#define __XCA_SERVER_SESSION_H

#include <QJsonObject>
#include <QString>

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
/* GET /v1/status: database, schema versions, object counts and whether
 * it ran on the DB worker; actor is the caller */
QJsonObject statusJob(const QString &actor);
/* server.stop, then the database is closed, also when the entry fails;
 * throws its error then. Nothing without an open database. */
QJsonObject closeSession();

}

#endif
