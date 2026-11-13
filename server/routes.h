/* vi: set sw=4 ts=4:
 *
 * The HTTP side of xca-server (BTD-154): routes, limits, problem+json.
 * Everything here runs on the cpp-httplib pool threads and never calls
 * lib/ directly: database work goes to the DB worker as a job.
 *
 *   GET /v1/health   200, no database
 *   GET /v1/status   200, a job on the DB worker
 * An unknown path is 404, another method on a known path 405 (Allow),
 * headers larger than header_max_bytes 431, a full job queue or a job
 * timeout 503 with Retry-After; all as application/problem+json with
 * the members type, title, status, detail and code.
 */

#ifndef __XCA_SERVER_ROUTES_H
#define __XCA_SERVER_ROUTES_H

#include <string>

#include <httplib.h>

namespace xcaserver {

class Config;
class DbWorker;

/* "cert:<lowercase hex SHA-256 of the peer certificate DER>", empty
 * without a peer certificate */
std::string certActor(const httplib::Request &req);
/* Applies the limits of config and installs the routes */
void installRoutes(httplib::Server &srv, DbWorker &worker,
		const Config &config);

}

#endif
