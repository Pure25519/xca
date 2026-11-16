/* vi: set sw=4 ts=4:
 *
 * The HTTP side of xca-server (BTD-154, BTD-155): routes, limits,
 * authentication, access rules, problem+json. Everything here runs on the
 * cpp-httplib pool threads and never calls lib/ directly: database work
 * (and the audit entries) goes to the DB worker as a job.
 *
 * A request passes, in this order:
 *   1. the header limit (431)
 *   2. authentication (auth.h): the client certificate or, with API keys,
 *      X-API-Key; neither is 401 unauthenticated + auth.denied
 *   3. the route: an unknown path is 404, another method on a known path
 *      405 (Allow); /v1/health needs no role
 *   4. auth.login, once per connection and identity (not for /v1/health)
 *   5. the role and CA check of the operation: 403 forbidden + auth.denied
 *   6. the handler: GET /v1/status and POST /v1/reload; every other
 *      operation of roles.json is a stub that answers 501 not_implemented
 * Every error is application/problem+json with the members type, title,
 * status, detail and code; a full job queue or a job timeout is 503 with
 * Retry-After.
 */

#ifndef __XCA_SERVER_ROUTES_H
#define __XCA_SERVER_ROUTES_H

#include <string>

#include <httplib.h>

namespace xcaserver {

class AuthAudit;
class Config;
class DbWorker;
class OperationTable;
class RoleHolder;

/* "cert:<lowercase hex SHA-256 of the peer certificate DER>", empty
 * without a peer certificate */
std::string certActor(const httplib::Request &req);
/* Applies the limits of config and installs the routes of operations;
 * all objects must outlive the server */
void installRoutes(httplib::Server &srv, DbWorker &worker,
		const Config &config, const OperationTable &operations,
		RoleHolder &roles, AuthAudit &audit);

}

#endif
