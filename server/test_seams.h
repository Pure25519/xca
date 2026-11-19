/* vi: set sw=4 ts=4:
 *
 * Test seams of xca-server (BTD-163): compiled only with BXC_PKI_TEST_SEAMS,
 * which a build gets only with BUILD_TESTING (test_release_no_seams checks
 * that a build without it has none), and active only while the environment
 * variable BXC_PKI_TEST_SEAMS is 1.
 *
 *   POST /_test/stall?seconds=N on the health listener: a job that keeps
 *   the DB worker busy for N seconds (1 to 60); 202 at once.
 */

#ifndef __XCA_SERVER_TEST_SEAMS_H
#define __XCA_SERVER_TEST_SEAMS_H

#ifdef BXC_PKI_TEST_SEAMS

namespace httplib {
struct Request;
struct Response;
}

namespace xcaserver {

class DbWorker;

namespace ServerTestSeams {
/* true when req was a seam request and res is its answer */
bool handle(const httplib::Request &req, httplib::Response &res,
		DbWorker &worker);
}

}

#endif

#endif
