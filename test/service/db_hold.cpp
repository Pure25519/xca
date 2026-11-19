/* vi: set sw=4 ts=4:
 *
 * Test helper for the database lock (BTD-302, BTD-303): opens a local
 * database the way the command line and the GUI do (database_model) and
 * keeps it open until it is killed.
 *
 * db_hold <database>
 *
 * The database password comes from the password source in
 * XCA_DB_HOLD_PASSWORD (e.g. env:XCA_SERVER_DB_PASSWORD). Prints "open"
 * on stdout once the database is open; on a failed open the error code
 * (e.g. database_in_use) on stderr and exit 1.
 */

#include <cstdio>

#include <QCoreApplication>
#include <QThread>

#include "lib/database_model.h"
#include "lib/exception.h"
#include "lib/json_report.h"
#include "lib/oid.h"
#include "lib/pass_info.h"
#include "lib/PwDialogCore.h"

int main(int argc, char *argv[])
{
	QCoreApplication app(argc, argv);
	if (argc != 2) {
		fprintf(stderr, "usage: db_hold <database>\n");
		return 2;
	}
	QByteArray source = qgetenv("XCA_DB_HOLD_PASSWORD");
	PasswordSourceScope password(pass_info::DatabasePassword,
				source.constData());
	try {
		initOIDs();
		Database.open(QString::fromLocal8Bit(argv[1]));
	} catch (errorEx &err) {
		fprintf(stderr, "%s\n", qPrintable(
			JsonReport::error(err)["code"].toString()));
		return 1;
	} catch (enum open_result) {
		fprintf(stderr, "open_failed\n");
		return 1;
	}
	printf("open\n");
	fflush(stdout);
	for (;;)
		QThread::sleep(60);
}
