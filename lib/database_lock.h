/* vi: set sw=4 ts=4:
 *
 * The exclusive database of xca-server (BTD-154).
 *
 * xca-server holds a QLockFile "<database>.lock" next to the local SQLite
 * database for its whole run. Every open of a local database in lib/
 * (database_model) checks that lock and refuses with the serviceError
 * database_in_use while another live process holds it. The GUI and the
 * command line only check, they never take the lock, so two GUIs can
 * still open one database as before. A lock of a process that is gone
 * (stale) is removed by the check and taken over by the next server.
 * Remote databases (user@host/db#QPSQL7 and the like) have no lock.
 */

#ifndef __DATABASE_LOCK_H
#define __DATABASE_LOCK_H

#include <QString>

class DatabaseLock
{
  public:
	/* "<absolute path of the database>.lock" */
	static QString lockFileName(const QString &database);
	/* Throws serviceError database_in_use if another live process
	 * holds the lock of the local database; a lock of this process
	 * passes, a stale lock is removed */
	static void refuseIfInUse(const QString &database);
	/* The text of the database_in_use error for a lock file */
	static QString inUseMessage(const QString &database);
};

#endif
