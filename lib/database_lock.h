/* vi: set sw=4 ts=4:
 *
 * The lock of a local database (BTD-154, BTD-302, BTD-303).
 *
 * A kernel lock on an open file of "<database>.lock" next to the local
 * SQLite database: flock() on Linux and the other POSIX hosts, LockFileEx()
 * on Windows. The kernel releases it when the holder closes the file or
 * ends, also after SIGKILL, so it never depends on a PID or a host name
 * (BTD-302: the QLockFile of BTD-154 judged staleness by both, and a
 * killed server in a recreated container kept the database locked).
 *
 * - xca-server holds the lock exclusive for its whole run;
 * - the GUI and the command line (database_model) hold it shared for as
 *   long as the database is open: several of them can share a database as
 *   before, the server does not start while one of them has it open, and
 *   none of them opens it while the server runs (BTD-303);
 * - the process that holds the lock exclusive opens its own database
 *   without a second lock (the DB worker of the server).
 *
 * The exclusive holder writes "<pid>\n<application>\n<host>\n" into the
 * file, only as a hint for the database_in_use message; a shared holder
 * clears a hint left by a server that is gone. The file itself stays: a
 * lock file that is removed while it is locked would let a second holder
 * lock a new file of the same name.
 *
 * Network file systems: on NFS, Linux maps flock() to NFS byte-range
 * locks, which the NFS server coordinates between clients (NFSv4, or
 * NFSv3 with lockd); a client that dies keeps its lock until its lease
 * ends (NFSv4: about 90 seconds). With the mount option "nolock", or on
 * SMB/CIFS mounts that do not forward the lock to the server, the lock
 * only covers the processes of one client. SQLite itself is not safe on
 * such file systems either: keep the database on a local disk or a volume
 * of one host.
 *
 * Remote databases (user@host/db#QPSQL7 and the like) have no lock.
 */

#ifndef __DATABASE_LOCK_H
#define __DATABASE_LOCK_H

#include <QString>

class DatabaseLock
{
  public:
	enum Mode { Shared, Exclusive };

	/* Takes the lock of the local database, or throws serviceError
	 * database_in_use if a holder of the other kind (exclusive: any
	 * holder) has it, or if the lock file cannot be used */
	DatabaseLock(const QString &database, Mode mode);
	~DatabaseLock();
	DatabaseLock(const DatabaseLock &) = delete;
	DatabaseLock &operator=(const DatabaseLock &) = delete;

	/* "<absolute path of the database>.lock" */
	static QString lockFileName(const QString &database);
	/* true if this process holds the lock of database exclusive */
	static bool heldExclusive(const QString &database);

  private:
	QString database{};
	Mode mode{ Shared };
#ifdef Q_OS_WIN
	void *handle{ nullptr };
#else
	int fd{ -1 };
#endif

	void writeHint();
	void clearHint();
	QString holderHint() const;
	/* The database_in_use message for a lock held by others */
	QString inUse() const;
	void release();
	[[noreturn]] void refuse(const QString &detail);
};

#endif
