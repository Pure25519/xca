/* vi: set sw=4 ts=4:
 *
 * The exclusive database of xca-server (BTD-154), see database_lock.h.
 */

#include "database_lock.h"

#include <QCoreApplication>
#include <QFileInfo>
#include <QLockFile>
#include <QObject>
#include <QSysInfo>

#include "exception.h"

QString DatabaseLock::lockFileName(const QString &database)
{
	return QFileInfo(database).absoluteFilePath() + ".lock";
}

QString DatabaseLock::inUseMessage(const QString &database)
{
	QString lock = lockFileName(database);
	qint64 pid = 0;
	QString host, app;
	QLockFile lf(lock);
	QString holder;
	if (lf.getLockInfo(&pid, &host, &app))
		holder = QObject::tr(" (process %1 '%2' on %3)")
				.arg(pid).arg(app).arg(host);
	return QObject::tr("The database '%1' is in use by xca-server: the "
		"lock file '%2' is held by another process%3. Stop the server "
		"or use its REST interface.").arg(database).arg(lock)
		.arg(holder);
}

void DatabaseLock::refuseIfInUse(const QString &database)
{
	QString lock = lockFileName(database);
	if (!QFileInfo::exists(lock))
		return;
	QLockFile lf(lock);
	qint64 pid = 0;
	QString host, app;
	/* the server of this process opens its own database */
	if (lf.getLockInfo(&pid, &host, &app) &&
	    pid == QCoreApplication::applicationPid() &&
	    (host.isEmpty() || host == QSysInfo::machineHostName()))
		return;
	/* Only a dead holder makes the lock stale, never its age: a
	 * stale lock is taken and given up again (removed), a live one
	 * fails at once */
	lf.setStaleLockTime(0);
	if (lf.tryLock(0)) {
		lf.unlock();
		return;
	}
	if (lf.error() == QLockFile::LockFailedError)
		throw serviceError("database_in_use", inUseMessage(database));
	/* the lock file cannot be read or written: no proof of a holder,
	 * but no proof of its absence either */
	throw serviceError("database_in_use", QObject::tr(
		"The lock file '%1' of the database '%2' exists but cannot be "
		"checked (no access)").arg(lock).arg(database));
}
