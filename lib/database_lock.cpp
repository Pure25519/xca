/* vi: set sw=4 ts=4:
 *
 * The lock of a local database (BTD-154, BTD-302, BTD-303), see
 * database_lock.h.
 */

#include "database_lock.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QMutex>
#include <QObject>
#include <QSet>
#include <QStringList>
#include <QSysInfo>

#include "exception.h"

#ifdef Q_OS_WIN
#include <string>
#include <windows.h>
#else
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {

/* The lock files this process holds exclusive */
QMutex exclusiveMutex;
QSet<QString> exclusiveFiles;

QString systemError(int code)
{
#ifdef Q_OS_WIN
	return QString("Windows error %1").arg(code);
#else
	return QString::fromLocal8Bit(strerror(code));
#endif
}

#ifdef Q_OS_WIN
/* A byte far behind the hint: Windows byte-range locks are mandatory, a
 * lock on the hint itself would keep others from reading it */
const DWORD lockOffsetHigh = 0x40000000;
#endif

}

QString DatabaseLock::lockFileName(const QString &database)
{
	/* the canonical path: two paths to one database (a symlink) share
	 * one lock (BTD-315); a database that does not exist yet has none */
	QFileInfo info(database);
	QString path = info.exists() ? info.canonicalFilePath() :
		info.absoluteFilePath();
	return path + ".lock";
}

bool DatabaseLock::heldExclusive(const QString &database)
{
	QMutexLocker guard(&exclusiveMutex);
	return exclusiveFiles.contains(lockFileName(database));
}

DatabaseLock::DatabaseLock(const QString &db, Mode m)
	: database(db), mode(m)
{
	QString lock = lockFileName(database);
#ifdef Q_OS_WIN
	std::wstring path = QDir::toNativeSeparators(lock).toStdWString();
	DWORD share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
	HANDLE h = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE,
		share, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	DWORD err = h == INVALID_HANDLE_VALUE ? GetLastError() : 0;
	if (h == INVALID_HANDLE_VALUE && mode == Shared &&
	    err == ERROR_ACCESS_DENIED) {
		h = CreateFileW(path.c_str(), GENERIC_READ, share, nullptr,
			OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		err = h == INVALID_HANDLE_VALUE ? GetLastError() : 0;
		/* no lock file, and none can be made here: no server can
		 * hold one either */
		if (err == ERROR_FILE_NOT_FOUND)
			return;
	}
	if (h == INVALID_HANDLE_VALUE)
		refuse(QObject::tr("The lock file '%1' of the database '%2' "
			"cannot be opened: %3").arg(lock, database,
			systemError(int(err))));
	handle = h;
	OVERLAPPED ov{};
	ov.OffsetHigh = lockOffsetHigh;
	DWORD flags = LOCKFILE_FAIL_IMMEDIATELY |
		(mode == Exclusive ? LOCKFILE_EXCLUSIVE_LOCK : 0);
	if (!LockFileEx(h, flags, 0, 1, 0, &ov)) {
		err = GetLastError();
		if (err == ERROR_LOCK_VIOLATION || err == ERROR_IO_PENDING)
			refuse(inUse());
		refuse(QObject::tr("The lock file '%1' of the database '%2' "
			"cannot be locked: %3").arg(lock, database,
			systemError(int(err))));
	}
#else
	QByteArray path = QFile::encodeName(lock);
	int err = 0;
	/* a few rounds: the file can be replaced between open and lock */
	for (int round = 0; ; round++) {
		/* flock() works on a read-only descriptor, so a lock file
		 * of another uid can be locked as long as it is readable;
		 * only the hint needs write access (BTD-315) */
		fd = ::open(path.constData(), O_RDWR | O_CLOEXEC);
		err = fd < 0 ? errno : 0;
		if (fd < 0 && (err == EACCES || err == EPERM || err == EROFS)) {
			fd = ::open(path.constData(), O_RDONLY | O_CLOEXEC);
			err = fd < 0 ? errno : 0;
		}
		if (fd < 0 && err == ENOENT) {
			fd = ::open(path.constData(),
				O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
			err = fd < 0 ? errno : 0;
			if (fd < 0 && err == EEXIST && round < 5)
				continue;
			/* no lock file and none can be made here: another
			 * uid could make one and hold it, so only a reader
			 * that cannot write the database goes on without
			 * a lock (BTD-315) */
			if (fd < 0 && mode == Shared &&
			    (err == EACCES || err == EPERM || err == EROFS) &&
			    ::access(QFile::encodeName(QFileInfo(database)
				.absoluteFilePath()).constData(), W_OK) != 0)
				return;
			if (fd < 0)
				refuse(QObject::tr("The lock file '%1' of the "
					"database '%2' cannot be made in '%3': "
					"%4. The server, the GUI and the "
					"command line need it to share the "
					"database; let every user of the "
					"database create files there, or "
					"create the lock file once, readable "
					"for all of them").arg(lock, database,
					QFileInfo(lock).absolutePath(),
					systemError(err)));
		}
		if (fd < 0)
			refuse(QObject::tr("The lock file '%1' of the database "
				"'%2' cannot be opened: %3").arg(lock, database,
				systemError(err)));
		if (::flock(fd, (mode == Exclusive ? LOCK_EX : LOCK_SH) |
				LOCK_NB) != 0) {
			err = errno;
			if (err == EWOULDBLOCK)
				refuse(inUse());
			/* NFS emulates flock() with byte-range locks, which
			 * need a writable descriptor for an exclusive lock */
			refuse(QObject::tr("The lock file '%1' of the "
				"database '%2' cannot be locked: %3").arg(lock,
				database, systemError(err)));
		}
		/* the path must still name the locked file: one deleted or
		 * replaced between open and lock is tried again */
		struct stat locked, named;
		if (::fstat(fd, &locked) == 0 &&
		    ::stat(path.constData(), &named) == 0 &&
		    locked.st_dev == named.st_dev &&
		    locked.st_ino == named.st_ino)
			break;
		::close(fd);
		fd = -1;
		if (round >= 5)
			refuse(QObject::tr("The lock file '%1' of the database "
				"'%2' keeps changing while it is locked")
				.arg(lock, database));
	}
#endif
	if (mode == Exclusive) {
		writeHint();
		QMutexLocker guard(&exclusiveMutex);
		exclusiveFiles.insert(lock);
	} else {
		/* no exclusive holder now: a hint is one of a server that
		 * is gone */
		clearHint();
	}
}

DatabaseLock::~DatabaseLock()
{
	if (mode == Exclusive) {
		clearHint();
		QMutexLocker guard(&exclusiveMutex);
		exclusiveFiles.remove(lockFileName(database));
	}
	release();
}

void DatabaseLock::release()
{
#ifdef Q_OS_WIN
	if (handle) {
		OVERLAPPED ov{};
		ov.OffsetHigh = lockOffsetHigh;
		UnlockFileEx(handle, 0, 1, 0, &ov);
		CloseHandle(handle);
		handle = nullptr;
	}
#else
	if (fd >= 0) {
		::close(fd);
		fd = -1;
	}
#endif
}

void DatabaseLock::refuse(const QString &detail)
{
	release();
	throw serviceError("database_in_use", detail);
}

QString DatabaseLock::inUse() const
{
	QString lock = lockFileName(database);
	QString holder = holderHint();
	if (mode == Shared || !holder.isEmpty())
		return QObject::tr("The database '%1' is in use by xca-server: "
			"the lock file '%2' is held by another process%3. Stop "
			"the server or use its REST interface.")
			.arg(database, lock, holder);
	return QObject::tr("The database '%1' is open in another process "
		"(the GUI or the command line): the lock file '%2' is held. "
		"Close the database there before xca-server starts.")
		.arg(database, lock);
}

void DatabaseLock::writeHint()
{
	QByteArray hint = QString("%1\n%2\n%3\n")
		.arg(QCoreApplication::applicationPid())
		.arg(QCoreApplication::applicationName())
		.arg(QSysInfo::machineHostName()).toUtf8();
#ifdef Q_OS_WIN
	DWORD written = 0;
	if (SetFilePointer(handle, 0, nullptr, FILE_BEGIN) !=
			INVALID_SET_FILE_POINTER && SetEndOfFile(handle))
		WriteFile(handle, hint.constData(), DWORD(hint.size()),
			&written, nullptr);
#else
	if (fd >= 0 && ::ftruncate(fd, 0) == 0) {
		ssize_t written = ::pwrite(fd, hint.constData(),
			size_t(hint.size()), 0);
		Q_UNUSED(written);
	}
#endif
}

void DatabaseLock::clearHint()
{
	/* best effort: a read-only lock file keeps its hint */
#ifdef Q_OS_WIN
	if (handle && SetFilePointer(handle, 0, nullptr, FILE_BEGIN) !=
			INVALID_SET_FILE_POINTER)
		SetEndOfFile(handle);
#else
	if (fd >= 0) {
		int cleared = ::ftruncate(fd, 0);
		Q_UNUSED(cleared);
	}
#endif
}

QString DatabaseLock::holderHint() const
{
	char buf[512];
	qint64 n = 0;
#ifdef Q_OS_WIN
	DWORD got = 0;
	OVERLAPPED ov{};
	if (handle && ReadFile(handle, buf, sizeof(buf), &got, &ov))
		n = got;
#else
	if (fd >= 0)
		n = ::pread(fd, buf, sizeof(buf), 0);
#endif
	if (n <= 0)
		return QString();
	QStringList l = QString::fromUtf8(buf, int(n)).split('\n');
	bool ok = false;
	qint64 pid = l.value(0).toLongLong(&ok);
	if (!ok || l.size() < 3)
		return QString();
	return QObject::tr(" (process %1 '%2' on %3)").arg(pid)
		.arg(l.value(1)).arg(l.value(2));
}
