/* vi: set sw=4 ts=4:
 *
 * Staged, atomic, owner-only file output (BTD-42), see staged_file.h.
 *
 * The POSIX path is built and tested on Linux. The Windows path (protected
 * DACL with OWNER RIGHTS only, CreateFileW CREATE_NEW, FlushFileBuffers,
 * MoveFileExW) is written for BTD-13 and NOT yet compiled or tested.
 */

#include "staged_file.h"

#include <cerrno>
#include <cstring>

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QObject>
#include <QRandomGenerator>

#include "exception.h"

#if defined(Q_OS_WIN)
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#else
#include <cstdio>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

std::function<bool(enum StagedFile::step, const QString &)>
	StagedFile::faultHook;

QString StagedFile::stepName(enum step s)
{
	switch (s) {
	case create: return "create";
	case write: return "write";
	case sync: return "sync";
	case publish_step: return "publish";
	case recheck: return "recheck";
	case owner_check: return "owner_check";
	}
	return "unknown";
}

static serviceError failed(const QString &what, const QString &path,
			const QString &why)
{
	return serviceError("write_failed", QObject::tr("%1 '%2' failed: %3")
		.arg(what, QDir::toNativeSeparators(path), why));
}

bool StagedFile::injected(enum step s) const
{
	return faultHook && faultHook(s, targetPath);
}

void StagedFile::fault(enum step s) const
{
	if (injected(s))
		throw failed(stepName(s), targetPath,
			QObject::tr("injected fault (test)"));
}

static serviceError notOwnerOnly(const QString &path, const QString &why)
{
	return serviceError("permission_check_failed", QObject::tr(
		"'%1' cannot be kept owner-only: %2")
		.arg(QDir::toNativeSeparators(path), why));
}

StagedFile::StagedFile(const QString &target, bool secretFile,
			bool replaceTarget)
	: targetPath(QFileInfo(target).absoluteFilePath()),
	  secret(secretFile), replace(replaceTarget)
{
}

StagedFile::~StagedFile()
{
	removeTemp();
}

void StagedFile::discard()
{
	removeTemp();
}

void StagedFile::removeTemp()
{
	if (staged && !published && !tempPath.isEmpty())
		QFile::remove(tempPath);
	staged = false;
}

void StagedFile::checkTarget(const QString &target, bool replaceTarget)
{
	QFileInfo t(QFileInfo(target).absoluteFilePath());
	QFileInfo dir(t.absolutePath());

	if (!dir.exists() || !dir.isDir())
		throw serviceError("invalid_output", QObject::tr(
			"The output directory '%1' does not exist")
			.arg(QDir::toNativeSeparators(dir.filePath())));
	if (!dir.isWritable())
		throw serviceError("invalid_output", QObject::tr(
			"The output directory '%1' is not writable")
			.arg(QDir::toNativeSeparators(dir.filePath())));
	/* also a dangling symbolic link exists as a name */
	if (t.exists() || t.isSymLink()) {
		if (!replaceTarget)
			throw serviceError("file_exists", QObject::tr(
				"'%1' exists; it is replaced only with --force")
				.arg(QDir::toNativeSeparators(t.filePath())));
		if (t.isDir() || (!t.isFile() && !t.isSymLink()))
			throw serviceError("invalid_output", QObject::tr(
				"'%1' is not a regular file")
				.arg(QDir::toNativeSeparators(t.filePath())));
	}
}

void StagedFile::writeFile(const QString &target, const QByteArray &data,
			bool secretFile, bool replaceTarget)
{
	StagedFile f(target, secretFile, replaceTarget);
	f.stage(data);
	f.publish();
}

static QString tempName(const QString &target)
{
	QFileInfo t(target);
	return t.absolutePath() + "/." + t.fileName() +
		QString(".bxc-tmp-%1").arg(
			QRandomGenerator::system()->generate64(), 16, 16,
			QChar('0'));
}

#if !defined(Q_OS_WIN)

static QString sysError(int err)
{
	return QString::fromLocal8Bit(strerror(err));
}

void StagedFile::stage(const QByteArray &data)
{
	if (staged || published)
		throw errorEx(QObject::tr("StagedFile: '%1' staged twice")
			.arg(targetPath));
	checkTarget(targetPath, replace);

	int fd = -1;
	for (int tries = 0; fd < 0 && tries < 8; tries++) {
		tempPath = tempName(targetPath);
		fault(create);
		/* the mode is the one of the creation: a secret is never
		 * readable by others, not even for a moment */
		fd = ::open(QFile::encodeName(tempPath).constData(),
			O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
			secret ? 0600 : 0644);
		if (fd < 0 && errno != EEXIST)
			throw failed(QObject::tr("Creating"), tempPath,
					sysError(errno));
	}
	if (fd < 0)
		throw failed(QObject::tr("Creating"), tempPath,
				sysError(EEXIST));
	staged = true;
	try {
		/* umask may only remove bits; a secret gets exactly 0600 */
		if (secret && fchmod(fd, 0600) != 0)
			throw failed(QObject::tr("Setting the mode of"),
					tempPath, sysError(errno));
		/* rule 10 before the commit (review of xca#62): a file
		 * system that ignores the mode (WSL drvfs, vfat) shows it
		 * here already; nothing is stored for a key it cannot hold */
		struct stat st;
		if (secret && fstat(fd, &st) != 0)
			throw failed(QObject::tr("Checking"), tempPath,
					sysError(errno));
		if (secret && (injected(owner_check) ||
		    (st.st_mode & 077) != 0 || st.st_uid != geteuid()))
			throw notOwnerOnly(targetPath, QObject::tr(
				"a new file in this directory has mode %1 and "
				"owner %2; choose a directory on a file system "
				"with POSIX permissions").arg(st.st_mode & 07777,
				4, 8, QChar('0')).arg(st.st_uid));
		const char *p = data.constData();
		qint64 left = data.size();
		while (left > 0) {
			fault(write);
			ssize_t n = ::write(fd, p, left);
			if (n < 0 && errno == EINTR)
				continue;
			if (n <= 0)
				throw failed(QObject::tr("Writing"), tempPath,
					sysError(n < 0 ? errno : EIO));
			p += n;
			left -= n;
		}
		fault(sync);
		if (fsync(fd) != 0)
			throw failed(QObject::tr("Syncing"), tempPath,
					sysError(errno));
		int fdc = fd;
		fd = -1;
		if (::close(fdc) != 0)
			throw failed(QObject::tr("Closing"), tempPath,
					sysError(errno));
	} catch (...) {
		if (fd >= 0)
			::close(fd);
		removeTemp();
		throw;
	}
	bytes = data.size();
}

static void syncDirectory(const QString &path)
{
	int dfd = ::open(QFile::encodeName(QFileInfo(path).absolutePath())
			.constData(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dfd >= 0) {
		/* best effort: some file systems refuse fsync on a directory */
		(void)fsync(dfd);
		::close(dfd);
	}
}

void StagedFile::publish()
{
	if (!staged || published)
		throw errorEx(QObject::tr("StagedFile: '%1' is not staged")
			.arg(targetPath));
	QByteArray tmp = QFile::encodeName(tempPath);
	QByteArray dst = QFile::encodeName(targetPath);

	fault(publish_step);
	if (replace) {
		if (::rename(tmp.constData(), dst.constData()) != 0)
			throw failed(QObject::tr("Renaming to"), targetPath,
					sysError(errno));
	} else {
		/* link() never replaces: a target created after stage()
		 * is not overwritten either */
		if (::link(tmp.constData(), dst.constData()) != 0) {
			int err = errno;
			if (err == EEXIST)
				throw serviceError("file_exists", QObject::tr(
					"'%1' exists; it is replaced only with "
					"--force").arg(QDir::toNativeSeparators(
						targetPath)));
			throw failed(QObject::tr("Linking to"), targetPath,
					sysError(err));
		}
		::unlink(tmp.constData());
	}
	published = true;
	staged = false;
	syncDirectory(targetPath);

	/* rule 10: the published secret is owner-only and ours; one that
	 * is not is removed again (review of xca#62), not left readable */
	struct stat st;
	QString why;
	if (injected(recheck))
		why = QObject::tr("injected fault (test)");
	else if (::lstat(dst.constData(), &st) != 0)
		why = sysError(errno);
	else if (!S_ISREG(st.st_mode) || (secret && ((st.st_mode & 077) != 0 ||
		 st.st_uid != geteuid())))
		why = QObject::tr("not an owner-only regular file after "
			"writing (mode %1)").arg(st.st_mode & 07777, 4, 8,
			QChar('0'));
	if (!why.isEmpty()) {
		if (::unlink(dst.constData()) == 0)
			published = false;
		syncDirectory(targetPath);
		throw notOwnerOnly(targetPath, why);
	}
}

#else /* Q_OS_WIN: NOT compiled or tested yet (BTD-13) */

static QString sysError(DWORD err)
{
	LPWSTR buf = nullptr;
	FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		nullptr, err, 0, (LPWSTR)&buf, 0, nullptr);
	QString s = buf ? QString::fromWCharArray(buf).trimmed() :
			QString("error %1").arg(err);
	LocalFree(buf);
	return s;
}

/* D: protected DACL (no inherited entries), OWNER RIGHTS (S-1-3-4) full
 * control only */
static const wchar_t ownerOnlySddl[] = L"D:P(A;;FA;;;OW)";

/* rule 10: the DACL is protected and has one entry; from the open handle
 * (h) or the path */
static bool ownerOnlyAcl(HANDLE h, const QString &path)
{
	PSECURITY_DESCRIPTOR sd = nullptr;
	PACL dacl = nullptr;
	DWORD r = h != INVALID_HANDLE_VALUE ?
		GetSecurityInfo(h, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
			nullptr, nullptr, &dacl, nullptr, &sd) :
		GetNamedSecurityInfoW(
			(LPCWSTR)QDir::toNativeSeparators(path).utf16(),
			SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr,
			nullptr, &dacl, nullptr, &sd);
	SECURITY_DESCRIPTOR_CONTROL ctl = 0;
	DWORD rev = 0;
	bool ok = r == ERROR_SUCCESS && dacl && dacl->AceCount == 1 &&
		GetSecurityDescriptorControl(sd, &ctl, &rev) &&
		(ctl & SE_DACL_PROTECTED);
	if (sd)
		LocalFree(sd);
	return ok;
}

void StagedFile::stage(const QByteArray &data)
{
	if (staged || published)
		throw errorEx(QObject::tr("StagedFile: '%1' staged twice")
			.arg(targetPath));
	checkTarget(targetPath, replace);

	SECURITY_ATTRIBUTES sa{};
	PSECURITY_DESCRIPTOR sd = nullptr;
	sa.nLength = sizeof(sa);
	if (secret) {
		if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
				ownerOnlySddl, SDDL_REVISION_1, &sd, nullptr))
			throw failed(QObject::tr("Preparing the ACL of"),
				targetPath, sysError(GetLastError()));
		sa.lpSecurityDescriptor = sd;
	}
	HANDLE h = INVALID_HANDLE_VALUE;
	for (int tries = 0; h == INVALID_HANDLE_VALUE && tries < 8; tries++) {
		tempPath = tempName(targetPath);
		fault(create);
		h = CreateFileW((LPCWSTR)QDir::toNativeSeparators(tempPath).utf16(),
			GENERIC_WRITE | READ_CONTROL, 0, &sa, CREATE_NEW,
			FILE_ATTRIBUTE_NORMAL, nullptr);
		if (h == INVALID_HANDLE_VALUE &&
		    GetLastError() != ERROR_FILE_EXISTS) {
			DWORD err = GetLastError();
			if (sd)
				LocalFree(sd);
			throw failed(QObject::tr("Creating"), tempPath,
					sysError(err));
		}
	}
	if (sd)
		LocalFree(sd);
	if (h == INVALID_HANDLE_VALUE)
		throw failed(QObject::tr("Creating"), tempPath,
				sysError(ERROR_FILE_EXISTS));
	staged = true;
	try {
		/* rule 10 before the commit (review of xca#62) */
		if (secret && (injected(owner_check) ||
		    !ownerOnlyAcl(h, tempPath)))
			throw notOwnerOnly(targetPath, QObject::tr(
				"a new file in this directory gets no "
				"owner-only ACL"));
		const char *p = data.constData();
		qint64 left = data.size();
		while (left > 0) {
			fault(write);
			DWORD n = 0;
			if (!WriteFile(h, p, (DWORD)qMin<qint64>(left, 1 << 20),
					&n, nullptr) || n == 0)
				throw failed(QObject::tr("Writing"), tempPath,
					sysError(GetLastError()));
			p += n;
			left -= n;
		}
		fault(sync);
		if (!FlushFileBuffers(h))
			throw failed(QObject::tr("Syncing"), tempPath,
					sysError(GetLastError()));
		HANDLE hc = h;
		h = INVALID_HANDLE_VALUE;
		CloseHandle(hc);
	} catch (...) {
		if (h != INVALID_HANDLE_VALUE)
			CloseHandle(h);
		removeTemp();
		throw;
	}
	bytes = data.size();
}

void StagedFile::publish()
{
	if (!staged || published)
		throw errorEx(QObject::tr("StagedFile: '%1' is not staged")
			.arg(targetPath));
	fault(publish_step);
	DWORD flags = MOVEFILE_WRITE_THROUGH;
	if (replace)
		flags |= MOVEFILE_REPLACE_EXISTING;
	if (!MoveFileExW((LPCWSTR)QDir::toNativeSeparators(tempPath).utf16(),
			(LPCWSTR)QDir::toNativeSeparators(targetPath).utf16(),
			flags)) {
		DWORD err = GetLastError();
		if (err == ERROR_ALREADY_EXISTS || err == ERROR_FILE_EXISTS)
			throw serviceError("file_exists", QObject::tr(
				"'%1' exists; it is replaced only with --force")
				.arg(QDir::toNativeSeparators(targetPath)));
		throw failed(QObject::tr("Renaming to"), targetPath,
				sysError(err));
	}
	published = true;
	staged = false;

	/* rule 10: the DACL moved with the file and is still protected;
	 * a secret without it is removed again (review of xca#62) */
	if (!secret && !injected(recheck))
		return;
	if (injected(recheck) || !ownerOnlyAcl(INVALID_HANDLE_VALUE,
						targetPath)) {
		if (DeleteFileW((LPCWSTR)QDir::toNativeSeparators(targetPath)
				.utf16()))
			published = false;
		throw notOwnerOnly(targetPath, QObject::tr(
			"no owner-only ACL after writing"));
	}
}

#endif

/* --- StagedDirectory ----------------------------------------------------- */

StagedDirectory::StagedDirectory(const QString &target, bool replaceTarget)
	: givenPath(QDir::cleanPath(QFileInfo(target).absoluteFilePath())),
	  replace(replaceTarget)
{
	QString canonical = QFileInfo(target).canonicalFilePath();
	targetPath = canonical.isEmpty() ? givenPath : canonical;
}

StagedDirectory::~StagedDirectory()
{
	removeTemp();
}

void StagedDirectory::removeTemp()
{
	if (staged && !published && !tempPath.isEmpty())
		QDir(tempPath).removeRecursively();
	staged = false;
}

void StagedDirectory::discard()
{
	removeTemp();
}

void StagedDirectory::checkTarget(const QString &target,
			const QString &marker, bool replaceTarget)
{
	QString native = QDir::toNativeSeparators(target);
	QFileInfo t(QFileInfo(target).canonicalFilePath());
	if (t.filePath().isEmpty() || !t.isDir())
		throw serviceError("invalid_output", QObject::tr(
			"The output directory '%1' does not exist").arg(native));
	QFileInfo parent(t.absolutePath());
	if (t.isRoot() || !parent.isWritable())
		throw serviceError("invalid_output", QObject::tr(
			"The directory above '%1' is not writable; the new "
			"content is prepared there and swapped in").arg(native));
#if !defined(Q_OS_WIN)
	struct stat st, pst;
	if (::stat(QFile::encodeName(t.filePath()).constData(), &st) == 0 &&
	    ::stat(QFile::encodeName(parent.filePath()).constData(),
		    &pst) == 0 && st.st_dev != pst.st_dev)
		throw serviceError("invalid_output", QObject::tr(
			"'%1' is a mount point and cannot be replaced as a "
			"whole; give a directory below it").arg(native));
#endif
	QStringList content = QDir(t.filePath()).entryList(QDir::AllEntries |
			QDir::Hidden | QDir::System | QDir::NoDotAndDotDot);
	if (content.isEmpty())
		return;
	if (!QFileInfo(QDir(t.filePath()).filePath(marker)).isFile())
		throw serviceError("invalid_output", QObject::tr(
			"'%1' holds files of something else (no %2); its "
			"content would be replaced as a whole: give an empty "
			"directory").arg(native, marker));
	if (!replaceTarget)
		throw serviceError("file_exists", QObject::tr(
			"'%1' holds an earlier export; it is replaced only with "
			"--force").arg(native));
}

void StagedDirectory::stage(const QString &marker)
{
	if (staged || published)
		throw errorEx(QObject::tr("StagedDirectory: '%1' staged twice")
			.arg(targetPath));
	checkTarget(givenPath, marker, replace);
	for (int tries = 0; tries < 8; tries++) {
		QString t = tempName(targetPath);
		if (QFileInfo::exists(t))
			continue;
		if (!QDir().mkdir(t))
			throw failed(QObject::tr("Creating"), t,
				QObject::tr("the directory cannot be created"));
		tempPath = t;
		staged = true;
		return;
	}
	throw failed(QObject::tr("Creating"), targetPath,
		QObject::tr("no free temporary name"));
}

bool StagedDirectory::contains(const QString &path) const
{
	QString p = QDir::cleanPath(QFileInfo(path).absoluteFilePath());
	for (const QString &d : { givenPath, targetPath })
		if (p == d || p.startsWith(d + "/"))
			return true;
	return false;
}

QString StagedDirectory::stagedPath(const QString &path) const
{
	QString p = QDir::cleanPath(QFileInfo(path).absoluteFilePath());
	for (const QString &d : { givenPath, targetPath }) {
		if (p == d)
			return tempPath;
		if (p.startsWith(d + "/"))
			return tempPath + p.mid(d.size());
	}
	return QString();
}

void StagedDirectory::publish()
{
	if (!staged || published)
		throw errorEx(QObject::tr("StagedDirectory: '%1' is not staged")
			.arg(targetPath));
	if (StagedFile::faultHook &&
	    StagedFile::faultHook(StagedFile::publish_step, targetPath))
		throw failed(QObject::tr("Swapping in"), targetPath,
			QObject::tr("injected fault (test)"));
	QString old;
#if defined(RENAME_EXCHANGE)
	/* one step: the sibling becomes the target, the target the sibling */
	if (::renameat2(AT_FDCWD, QFile::encodeName(tempPath).constData(),
			AT_FDCWD, QFile::encodeName(targetPath).constData(),
			RENAME_EXCHANGE) == 0)
		old = tempPath;
	else if (errno != EINVAL && errno != ENOSYS && errno != ENOTSUP)
		throw failed(QObject::tr("Swapping in"), targetPath,
				sysError(errno));
#endif
	if (old.isEmpty()) {
		/* two steps: for a moment the target is absent */
		old = tempPath + ".old";
		if (!QDir().rename(targetPath, old))
			throw failed(QObject::tr("Moving aside"), targetPath,
				QObject::tr("rename failed"));
		if (!QDir().rename(tempPath, targetPath)) {
			QDir().rename(old, targetPath);
			throw failed(QObject::tr("Swapping in"), targetPath,
				QObject::tr("rename failed"));
		}
	}
	published = true;
	staged = false;
	/* the old content; best effort, the new one is in place */
	if (!QDir(old).removeRecursively())
		qWarning("'%s' could not be removed completely",
			QFile::encodeName(old).constData());
}
