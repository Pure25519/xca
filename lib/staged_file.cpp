/* vi: set sw=4 ts=4:
 *
 * Staged, atomic, owner-only file output (BTD-42, BTD-210), see
 * staged_file.h.
 *
 * The POSIX path is built and tested on Linux. The Windows path (protected
 * DACL with OWNER RIGHTS only, CreateFileW CREATE_NEW, FlushFileBuffers,
 * MoveFileExW) is written for BTD-13 and NOT yet compiled or tested; it is
 * still path based (no handle-relative steps, no clean-up of temporary
 * files of earlier runs).
 */

#include "staged_file.h"

#include <algorithm>
#include <cerrno>
#include <cstring>

#include <QCryptographicHash>
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QObject>
#include <QRandomGenerator>
#include <QRegularExpression>
#include <QSet>

#include "exception.h"

#if defined(Q_OS_WIN)
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#else
#include <cstdio>
#include <ctime>
#include <dirent.h>
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
	case swap: return "swap";
	case probe: return "probe";
	case noreplace: return "noreplace";
	case unlink_temp: return "unlink";
	}
	return "unknown";
}

static QString native(const QString &path)
{
	return QDir::toNativeSeparators(path);
}

static serviceError failed(const QString &what, const QString &path,
			const QString &why)
{
	return serviceError("write_failed", QObject::tr("%1 '%2' failed: %3")
		.arg(what, native(path), why));
}

/* BTD-210 c: a directory of the path was renamed, or replaced by another
 * directory or a symbolic link, since stage() opened it */
static serviceError directoryChanged(const QString &dir)
{
	return serviceError("target_directory_changed", QObject::tr(
		"The output directory '%1' was moved or replaced (by another "
		"directory or a symbolic link) while the output was prepared; "
		"nothing was written to it").arg(native(dir)));
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
		.arg(native(path), why));
}

static serviceError exists(const QString &path)
{
	return serviceError("file_exists", QObject::tr(
		"'%1' exists; it is replaced only with --force")
		.arg(native(path)));
}

StagedFile::StagedFile(const QString &target, bool secretFile,
			bool replaceTarget)
	: targetPath(QFileInfo(target).absoluteFilePath()),
	  secret(secretFile), replace(replaceTarget)
{
	targetName = QFileInfo(targetPath).fileName();
}

StagedFile::~StagedFile()
{
	removeTemp();
	closeDirectory();
}

void StagedFile::discard()
{
	removeTemp();
}

void StagedFile::checkTarget(const QString &target, bool replaceTarget)
{
	QFileInfo t(QFileInfo(target).absoluteFilePath());
	QFileInfo dir(t.absolutePath());

	if (!dir.exists() || !dir.isDir())
		throw serviceError("invalid_output", QObject::tr(
			"The output directory '%1' does not exist")
			.arg(native(dir.filePath())));
	if (!dir.isWritable())
		throw serviceError("invalid_output", QObject::tr(
			"The output directory '%1' is not writable")
			.arg(native(dir.filePath())));
	/* also a dangling symbolic link exists as a name */
	if (t.exists() || t.isSymLink()) {
		if (!replaceTarget)
			throw exists(t.filePath());
		if (t.isDir() || (!t.isFile() && !t.isSymLink()))
			throw serviceError("invalid_output", QObject::tr(
				"'%1' is not a regular file")
				.arg(native(t.filePath())));
	}
}

void StagedFile::writeFile(const QString &target, const QByteArray &data,
			bool secretFile, bool replaceTarget)
{
	StagedFile f(target, secretFile, replaceTarget);
	f.stage(data);
	f.publish();
}

/* The length that counts against the limit of a file name: bytes on POSIX
 * (NAME_MAX), UTF-16 units on Windows */
static int nameLength(const QString &name)
{
#if defined(Q_OS_WIN)
	return name.size();
#else
	return QFile::encodeName(name).size();
#endif
}

/* ".<name>.bxc-tmp-<16 hex>"; where that is longer than a file name may be
 * (255), a prefix of the name and the first 16 hex digits of the SHA-256
 * of the whole name stand for it (BTD-210 d), so a long target name still
 * gets a temporary file of the form the clean-up looks for */
static QString temporaryName(const QString &name)
{
	QString random = QString(".bxc-tmp-%1").arg(
		QRandomGenerator::system()->generate64(), 16, 16, QChar('0'));
	if (nameLength("." + name + random) <= 255)
		return "." + name + random;
	QString hash = QString::fromLatin1(QCryptographicHash::hash(
		name.toUtf8(), QCryptographicHash::Sha256).toHex().left(16));
	QString prefix = name;
	while (!prefix.isEmpty() &&
	       (nameLength("." + prefix + "-" + hash + random) > 255 ||
		prefix.back().isHighSurrogate()))
		prefix.chop(1);
	return "." + prefix + "-" + hash + random;
}

void StagedFile::tempLeft(const QString &path)
{
	warns << warning("temp_file_left", QObject::tr(
		"The temporary file '%1' of '%2' could not be removed; it holds "
		"the content of the file (for a key file: the private key): "
		"remove it").arg(native(path), native(targetPath)));
}

#if !defined(Q_OS_WIN)

static QString sysError(int err)
{
	return QString::fromLocal8Bit(strerror(err));
}

/* What stage() removes after staleSeconds: a temporary file of a killed
 * run, whatever its target */
static const QRegularExpression tempPattern(
	"^\\..+\\.bxc-tmp-[0-9a-f]{16}$");
static const int staleSeconds = 600;

/* A descriptor that is closed when it goes out of scope */
class Fd
{
  public:
	int fd;
	explicit Fd(int f) : fd(f) { }
	~Fd()
	{
		if (fd >= 0)
			::close(fd);
	}
	Fd(const Fd &) = delete;
	Fd &operator=(const Fd &) = delete;
};

/* BTD-210 c: a canonical directory path (no symbolic link, no "..")
 * opened from "/" one component at a time with O_NOFOLLOW, so a component
 * that became a symbolic link since it was canonicalised is refused (ELOOP
 * or ENOTDIR) instead of followed. The directory itself is opened for
 * reading (fsync, readdir), unless pathOnly. -1 and errno on failure. */
static int openCanonical(const QString &canonical, bool pathOnly)
{
#if defined(O_PATH)
	const int walk = O_PATH;
#else
	const int walk = O_RDONLY;
#endif
	QList<QByteArray> parts;
	for (const QByteArray &p : QFile::encodeName(canonical).split('/'))
		if (!p.isEmpty())
			parts << p;
	int fd = ::open("/", (parts.isEmpty() && !pathOnly ? O_RDONLY : walk) |
			O_DIRECTORY | O_CLOEXEC);
	for (int i = 0; fd >= 0 && i < parts.size(); i++) {
		int mode = i == parts.size() - 1 && !pathOnly ? O_RDONLY : walk;
		int next = ::openat(fd, parts[i].constData(), mode |
				O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
		int err = errno;
		::close(fd);
		fd = next;
		errno = err;
	}
	return fd;
}

/* The path still leads to the directory of fd */
static bool sameCanonical(int fd, const QString &canonical)
{
	Fd now(openCanonical(canonical, true));
	struct stat a, b;
	return now.fd >= 0 && fstat(now.fd, &a) == 0 && fstat(fd, &b) == 0 &&
		a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}

/* The names in the directory dfd, without "." and ".." */
static QList<QByteArray> entries(int dfd)
{
	QList<QByteArray> l;
	int fd = ::openat(dfd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	DIR *d = fd >= 0 ? fdopendir(fd) : nullptr;
	if (!d) {
		if (fd >= 0)
			::close(fd);
		return l;
	}
	while (struct dirent *e = readdir(d)) {
		QByteArray n(e->d_name);
		if (n != "." && n != "..")
			l << n;
	}
	closedir(d);
	return l;
}

void StagedFile::openDirectory()
{
	QString dir = QFileInfo(targetPath).absolutePath();
	dirPath = QFileInfo(dir).canonicalFilePath();
	if (dirPath.isEmpty())
		throw directoryChanged(dir);
	dirFd = openCanonical(dirPath, false);
	if (dirFd < 0) {
		int err = errno;
		if (err == ELOOP || err == ENOTDIR || err == ENOENT)
			throw directoryChanged(dir);
		throw failed(QObject::tr("Opening"), dirPath, sysError(err));
	}
}

void StagedFile::closeDirectory()
{
	if (dirFd >= 0)
		::close(dirFd);
	dirFd = -1;
}

bool StagedFile::sameDirectory() const
{
	return sameCanonical(dirFd, dirPath);
}

void StagedFile::removeTemp()
{
	if (staged && !published && dirFd >= 0 && !tempName.isEmpty())
		::unlinkat(dirFd, QFile::encodeName(tempName).constData(), 0);
	staged = false;
}

/* BTD-210 b: temporary files of killed runs (possibly plaintext keys) of
 * this user, regular files older than staleSeconds; a younger one may
 * belong to a run that is still going */
void StagedFile::removeStale()
{
	time_t limit = time(nullptr) - staleSeconds;
	QStringList removed;
	for (const QByteArray &n : entries(dirFd)) {
		QString name = QFile::decodeName(n);
		struct stat st;
		if (!tempPattern.match(name).hasMatch() ||
		    fstatat(dirFd, n.constData(), &st, AT_SYMLINK_NOFOLLOW) != 0 ||
		    !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
		    st.st_mtime > limit)
			continue;
		if (::unlinkat(dirFd, n.constData(), 0) == 0)
			removed << name;
	}
	if (removed.isEmpty())
		return;
	removed.sort();
	warns << warning("stale_temp_removed", QObject::tr(
		"Temporary files of earlier runs (older than 10 minutes) were "
		"removed from '%1': %2").arg(native(dirPath),
		removed.join(", ")));
}

/* BTD-210 a: the publish without replacing, tried before the commit with
 * the temporary file itself: renameat2(RENAME_NOREPLACE) to a second
 * temporary name (the file keeps it), or, where the file system rejects
 * that flag (EINVAL), link() to a second name that is removed again. A
 * directory where neither works (vfat with link(), SMB, FUSE) would
 * leave a stored object without its file after the commit: refused. */
void StagedFile::probePublish()
{
	if (injected(probe))
		throw serviceError("target_filesystem_unsupported", QObject::tr(
			"The file system of the output directory '%1' cannot "
			"publish a file without replacing an existing one: "
			"injected fault (test); nothing was stored")
			.arg(native(dirPath)));
	QString next = temporaryName(targetName);
	QByteArray from = QFile::encodeName(tempName);
	QByteArray to = QFile::encodeName(next);
	int err = EINVAL;
#if defined(RENAME_NOREPLACE)
	if (!injected(noreplace)) {
		if (::renameat2(dirFd, from.constData(), dirFd, to.constData(),
				RENAME_NOREPLACE) == 0) {
			tempName = next;
			tempPath = dirPath + "/" + next;
			useLink = false;
			return;
		}
		err = errno;
	}
#endif
	if (err != EINVAL && err != ENOSYS && err != ENOTSUP)
		throw failed(QObject::tr("Renaming"), tempPath, sysError(err));
	if (::linkat(dirFd, from.constData(), dirFd, to.constData(), 0) != 0) {
		err = errno;
		throw serviceError("target_filesystem_unsupported", QObject::tr(
			"The file system of the output directory '%1' cannot "
			"publish a file without replacing an existing one: "
			"neither renameat2(RENAME_NOREPLACE) nor link() works "
			"there (%2); nothing was stored. Choose a directory on a "
			"local file system, or give --force (an existing file is "
			"then replaced)").arg(native(dirPath), sysError(err)));
	}
	if (::unlinkat(dirFd, to.constData(), 0) != 0)
		tempLeft(dirPath + "/" + next);
	useLink = true;
}

void StagedFile::stage(const QByteArray &data)
{
	if (staged || published)
		throw errorEx(QObject::tr("StagedFile: '%1' staged twice")
			.arg(targetPath));
	checkTarget(targetPath, replace);
	openDirectory();
	removeStale();

	int fd = -1;
	for (int tries = 0; fd < 0 && tries < 8; tries++) {
		tempName = temporaryName(targetName);
		tempPath = dirPath + "/" + tempName;
		fault(create);
		/* the mode is the one of the creation: a secret is never
		 * readable by others, not even for a moment */
		fd = ::openat(dirFd, QFile::encodeName(tempName).constData(),
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
		if (!replace)
			probePublish();
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

void StagedFile::publish()
{
	if (!staged || published)
		throw errorEx(QObject::tr("StagedFile: '%1' is not staged")
			.arg(targetPath));
	QByteArray tmp = QFile::encodeName(tempName);
	QByteArray dst = QFile::encodeName(targetName);

	fault(publish_step);
	/* every step is relative to the directory of stage(); one that
	 * is no longer at its path gets nothing (BTD-210 c) */
	if (!sameDirectory())
		throw directoryChanged(QFileInfo(targetPath).absolutePath());
	if (replace) {
		if (::renameat(dirFd, tmp.constData(), dirFd,
				dst.constData()) != 0)
			throw failed(QObject::tr("Renaming to"), targetPath,
					sysError(errno));
	} else {
		/* neither way replaces: a target created after stage() is
		 * not overwritten either */
		bool viaLink = useLink || injected(noreplace);
#if defined(RENAME_NOREPLACE)
		if (!viaLink && ::renameat2(dirFd, tmp.constData(), dirFd,
				dst.constData(), RENAME_NOREPLACE) != 0) {
			int err = errno;
			if (err == EEXIST)
				throw exists(targetPath);
			if (err != EINVAL)
				throw failed(QObject::tr("Renaming to"),
						targetPath, sysError(err));
			viaLink = true;
		}
#else
		viaLink = true;
#endif
		if (viaLink) {
			if (::linkat(dirFd, tmp.constData(), dirFd,
					dst.constData(), 0) != 0) {
				int err = errno;
				if (err == EEXIST)
					throw exists(targetPath);
				throw failed(QObject::tr("Linking to"),
						targetPath, sysError(err));
			}
			if (injected(unlink_temp) ||
			    ::unlinkat(dirFd, tmp.constData(), 0) != 0)
				tempLeft(tempPath);
		}
	}
	published = true;
	staged = false;
	/* best effort: some file systems refuse fsync on a directory */
	(void)fsync(dirFd);

	/* rule 10: the published secret is owner-only and ours; one that
	 * is not is removed again (review of xca#62), not left readable */
	struct stat st;
	QString why;
	if (injected(recheck))
		why = QObject::tr("injected fault (test)");
	else if (fstatat(dirFd, dst.constData(), &st,
			AT_SYMLINK_NOFOLLOW) != 0)
		why = sysError(errno);
	else if (!S_ISREG(st.st_mode) || (secret && ((st.st_mode & 077) != 0 ||
		 st.st_uid != geteuid())))
		why = QObject::tr("not an owner-only regular file after "
			"writing (mode %1)").arg(st.st_mode & 07777, 4, 8,
			QChar('0'));
	if (!why.isEmpty()) {
		if (::unlinkat(dirFd, dst.constData(), 0) == 0)
			published = false;
		(void)fsync(dirFd);
		closeDirectory();
		throw notOwnerOnly(targetPath, why);
	}
	closeDirectory();
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

void StagedFile::removeTemp()
{
	if (staged && !published && !tempPath.isEmpty())
		QFile::remove(tempPath);
	staged = false;
}

void StagedFile::closeDirectory()
{
}

/* D: protected DACL (no inherited entries), OWNER RIGHTS (S-1-3-4) full
 * control only */
static const wchar_t ownerOnlySddl[] = L"D:P(A;;FA;;;OW)";

/* The SID of the user of this process' token equals sid */
static bool isTokenUser(PSID sid)
{
	HANDLE tok = nullptr;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok))
		return false;
	DWORD len = 0;
	GetTokenInformation(tok, TokenUser, nullptr, 0, &len);
	QByteArray buf(len ? (int)len : 1, '\0');
	bool ok = len > 0 && GetTokenInformation(tok, TokenUser, buf.data(),
			len, &len) &&
		EqualSid(((TOKEN_USER *)buf.data())->User.Sid, sid);
	CloseHandle(tok);
	return ok;
}

/* rule 10 (BTD-210 d): the DACL is protected and has exactly one entry,
 * an ACCESS_ALLOWED_ACE with full control (FILE_ALL_ACCESS or GENERIC_ALL)
 * for OWNER RIGHTS (S-1-3-4) or the owner of the file, and that owner is
 * the user of this process; from the open handle (h) or the path */
static bool ownerOnlyAcl(HANDLE h, const QString &path)
{
	const SECURITY_INFORMATION si = DACL_SECURITY_INFORMATION |
					OWNER_SECURITY_INFORMATION;
	PSECURITY_DESCRIPTOR sd = nullptr;
	PSID owner = nullptr;
	PACL dacl = nullptr;
	DWORD r = h != INVALID_HANDLE_VALUE ?
		GetSecurityInfo(h, SE_FILE_OBJECT, si, &owner, nullptr,
			&dacl, nullptr, &sd) :
		GetNamedSecurityInfoW((LPCWSTR)native(path).utf16(),
			SE_FILE_OBJECT, si, &owner, nullptr, &dacl, nullptr,
			&sd);
	SECURITY_DESCRIPTOR_CONTROL ctl = 0;
	DWORD rev = 0;
	ACCESS_ALLOWED_ACE *ace = nullptr;
	BYTE ownerRights[SECURITY_MAX_SID_SIZE];
	DWORD orLen = sizeof(ownerRights);
	bool ok = r == ERROR_SUCCESS && dacl && owner &&
		dacl->AceCount == 1 &&
		GetSecurityDescriptorControl(sd, &ctl, &rev) &&
		(ctl & SE_DACL_PROTECTED) &&
		GetAce(dacl, 0, (LPVOID *)&ace) &&
		ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE &&
		(ace->Mask == FILE_ALL_ACCESS || ace->Mask == GENERIC_ALL) &&
		CreateWellKnownSid(WinCreatorOwnerRightsSid, nullptr,
			ownerRights, &orLen) &&
		(EqualSid((PSID)&ace->SidStart, (PSID)ownerRights) ||
		 EqualSid((PSID)&ace->SidStart, owner)) &&
		isTokenUser(owner);
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
	dirPath = QFileInfo(targetPath).absolutePath();

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
		tempName = temporaryName(targetName);
		tempPath = dirPath + "/" + tempName;
		fault(create);
		h = CreateFileW((LPCWSTR)native(tempPath).utf16(),
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
	if (!MoveFileExW((LPCWSTR)native(tempPath).utf16(),
			(LPCWSTR)native(targetPath).utf16(), flags)) {
		DWORD err = GetLastError();
		if (err == ERROR_ALREADY_EXISTS || err == ERROR_FILE_EXISTS)
			throw exists(targetPath);
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
		if (DeleteFileW((LPCWSTR)native(targetPath).utf16()))
			published = false;
		throw notOwnerOnly(targetPath, QObject::tr(
			"no owner-only ACL after writing"));
	}
}

#endif

/* --- StagedDirectory ----------------------------------------------------- */

StagedDirectory::StagedDirectory(const QString &target,
			const QString &markerName, const QString &markerSchema,
			bool replaceTarget)
	: givenPath(QDir::cleanPath(QFileInfo(target).absoluteFilePath())),
	  marker(markerName), schema(markerSchema), replace(replaceTarget)
{
	QString canonical = QFileInfo(target).canonicalFilePath();
	targetPath = canonical.isEmpty() ? givenPath : canonical;
}

StagedDirectory::~StagedDirectory()
{
	removeTemp();
#if !defined(Q_OS_WIN)
	if (parentFd >= 0)
		::close(parentFd);
#endif
}

void StagedDirectory::discard()
{
	removeTemp();
}

/* The directories above the relative paths, deepest first */
static QStringList parents(const QStringList &paths)
{
	QSet<QString> dirs;
	for (const QString &p : paths)
		for (QString d = QFileInfo(p).path(); d != "." && !d.isEmpty();
		     d = QFileInfo(d).path())
			dirs << d;
	QStringList l = dirs.values();
	std::sort(l.begin(), l.end(), [](const QString &a, const QString &b) {
		return a.count('/') > b.count('/') ||
			(a.count('/') == b.count('/') && a < b);
	});
	return l;
}

static serviceError foreign(const QString &native, const QString &why)
{
	return serviceError("invalid_output", QObject::tr(
		"'%1' holds something other than an earlier export "
		"(%2); its content would be replaced as a whole: give "
		"an empty directory").arg(native, why));
}

/* The paths an earlier export lists in its manifest (json), the marker
 * first; a manifest of something else is foreign */
static QStringList manifestPaths(const QByteArray &json,
		const QString &native, const QString &markerName,
		const QString &markerSchema)
{
	QJsonDocument doc = QJsonDocument::fromJson(json);
	if (!doc.isObject() ||
	    doc.object().value("schema").toString() != markerSchema)
		throw foreign(native, QObject::tr("%1 is no %2").arg(markerName,
						markerSchema));
	QStringList known { markerName };
	for (const QJsonValue &v : doc.object().value("entries").toArray()) {
		QString p = QDir::cleanPath(v.toObject().value("path")
						.toString());
		if (p.isEmpty() || p == "." || p == ".." ||
		    p.startsWith("../") || QDir::isAbsolutePath(p))
			throw foreign(native, QObject::tr(
				"%1 lists the path '%2'").arg(markerName, p));
		if (!known.contains(p))
			known << p;
	}
	return known;
}

#if !defined(Q_OS_WIN)

/* Every entry below the directory dfd (rel: its path relative to the
 * target) is a directory of dirs or a regular file of known; symbolic
 * links and anything else are foreign. Never follows a link. */
static void checkEntries(int dfd, const QString &rel,
		const QStringList &known, const QStringList &dirs,
		const QString &native)
{
	for (const QByteArray &n : entries(dfd)) {
		QString r = (rel.isEmpty() ? QString() : rel + "/") +
				QFile::decodeName(n);
		struct stat st;
		if (fstatat(dfd, n.constData(), &st, AT_SYMLINK_NOFOLLOW) != 0) {
			int err = errno;
			throw foreign(native, QObject::tr("'%1': %2").arg(r,
					sysError(err)));
		}
		if (S_ISDIR(st.st_mode) && dirs.contains(r)) {
			Fd sub(::openat(dfd, n.constData(), O_RDONLY |
				O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
			if (sub.fd < 0) {
				int err = errno;
				throw foreign(native, QObject::tr("'%1': %2")
					.arg(r, sysError(err)));
			}
			checkEntries(sub.fd, r, known, dirs, native);
		} else if (!S_ISREG(st.st_mode) || !known.contains(r)) {
			throw foreign(native, QObject::tr(
				"'%1' is not part of it").arg(r));
		}
	}
}

/* The target name in the directory parentFd: a directory (not a link),
 * not a mount point, empty or exactly an earlier export; its entries (see
 * checkTarget()) and its identity (st) */
static QStringList checkAt(int parentFd, const QString &name,
		const QString &native, const QString &markerName,
		const QString &markerSchema, bool replaceTarget, struct stat *st)
{
	Fd t(::openat(parentFd, QFile::encodeName(name).constData(),
		O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
	if (t.fd < 0) {
		int err = errno;
		if (err == ELOOP || err == ENOTDIR || err == ENOENT)
			throw directoryChanged(native);
		throw failed(QObject::tr("Opening"), native, sysError(err));
	}
	struct stat pst;
	if (fstat(t.fd, st) != 0 || fstat(parentFd, &pst) != 0)
		throw failed(QObject::tr("Checking"), native, sysError(errno));
	if (st->st_dev != pst.st_dev)
		throw serviceError("invalid_output", QObject::tr(
			"'%1' is a mount point and cannot be replaced as a "
			"whole; give a directory below it").arg(native));
	if (entries(t.fd).isEmpty())
		return QStringList();

	/* only an earlier export of this kind is replaced: its manifest,
	 * not just a file of that name, and nothing but its entries;
	 * O_NONBLOCK: a FIFO of that name does not block the check */
	Fd mf(::openat(t.fd, QFile::encodeName(markerName).constData(),
		O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC));
	struct stat mst;
	if (mf.fd < 0 || fstat(mf.fd, &mst) != 0 || !S_ISREG(mst.st_mode) ||
	    mst.st_size > (16 << 20))
		throw foreign(native, QObject::tr("no %1").arg(markerName));
	QByteArray json;
	char buf[65536];
	ssize_t n;
	while ((n = ::read(mf.fd, buf, sizeof(buf))) != 0) {
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0 || json.size() + n > (16 << 20))
			throw foreign(native, QObject::tr("%1 unreadable")
				.arg(markerName));
		json.append(buf, n);
	}
	QStringList known = manifestPaths(json, native, markerName,
					markerSchema);
	checkEntries(t.fd, QString(), known, parents(known), native);
	if (!replaceTarget)
		throw serviceError("file_exists", QObject::tr(
			"'%1' holds an earlier export; it is replaced only with "
			"--force").arg(native));
	return known;
}

/* The checks of checkTarget(); the canonical target, the directory above
 * it opened (parentFd, -1 when not wanted: closed) and the identity of
 * the target (st) */
static QStringList checkDirectory(const QString &target,
		const QString &markerName, const QString &markerSchema,
		bool replaceTarget, QString *canonical, int *parentFd,
		struct stat *st)
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
	Fd p(openCanonical(parent.filePath(), false));
	if (p.fd < 0) {
		int err = errno;
		if (err == ELOOP || err == ENOTDIR || err == ENOENT)
			throw directoryChanged(native);
		throw failed(QObject::tr("Opening"), parent.filePath(),
				sysError(err));
	}
	QStringList known = checkAt(p.fd, t.fileName(), native, markerName,
			markerSchema, replaceTarget, st);
	*canonical = t.filePath();
	if (parentFd) {
		*parentFd = p.fd;
		p.fd = -1;
	}
	return known;
}

QStringList StagedDirectory::checkTarget(const QString &target,
			const QString &markerName, const QString &markerSchema,
			bool replaceTarget)
{
	QString canonical;
	struct stat st;
	return checkDirectory(target, markerName, markerSchema,
			replaceTarget, &canonical, nullptr, &st);
}

/* name in dfd and everything below it, never following a link */
static void removeTree(int dfd, const QByteArray &name)
{
	{
		Fd d(::openat(dfd, name.constData(), O_RDONLY | O_DIRECTORY |
			O_NOFOLLOW | O_CLOEXEC));
		for (const QByteArray &n : d.fd >= 0 ? entries(d.fd) :
				QList<QByteArray>()) {
			struct stat st;
			if (fstatat(d.fd, n.constData(), &st,
					AT_SYMLINK_NOFOLLOW) == 0 &&
			    S_ISDIR(st.st_mode))
				removeTree(d.fd, n);
			else
				::unlinkat(d.fd, n.constData(), 0);
		}
	}
	::unlinkat(dfd, name.constData(), AT_REMOVEDIR);
}

/* rel (a path below root): its last component removed from the
 * directory above it, which is reached without following a link */
static void removeBelow(int root, const QString &rel, bool dir)
{
	QList<QByteArray> parts = QFile::encodeName(rel).split('/');
	QByteArray last = parts.takeLast();
	Fd d(::dup(root));
	for (const QByteArray &p : parts) {
		int next = d.fd < 0 ? -1 : ::openat(d.fd, p.constData(),
			O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
		::close(d.fd);
		d.fd = next;
	}
	if (d.fd >= 0)
		::unlinkat(d.fd, last.constData(), dir ? AT_REMOVEDIR : 0);
}

void StagedDirectory::removeTemp()
{
	if (staged && !published && parentFd >= 0 && !tempName.isEmpty())
		removeTree(parentFd, QFile::encodeName(tempName));
	staged = false;
}

void StagedDirectory::stage()
{
	if (staged || published)
		throw errorEx(QObject::tr("StagedDirectory: '%1' staged twice")
			.arg(targetPath));
	QString canonical;
	struct stat st;
	checkDirectory(givenPath, marker, schema, replace, &canonical,
			&parentFd, &st);
	targetPath = canonical;
	targetDev = st.st_dev;
	targetIno = st.st_ino;
	parentPath = QFileInfo(canonical).absolutePath();
	targetName = QFileInfo(canonical).fileName();
	for (int tries = 0; tries < 8; tries++) {
		QString t = temporaryName(targetName);
		if (::mkdirat(parentFd, QFile::encodeName(t).constData(),
				0777) != 0) {
			if (errno == EEXIST)
				continue;
			throw failed(QObject::tr("Creating"), parentPath + "/" +
				t, sysError(errno));
		}
		tempName = t;
		tempPath = parentPath + "/" + t;
		staged = true;
		return;
	}
	throw failed(QObject::tr("Creating"), targetPath,
		QObject::tr("no free temporary name"));
}

void StagedDirectory::publish()
{
	if (!staged || published)
		throw errorEx(QObject::tr("StagedDirectory: '%1' is not staged")
			.arg(targetPath));
	if (StagedFile::faultHook &&
	    StagedFile::faultHook(StagedFile::swap, targetPath))
		throw failed(QObject::tr("Swapping in"), targetPath,
			QObject::tr("injected fault (test)"));
	/* again, after the commit, relative to the directory above of
	 * stage(), which must still be at its path: what changed since
	 * stage() is refused (also a target that is now another directory
	 * or a link), and only the entries found now are removed later */
	QString native = QDir::toNativeSeparators(givenPath);
	if (!sameCanonical(parentFd, parentPath))
		throw directoryChanged(native);
	struct stat st;
	QStringList known = checkAt(parentFd, targetName, native, marker,
			schema, replace, &st);
	if ((quint64)st.st_dev != targetDev || (quint64)st.st_ino != targetIno)
		throw directoryChanged(native);

	QByteArray tmp = QFile::encodeName(tempName);
	QByteArray dst = QFile::encodeName(targetName);
	QByteArray old;
#if defined(RENAME_EXCHANGE)
	/* one step: the sibling becomes the target, the target the sibling */
	if (::renameat2(parentFd, tmp.constData(), parentFd, dst.constData(),
			RENAME_EXCHANGE) == 0)
		old = tmp;
	else if (errno != EINVAL && errno != ENOSYS && errno != ENOTSUP)
		throw failed(QObject::tr("Swapping in"), targetPath,
				sysError(errno));
#endif
	if (old.isEmpty()) {
		/* two steps: for a moment the target is absent */
		old = tmp + ".old";
		if (::renameat(parentFd, dst.constData(), parentFd,
				old.constData()) != 0)
			throw failed(QObject::tr("Moving aside"), targetPath,
				sysError(errno));
		if (::renameat(parentFd, tmp.constData(), parentFd,
				dst.constData()) != 0) {
			int err = errno;
			if (::renameat(parentFd, old.constData(), parentFd,
					dst.constData()) == 0)
				throw failed(QObject::tr("Swapping in"),
					targetPath, QObject::tr("%1; the old "
					"content is back").arg(sysError(err)));
			QString o = parentPath + "/" + QFile::decodeName(old);
			throw failed(QObject::tr("Swapping in"), targetPath,
				QObject::tr("%1, and so did moving the old "
				"content back: it is in '%2', the new one in "
				"'%3'; move the one you want to '%4'")
				.arg(sysError(err), QDir::toNativeSeparators(o),
				QDir::toNativeSeparators(tempPath),
				QDir::toNativeSeparators(targetPath)));
		}
	}
	published = true;
	staged = false;
	(void)fsync(parentFd);

	/* the old content: the entries of the earlier export only */
	{
		Fd od(::openat(parentFd, old.constData(), O_RDONLY |
			O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
		if (od.fd >= 0) {
			for (const QString &f : known)
				removeBelow(od.fd, f, false);
			for (const QString &d : parents(known))
				removeBelow(od.fd, d, true);
		}
	}
	if (::unlinkat(parentFd, old.constData(), AT_REMOVEDIR) != 0)
		leftoverPath = parentPath + "/" + QFile::decodeName(old);
}

#else /* Q_OS_WIN: path based, NOT compiled or tested yet (BTD-13) */

QStringList StagedDirectory::checkTarget(const QString &target,
			const QString &markerName, const QString &markerSchema,
			bool replaceTarget)
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
	QDir dir(t.filePath());
	const QDir::Filters all = QDir::AllEntries | QDir::Hidden |
				QDir::System | QDir::NoDotAndDotDot;
	if (dir.entryList(all).isEmpty())
		return QStringList();

	QFileInfo mi(dir.filePath(markerName));
	QFile mf(mi.filePath());
	if (mi.isSymLink() || !mi.isFile() || mi.size() > (16 << 20) ||
	    !mf.open(QIODevice::ReadOnly))
		throw foreign(native, QObject::tr("no %1").arg(markerName));
	QStringList known = manifestPaths(mf.readAll(), native, markerName,
					markerSchema);
	QStringList dirs = parents(known);
	QDirIterator it(dir.path(), all, QDirIterator::Subdirectories);
	while (it.hasNext()) {
		it.next();
		QFileInfo i = it.fileInfo();
		QString rel = dir.relativeFilePath(i.filePath());
		bool ok = !i.isSymLink() && (i.isDir() ? dirs.contains(rel) :
				i.isFile() && known.contains(rel));
		if (!ok)
			throw foreign(native, QObject::tr(
				"'%1' is not part of it").arg(rel));
	}
	if (!replaceTarget)
		throw serviceError("file_exists", QObject::tr(
			"'%1' holds an earlier export; it is replaced only with "
			"--force").arg(native));
	return known;
}

void StagedDirectory::removeTemp()
{
	if (staged && !published && !tempPath.isEmpty())
		QDir(tempPath).removeRecursively();
	staged = false;
}

void StagedDirectory::stage()
{
	if (staged || published)
		throw errorEx(QObject::tr("StagedDirectory: '%1' staged twice")
			.arg(targetPath));
	checkTarget(givenPath, marker, schema, replace);
	QFileInfo t(targetPath);
	for (int tries = 0; tries < 8; tries++) {
		QString p = t.absolutePath() + "/" +
				temporaryName(t.fileName());
		if (QFileInfo::exists(p))
			continue;
		if (!QDir().mkdir(p))
			throw failed(QObject::tr("Creating"), p,
				QObject::tr("the directory cannot be created"));
		tempPath = p;
		staged = true;
		return;
	}
	throw failed(QObject::tr("Creating"), targetPath,
		QObject::tr("no free temporary name"));
}

void StagedDirectory::publish()
{
	if (!staged || published)
		throw errorEx(QObject::tr("StagedDirectory: '%1' is not staged")
			.arg(targetPath));
	if (StagedFile::faultHook &&
	    StagedFile::faultHook(StagedFile::swap, targetPath))
		throw failed(QObject::tr("Swapping in"), targetPath,
			QObject::tr("injected fault (test)"));
	/* again, after the commit: what changed since stage() is refused,
	 * and only the entries found now are removed later */
	QStringList known = checkTarget(givenPath, marker, schema, replace);

	/* two steps: for a moment the target is absent */
	QString old = tempPath + ".old";
	if (!QDir().rename(targetPath, old))
		throw failed(QObject::tr("Moving aside"), targetPath,
			QObject::tr("rename failed"));
	if (!QDir().rename(tempPath, targetPath)) {
		if (QDir().rename(old, targetPath))
			throw failed(QObject::tr("Swapping in"),
				targetPath, QObject::tr("rename "
				"failed; the old content is back"));
		throw failed(QObject::tr("Swapping in"), targetPath,
			QObject::tr("rename failed, and so did moving "
			"the old content back: it is in '%1', the new "
			"one in '%2'; move the one you want to '%3'")
			.arg(QDir::toNativeSeparators(old),
			QDir::toNativeSeparators(tempPath),
			QDir::toNativeSeparators(targetPath)));
	}
	published = true;
	staged = false;

	/* the old content: the entries of the earlier export only */
	QDir od(old);
	for (const QString &f : known)
		od.remove(f);
	for (const QString &d : parents(known))
		od.rmdir(d);
	if (!QDir().rmdir(old))
		leftoverPath = old;
}

#endif

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
