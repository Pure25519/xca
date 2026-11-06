/* vi: set sw=4 ts=4:
 *
 * Follow-ups to the hardened StagedFile and StagedDirectory (BTD-213,
 * after BTD-210): the directory descriptors stay bounded by the number of
 * directories, a trust-list directory keeps its mode across the swap, the
 * message of a file system that cannot publish safely names the remedy,
 * and the clean-up of stale temporary files spares a run that is alive.
 */

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTemporaryDir>

#include <memory>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#include "lib/exception.h"
#include "lib/staged_file.h"

#include "ServiceTestCase.h"

/* RLIMIT_NOFILE for its lifetime */
class FdLimit
{
	struct rlimit old{};
  public:
	FdLimit(rlim_t limit)
	{
		getrlimit(RLIMIT_NOFILE, &old);
		struct rlimit l = old;
		l.rlim_cur = limit;
		setrlimit(RLIMIT_NOFILE, &l);
	}
	~FdLimit()
	{
		setrlimit(RLIMIT_NOFILE, &old);
	}
};

class test_service_staged_file : public ServiceTestCase
{
	Q_OBJECT

	QTemporaryDir dir{};

	/* the open descriptors of this process that are directories */
	static int openDirectories();
	static void setAge(const QString &path, int seconds);

  private slots:
	void cleanup();
	void manyFilesFewDirectoryFds();
	void trustListKeepsDirectoryMode();
	void unsupportedFileSystemMessage();
	void staleCleanupSparesLiveRun();
	void staleCleanupRemovesDeadRun();
};

void test_service_staged_file::cleanup()
{
	StagedFile::faultHook = nullptr;
	ServiceTestCase::cleanup();
}

int test_service_staged_file::openDirectories()
{
	int n = 0;
	for (const QFileInfo &fd : QDir("/proc/self/fd").entryInfoList(
			QDir::AllEntries | QDir::System | QDir::NoDotAndDotDot)) {
		struct stat st;
		if (stat(QFile::encodeName(fd.filePath()).constData(), &st) == 0 &&
		    S_ISDIR(st.st_mode))
			n++;
	}
	return n;
}

void test_service_staged_file::setAge(const QString &path, int seconds)
{
	struct timeval t[2];
	gettimeofday(&t[0], nullptr);
	t[0].tv_sec -= seconds;
	t[1] = t[0];
	QVERIFY(utimes(QFile::encodeName(path).constData(), t) == 0);
}

/* BTD-213 (1): 1100 files in two directories staged at once under a limit
 * of 256 descriptors. Before, every staged file kept its own descriptor of
 * its directory and the export failed with EMFILE. */
void test_service_staged_file::manyFilesFewDirectoryFds()
{
	QString a = dir.filePath("certs"), b = dir.filePath("crl");
	QVERIFY(QDir().mkpath(a) && QDir().mkpath(b));
	int before = openDirectories();
	QList<std::shared_ptr<StagedFile> > files;
	{
		FdLimit limit(256);
		try {
			for (int i = 0; i < 1100; i++) {
				auto f = std::make_shared<StagedFile>(QString(
					"%1/f%2.der").arg(i % 2 ? a : b).arg(i),
					false, false);
				f->stage(QByteArray("content ") +
					QByteArray::number(i));
				files << f;
			}
		} catch (errorEx &err) {
			QFAIL(CCHAR(QString("staging file %1 failed: %2")
				.arg(files.size()).arg(err.getString())));
		}
		int during = openDirectories() - before;
		QVERIFY2(during <= 2, CCHAR(QString("%1 directory descriptors "
			"for 2 directories").arg(during)));
	}
	for (auto &f : files)
		f->publish();
	QCOMPARE(QDir(a).entryList(QDir::Files).size(), 550);
	QCOMPARE(QDir(b).entryList(QDir::Files).size(), 550);
	files.clear();
	QCOMPARE(openDirectories(), before);
}

/* BTD-213 (4): the staged directory gets the mode of the directory it
 * replaces. Before, a 0750 trust-list directory became 0777 minus umask
 * after the swap. */
void test_service_staged_file::trustListKeepsDirectoryMode()
{
	QString target = dir.filePath("trustlist");
	QVERIFY(QDir().mkpath(target));
	QVERIFY(chmod(QFile::encodeName(target).constData(), 0750) == 0);
	StagedDirectory d(target, "manifest.json", "urn:test:manifest", false);
	d.stage();
	StagedFile f(d.stagedPath(target + "/manifest.json"), false, false);
	f.stage("{\"schema\": \"urn:test:manifest\", \"entries\": []}\n");
	f.publish();
	d.publish();
	struct stat st;
	QVERIFY(stat(QFile::encodeName(target).constData(), &st) == 0);
	QCOMPARE(QString::number(st.st_mode & 07777, 8), QString("750"));
}

/* BTD-213 (5): a file system that can publish neither with
 * renameat2(RENAME_NOREPLACE) nor with link() is refused with a text that
 * names the remedy, a directory on a local file system, and does not offer
 * --force as the way around it */
void test_service_staged_file::unsupportedFileSystemMessage()
{
	StagedFile::faultHook = [](enum StagedFile::step s, const QString &) {
		return s == StagedFile::probe;
	};
	StagedFile f(dir.filePath("probe.pem"), false, false);
	try {
		f.stage("data\n");
		QFAIL("no serviceError");
	} catch (serviceError &err) {
		QCOMPARE(err.code, QString("target_filesystem_unsupported"));
		QString text = err.getString();
		QVERIFY2(text.contains("local file system"), CCHAR(text));
		QVERIFY2(!text.contains("give --force"), CCHAR(text));
	}
}

/* BTD-213 (6): a temporary file older than the age limit whose run is
 * still alive (this process) stays; the run publishes it. Before, the age
 * alone decided and a second run in the same directory removed it. */
void test_service_staged_file::staleCleanupSparesLiveRun()
{
	StagedFile first(dir.filePath("slow.pem"), false, false);
	first.stage("slow run\n");
	setAge(first.temporary(), 3600);

	/* a second run in the same directory meanwhile */
	StagedFile second(dir.filePath("other.pem"), false, false);
	second.stage("other run\n");
	QVERIFY2(QFileInfo::exists(first.temporary()),
		CCHAR(first.temporary()));
	first.publish();
	second.publish();
	QVERIFY(QFileInfo::exists(dir.filePath("slow.pem")));
	for (const StagedFile::warning &w : second.warnings())
		QVERIFY2(w.first != "stale_temp_removed", CCHAR(w.second));
}

/* BTD-213 (6): the temporary file of a run that is gone (its pid does not
 * exist) and older than the age limit is removed and reported */
void test_service_staged_file::staleCleanupRemovesDeadRun()
{
	pid_t child = fork();
	if (child == 0)
		_exit(0);
	QVERIFY(child > 0);
	QVERIFY(waitpid(child, nullptr, 0) == child);
	QString dead = dir.filePath(QString(".gone.pem.bxc-tmp-p%1s1-"
				"0123456789abcdef").arg(child));
	QFile f(dead);
	QVERIFY(f.open(QIODevice::WriteOnly));
	f.write("left by a killed run\n");
	f.close();
	setAge(dead, 3600);
	/* young and dead: kept, the age limit still applies */
	QString young = dir.filePath(QString(".young.pem.bxc-tmp-p%1s1-"
				"fedcba9876543210").arg(child));
	QFile y(young);
	QVERIFY(y.open(QIODevice::WriteOnly));
	y.close();

	StagedFile next(dir.filePath("next.pem"), false, false);
	next.stage("next run\n");
	QVERIFY(!QFileInfo::exists(dead));
	QVERIFY(QFileInfo::exists(young));
	bool reported = false;
	for (const StagedFile::warning &w : next.warnings())
		reported |= w.first == "stale_temp_removed";
	QVERIFY(reported);
	next.publish();
}

XCA_SERVICE_TEST_MAIN(test_service_staged_file)
#include "test_service_staged_file.moc"
