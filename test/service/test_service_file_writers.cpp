/* vi: set sw=4 ts=4:
 *
 * The remaining file writers (BTD-139): the database dump, the
 * certificate index, DH parameters and the .rnd seed write through
 * StagedFile (BTD-42). A write that fails after the file was opened
 * leaves an existing target as it was, and key material is owner-only
 * from the creation of the file on. Before, XFile::open_write() emptied
 * the target first, and open_key() set the mode only after the open.
 *
 * The failing write is a real one: RLIMIT_FSIZE makes every write past
 * a few bytes fail with EFBIG (SIGXFSZ ignored), as a full disk would.
 */

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTemporaryDir>

#include <csignal>
#include <sys/resource.h>
#include <sys/stat.h>

#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/db_crl.h"
#include "lib/db_key.h"
#include "lib/db_temp.h"
#include "lib/db_x509.h"
#include "lib/db_x509req.h"
#include "lib/digest.h"
#include "lib/entropy.h"
#include "lib/exception.h"
#include "lib/func.h"
#include "lib/issuance.h"
#include "lib/pki_crl.h"
#include "lib/pki_temp.h"
#include "lib/pki_x509.h"
#include "lib/pki_x509req.h"
#include "lib/request.h"
#include "lib/staged_file.h"
#include "lib/template.h"

#include "ServiceTestCase.h"

/* RLIMIT_FSIZE for its lifetime: writes past limit bytes fail */
class FileSizeLimit
{
	struct rlimit old{};
	void (*oldHandler)(int){};
  public:
	FileSizeLimit(rlim_t limit)
	{
		getrlimit(RLIMIT_FSIZE, &old);
		oldHandler = signal(SIGXFSZ, SIG_IGN);
		struct rlimit l = old;
		l.rlim_cur = limit;
		setrlimit(RLIMIT_FSIZE, &l);
	}
	~FileSizeLimit()
	{
		setrlimit(RLIMIT_FSIZE, &old);
		signal(SIGXFSZ, oldHandler);
	}
};

class test_service_file_writers : public ServiceTestCase
{
	Q_OBJECT

	ServiceContext ctx{ ServiceContext::cli, "os:service-test" };
	QTemporaryDir dir{};
	pki_x509 *cert{};
	pki_key *key{};
	pki_x509req *req{};
	pki_crl *crl{};
	pki_temp *temp{};

	pki_base *object(const QString &kind);
	static QByteArray contents(const QString &path);
	/* The modes of the temporary files beside target seen at the write
	 * step of StagedFile, recorded while call runs */
	static QList<int> stagedModes(const QString &target,
			std::function<void()> call);

  private slots:
	void init();
	void cleanup();
	void dumpFailureKeepsOldFile_data();
	void dumpFailureKeepsOldFile();
	void indexFailureKeepsOldFile();
	void dumpKeyOwnerOnlyBeforeFirstByte();
	void seedOwnerOnlyBeforeFirstByte();
};

void test_service_file_writers::init()
{
	ServiceTestCase::init();
	db_key *keys = Database.model<db_key>();
	QDateTime now = QDateTime::currentDateTimeUtc();

	IssuanceSpec spec;
	spec.name = "BTD-139 CA";
	spec.subject.addEntryByNid(NID_commonName, spec.name);
	spec.key = keys->newKey(ctx, keyjob("EC:prime256v1"), "BTD-139 CA key");
	spec.notBefore = a1time(now.addDays(-1));
	spec.notAfter = a1time(now.addYears(2));
	spec.hashAlgo = digest(NID_sha256);
	spec.extensions.basicCA = ExtensionSpec::bc_ca;
	spec.extensions.keyUsage << "keyCertSign" << "cRLSign";
	cert = Database.model<db_x509>()->newCert(ctx, spec);

	key = keys->newKey(ctx, keyjob("RSA:2048"), "BTD-139 RSA key");

	RequestSpec r;
	r.name = "BTD-139 request";
	r.subject.addEntryByNid(NID_commonName, r.name);
	r.key = key;
	req = Database.model<db_x509req>()->newRequest(ctx, r);

	crljob job(cert);
	job.hashAlgo = digest(NID_sha256);
	crl = Database.model<db_crl>()->newCrl(ctx, job);

	TemplateSpec t;
	t.name = "BTD-139 template";
	t.extensions.basicCA = ExtensionSpec::bc_not_ca;
	temp = Database.model<db_temp>()->newTemplate(ctx, t);
}

void test_service_file_writers::cleanup()
{
	StagedFile::faultHook = nullptr;
	ServiceTestCase::cleanup();
}

pki_base *test_service_file_writers::object(const QString &kind)
{
	if (kind == "certificate")
		return cert;
	if (kind == "key")
		return key;
	if (kind == "request")
		return req;
	if (kind == "crl")
		return crl;
	return temp;
}

QByteArray test_service_file_writers::contents(const QString &path)
{
	QFile f(path);
	return f.open(QIODevice::ReadOnly) ? f.readAll() : QByteArray();
}

QList<int> test_service_file_writers::stagedModes(const QString &target,
		std::function<void()> call)
{
	QList<int> modes;
	QFileInfo t(target);
	StagedFile::faultHook = [&modes, t](enum StagedFile::step s,
			const QString &) {
		if (s != StagedFile::write)
			return false;
		QDir d(t.absolutePath());
		for (const QString &n : d.entryList(QStringList() <<
				"." + t.fileName() + ".bxc-tmp-*",
				QDir::Files | QDir::Hidden)) {
			struct stat st;
			if (stat(QFile::encodeName(d.filePath(n)), &st) == 0)
				modes << (st.st_mode & 0777);
		}
		return false;
	};
	call();
	StagedFile::faultHook = nullptr;
	return modes;
}

void test_service_file_writers::dumpFailureKeepsOldFile_data()
{
	QTest::addColumn<QString>("kind");
	QTest::addColumn<QString>("suffix");

	QTest::newRow("certificate") << "certificate" << ".crt";
	QTest::newRow("private key") << "key" << ".pem";
	QTest::newRow("request") << "request" << ".csr";
	QTest::newRow("crl") << "crl" << ".crl";
	QTest::newRow("template") << "template" << ".xca";
}

void test_service_file_writers::dumpFailureKeepsOldFile()
{
	/* A dump never overwrites: get_dump_filename() picks a free name.
	 * A dump that fails while it writes leaves no half file under that
	 * name, and the file of an earlier dump stays as it was. */
	QFETCH(QString, kind);
	QFETCH(QString, suffix);
	pki_base *pki = object(kind);
	QVERIFY(pki);
	QString first = pki->get_dump_filename(dir.path(), suffix);
	pki->writeDefault(dir.path());
	QByteArray before = contents(first);
	QVERIFY(before.size() > 64);
	QString second = pki->get_dump_filename(dir.path(), suffix);
	QVERIFY(second != first);

	bool failed = false;
	{
		FileSizeLimit limit(64);
		try {
			pki->writeDefault(dir.path());
		} catch (errorEx &) {
			failed = true;
		}
	}
	QCOMPARE(contents(first), before);
	QVERIFY2(!QFile::exists(second), CCHAR("a half file was left: " +
		QString::number(QFileInfo(second).size()) + " bytes"));
	QVERIFY2(failed, "the failed write was not reported");
}

void test_service_file_writers::indexFailureKeepsOldFile()
{
	QString path = dir.filePath("index.txt");
	Database.model<db_x509>()->writeIndex(path, false);
	QByteArray before = contents(path);
	QVERIFY(before.size() > 0);

	bool failed = false;
	{
		FileSizeLimit limit(8);
		try {
			Database.model<db_x509>()->writeIndex(path, false);
		} catch (errorEx &) {
			failed = true;
		}
	}
	QCOMPARE(contents(path), before);
	QVERIFY2(failed, "the failed write was not reported");
}

void test_service_file_writers::dumpKeyOwnerOnlyBeforeFirstByte()
{
	/* The private key of the dump is owner-only while it is written,
	 * not only afterwards */
	QString path = key->get_dump_filename(dir.path(), ".pem");
	QList<int> modes = stagedModes(path, [&]() {
		key->writeDefault(dir.path());
	});
	QCOMPARE(modes, QList<int>() << 0600);
	struct stat st;
	QCOMPARE(stat(QFile::encodeName(path), &st), 0);
	QCOMPARE(int(st.st_mode & 0777), 0600);
}

void test_service_file_writers::seedOwnerOnlyBeforeFirstByte()
{
	/* The .rnd seed that Entropy writes when it ends */
	QString path = getUserSettingsDir() + "/.rnd";
	QDir().mkpath(getUserSettingsDir());
	QList<int> modes = stagedModes(path, []() {
		Entropy *e = new Entropy();
		delete e;
	});
	QCOMPARE(modes, QList<int>() << 0600);
	struct stat st;
	QCOMPARE(stat(QFile::encodeName(path), &st), 0);
	QCOMPARE(int(st.st_mode & 0777), 0600);
}

XCA_SERVICE_TEST_MAIN(test_service_file_writers)
#include "test_service_file_writers.moc"
