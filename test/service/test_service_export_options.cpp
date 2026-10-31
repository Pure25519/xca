/* vi: set sw=4 ts=4:
 *
 * The options of one export (BTD-183): the PKCS#12 algorithm and the
 * ML-DSA private key encoding of an ExportSpec reach the writers of
 * that export only. Before, exportItems() put them into static state
 * (encAlgo::ExportScope, pki_evp::MlDsaFormatScope) for the time of the
 * export, so a writer on another thread, e.g. a second request of the
 * REST server, wrote with the options of the export that was running.
 *
 * Each test holds an export in its password prompt, after it has taken
 * its options and before its writers run, and writes the same object
 * there without options: that file must carry the defaults, the
 * export's file its own options. The second writer runs on the same
 * thread: it reads the key from the database, whose connection belongs
 * to this thread. It stands for any writer that runs while an export
 * holds its options, e.g. on a worker of the REST server (BTD-154).
 */

#include <functional>

#include <QBuffer>
#include <QFile>
#include <QTemporaryDir>

#include <openssl/pkcs12.h>
#include <openssl/x509.h>

#include "lib/PwDialogCore.h"
#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/db_key.h"
#include "lib/db_x509.h"
#include "lib/exception.h"
#include "lib/importexport.h"
#include "lib/issuance.h"
#include "lib/pki_evp.h"
#include "lib/pki_export.h"
#include "lib/pki_x509.h"
#include "lib/settings.h"

#include "ServiceTestCase.h"

static const char pass[] = "Export-Secret-183";
/* pki_export ids: certificate PKCS#12, key PKCS#8 encrypted */
static const int certPkcs12 = 15, keyPkcs8Encrypted = 28;

/* Answers the export password prompt with pass; runs the hook first,
 * while the export waits in its prompt */
class HookPwDialog : public PwDialogUI_i
{
  public:
	std::function<void()> hook{};

	enum open_result execute(pass_info *, Passwd *passwd, bool,
				bool) override
	{
		if (hook) {
			std::function<void()> h = hook;
			hook = nullptr;
			h();
		}
		*passwd = pass;
		return pw_ok;
	}
	int selectToken(const QStringList &) override
	{
		return -1;
	}
	int selectKeySlot(const QString &, const QStringList &) override
	{
		return -1;
	}
	void pinPadLogin(pass_info *, QThread *) override { }
};

class test_service_export_options : public ServiceTestCase
{
	Q_OBJECT

	ServiceContext ctx{ ServiceContext::cli, "os:service-test" };
	QTemporaryDir dir{};
	HookPwDialog *prompt{};

	QString file(const QString &name) const
	{
		return dir.filePath(name);
	}
	static QByteArray readFile(const QString &name)
	{
		QFile f(name);
		return f.open(QIODevice::ReadOnly) ? f.readAll() : QByteArray();
	}
	pki_x509 *leaf(const QString &name);
	/* Runs write; the error text of an exception, empty on success */
	static QString errorOf(const std::function<void()> &write);
	/* The algorithm of the shrouded key bag of a PKCS#12 file */
	static int keyBagAlgorithm(const QByteArray &der);
	/* The first byte of the ML-DSA privateKey in a PKCS#8 file (RFC
	 * 9881): 0x80 seed, 0x04 expanded, 0x30 both */
	static int mlDsaTag(const QByteArray &data, bool encrypted);

  private slots:
	void init();
	void cleanup();
	void pkcs12AlgorithmPerExport();
	void mlDsaFormatPerExport();
};

void test_service_export_options::init()
{
	ServiceTestCase::init();
	prompt = new HookPwDialog;
	pwdialog->delegateTo(prompt);
}

void test_service_export_options::cleanup()
{
	pwdialog->reset();
	prompt = nullptr;
	ServiceTestCase::cleanup();
}

pki_x509 *test_service_export_options::leaf(const QString &name)
{
	QDateTime now = QDateTime::currentDateTimeUtc();
	IssuanceSpec spec;
	spec.name = name;
	spec.subject.addEntryByNid(NID_commonName, name);
	spec.key = Database.model<db_key>()->newKey(ctx,
			keyjob("EC:prime256v1"), name + " key");
	spec.notBefore = a1time(now.addDays(-1));
	spec.notAfter = a1time(now.addYears(1));
	spec.hashAlgo = digest(NID_sha256);
	spec.extensions.basicCA = ExtensionSpec::bc_not_ca;
	spec.extensions.keyUsage << "digitalSignature";
	return Database.model<db_x509>()->newCert(ctx, spec);
}

QString test_service_export_options::errorOf(
			const std::function<void()> &write)
{
	try {
		write();
	} catch (errorEx &err) {
		return err.getString();
	} catch (...) {
		return "exception";
	}
	return QString();
}

int test_service_export_options::keyBagAlgorithm(const QByteArray &der)
{
	const unsigned char *p = (const unsigned char *)der.constData();
	PKCS12 *p12 = d2i_PKCS12(nullptr, &p, der.size());
	int nid = NID_undef;
	STACK_OF(PKCS7) *safes = p12 ? PKCS12_unpack_authsafes(p12) : nullptr;
	for (int i = 0; i < sk_PKCS7_num(safes); i++) {
		PKCS7 *p7 = sk_PKCS7_value(safes, i);
		if (PKCS7_type_is_encrypted(p7))
			continue;
		STACK_OF(PKCS12_SAFEBAG) *bags = PKCS12_unpack_p7data(p7);
		for (int j = 0; j < sk_PKCS12_SAFEBAG_num(bags); j++) {
			const PKCS12_SAFEBAG *bag =
				sk_PKCS12_SAFEBAG_value(bags, j);
			if (PKCS12_SAFEBAG_get_nid(bag) !=
			    NID_pkcs8ShroudedKeyBag)
				continue;
			const X509_ALGOR *alg;
			const ASN1_OBJECT *obj;
			X509_SIG_get0(PKCS12_SAFEBAG_get0_pkcs8(bag), &alg,
					nullptr);
			X509_ALGOR_get0(&obj, nullptr, nullptr, alg);
			nid = OBJ_obj2nid(obj);
		}
		sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
	}
	sk_PKCS7_pop_free(safes, PKCS7_free);
	PKCS12_free(p12);
	ign_openssl_error();
	return nid;
}

int test_service_export_options::mlDsaTag(const QByteArray &data,
			bool encrypted)
{
	BIO *b = BIO_new_mem_buf(data.constData(), data.size());
	PKCS8_PRIV_KEY_INFO *p8 = nullptr;
	if (encrypted) {
		X509_SIG *sig = PEM_read_bio_PKCS8(b, nullptr, nullptr, nullptr);
		if (sig)
			p8 = PKCS8_decrypt(sig, pass, strlen(pass));
		X509_SIG_free(sig);
	} else {
		p8 = d2i_PKCS8_PRIV_KEY_INFO_bio(b, nullptr);
	}
	BIO_free(b);
	const unsigned char *pk = nullptr;
	int len = 0, tag = -1;
	if (p8 && PKCS8_pkey_get0(nullptr, &pk, &len, nullptr, p8) && len > 0)
		tag = pk[0];
	PKCS8_PRIV_KEY_INFO_free(p8);
	ign_openssl_error();
	return tag;
}

/* An export with PBE-SHA1-3DES; meanwhile the same certificate is
 * written as PKCS#12 without an algorithm: AES-256-CBC (PBES2) of the
 * setting, not the 3DES of the running export */
void test_service_export_options::pkcs12AlgorithmPerExport()
{
	Settings["pkcs12_enc_algo"] = QString("AES-256-CBC");
	pki_x509 *cert = leaf("BTD-183 pkcs12");
	QVERIFY(cert);

	QByteArray parallel;
	QString error = "not run";
	prompt->hook = [&]() {
		error = errorOf([&]() {
			QBuffer buf(&parallel);
			buf.open(QIODevice::WriteOnly);
			Passwd p;
			p = pass;
			Database.model<db_x509>()->writePKCS12(cert, buf,
							false, p);
		});
	};
	ExportSpec spec;
	spec.items << cert;
	spec.format = pki_export::by_id(certPkcs12);
	spec.fileName = file("outer.p12");
	spec.pkcs12Algorithm = "PBE-SHA1-3DES";
	Database.model<db_x509>()->exportItems(ctx, spec);

	QVERIFY2(error.isEmpty(), CCHAR(error));
	QCOMPARE(keyBagAlgorithm(readFile(spec.fileName)),
		NID_pbe_WithSHA1And3_Key_TripleDES_CBC);
	QCOMPARE(keyBagAlgorithm(parallel), NID_pbes2);
}

/* An export of an ML-DSA key as seed; meanwhile the same key is
 * written as PKCS#8 without a choice: both (0x30), not the seed of the
 * running export. The export's file and audit entry say seed. */
void test_service_export_options::mlDsaFormatPerExport()
{
	pki_key *key = Database.model<db_key>()->newKey(ctx,
			keyjob("ML-DSA-65"), "BTD-183 mldsa");
	pki_evp *evp = dynamic_cast<pki_evp *>(key);
	QVERIFY(evp);

	QByteArray parallel;
	QString error = "not run";
	prompt->hook = [&]() {
		error = errorOf([&]() {
			QBuffer buf(&parallel);
			buf.open(QIODevice::WriteOnly);
			evp->writePKCS8(buf, nullptr, Passwd(), false);
		});
	};
	ExportSpec spec;
	spec.items << key;
	spec.format = pki_export::by_id(keyPkcs8Encrypted);
	spec.fileName = file("outer.pem");
	spec.privateKeyFormat = "seed";
	Database.model<db_key>()->exportItems(ctx, spec);

	QVERIFY2(error.isEmpty(), CCHAR(error));
	QCOMPARE(mlDsaTag(readFile(spec.fileName), true), 0x80);
	QCOMPARE(mlDsaTag(parallel, false), 0x30);

	QList<AuditEntry> e;
	foreach(const AuditEntry &a, AuditLog::entries()) {
		if (a.action == "key.export_private")
			e << a;
	}
	QCOMPARE(e.size(), 1);
	QCOMPARE(e[0].params.value("ml_dsa_encoding").toString(),
		QString("seed"));
}

XCA_SERVICE_TEST_MAIN(test_service_export_options)
#include "test_service_export_options.moc"
