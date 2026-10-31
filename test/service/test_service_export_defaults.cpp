/* vi: set sw=4 ts=4:
 *
 * Secure export defaults (BTD-52): a PKCS#12 export without a chosen
 * algorithm is AES-256-CBC with PBES2/PBKDF2-HMAC-SHA256 and an
 * HMAC-SHA256 MAC, legacy 3DES with a SHA-1 MAC only on request; an
 * encrypted key export is PKCS#8 PBES2, RFC 1423 and PKCS#1 only in the
 * formats that name them; every structure is definite-length DER. Each
 * key format and PKCS#12 make the round trip export, openssl, re-import
 * for RSA, EC and Ed25519. Before, the compiled default was
 * PBE-SHA1-3DES with a SHA-1 MAC, the GUI warned about it on every
 * database open, and the database dump wrote RFC 1423.
 */

#include <QDir>
#include <QFile>
#include <QProcess>
#include <QSqlError>
#include <QSqlQuery>
#include <QTemporaryDir>

#include <openssl/asn1.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>

#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/db_key.h"
#include "lib/db_x509.h"
#include "lib/digest.h"
#include "lib/exception.h"
#include "lib/importexport.h"
#include "lib/issuance.h"
#include "lib/pki_evp.h"
#include "lib/pki_export.h"
#include "lib/pki_pkcs12.h"
#include "lib/pki_x509.h"
#include "lib/settings.h"

#include "ServiceTestCase.h"

/* Tests that read the output with the openssl program (BTD-52 review:
 * a skip per test, not for the whole case) */
#ifdef OPENSSL_PROGRAM
#define NEED_OPENSSL() do {} while (0)
#else
#define NEED_OPENSSL() QSKIP("openssl program not found")
#endif

static const char passVar[] = "BTD52_EXPORT_PASS";
static const char pass[] = "Export-Secret-52";

class test_service_export_defaults : public ServiceTestCase
{
	Q_OBJECT

	ServiceContext ctx{ ServiceContext::cli, "os:service-test" };
	QTemporaryDir dir{};

	QString file(const QString &name) const
	{
		return dir.filePath(name);
	}
	static QString openssl(const QStringList &args, int *exitCode);
	/* the output, or a failed check with the output */
	static QString opensslOk(const QStringList &args);
	static QString passin()
	{
		return QString("env:%1").arg(passVar);
	}
	pki_x509 *leaf(const QString &keyType);
	QString exportTo(pki_base *pki, int format, const QString &name);
	static QByteArray readFile(const QString &name);

  private slots:
	void initTestCase();
	void noLegacyWarningByDefault();
	void pkcs12Parameters();
	void auditNamesProtection();
	void pkcs12AlgorithmNeedsPkcs12Format();
	void migrateOldDefault();
	void keepLegacyIsAChoice();
	void migrationIsOneTransaction_data();
	void migrationIsOneTransaction();
	void migrationNeedsUnlock();
	void clearKeepsOpenDatabase();
	void pkcs12Default_data();
	void pkcs12Default();
	void pkcs12LegacyOnRequest();
	void pkcs12AlgorithmPerExport();
	void keyFormats_data();
	void keyFormats();
	void pkcs12RoundTrip_data();
	void pkcs12RoundTrip();
	void dumpWritesPkcs8();
	void defaultsDoNotLeakAcrossDatabases();
	void pkcs12Pbmac1();
	void pkcs12IterationsPerExport();
	void pkcs12IterationsSetting();
	void pkcs12OptionErrors_data();
	void pkcs12OptionErrors();
};

QString test_service_export_defaults::openssl(const QStringList &args,
			int *exitCode)
{
#ifdef OPENSSL_PROGRAM
	QProcess p;
	p.setProcessChannelMode(QProcess::MergedChannels);
	p.start(OPENSSL_PROGRAM, args);
	*exitCode = p.waitForFinished(30000) ? p.exitCode() : -1;
	return QString::fromUtf8(p.readAll());
#else
	(void)args;
	*exitCode = -1;
	return QString();
#endif
}

QString test_service_export_defaults::opensslOk(const QStringList &args)
{
	int rc;
	QString out = openssl(args, &rc);
	if (rc != 0)
		qWarning().noquote() << "openssl" << args.join(" ") << "\n" << out;
	return rc == 0 ? out : QString();
}

void test_service_export_defaults::initTestCase()
{
	ServiceTestCase::initTestCase();
	qputenv(passVar, pass);
}


/* A self-signed certificate with a new key of that type */
pki_x509 *test_service_export_defaults::leaf(const QString &keyType)
{
	QDateTime now = QDateTime::currentDateTimeUtc();
	IssuanceSpec spec;
	spec.name = "BTD-52 " + keyType;
	spec.subject.addEntryByNid(NID_commonName, spec.name);
	spec.key = Database.model<db_key>()->newKey(ctx, keyjob(keyType),
					spec.name + " key");
	spec.notBefore = a1time(now.addDays(-1));
	spec.notAfter = a1time(now.addYears(1));
	/* Ed25519 signs without a separate digest */
	spec.hashAlgo = digest(keyType == "ED25519" ? NID_undef : NID_sha256);
	spec.extensions.basicCA = ExtensionSpec::bc_not_ca;
	spec.extensions.keyUsage << "digitalSignature";
	return Database.model<db_x509>()->newCert(ctx, spec);
}

QString test_service_export_defaults::exportTo(pki_base *pki, int format,
			const QString &name)
{
	ExportSpec spec;
	spec.items << pki;
	spec.format = pki_export::by_id(format);
	spec.fileName = file(name);
	spec.passwordSource = passin();
	Database.modelForPki(pki)->exportItems(ctx, spec);
	return spec.fileName;
}

QByteArray test_service_export_defaults::readFile(const QString &name)
{
	QFile f(name);
	if (!f.open(QIODevice::ReadOnly))
		return QByteArray();
	return f.readAll();
}

void test_service_export_defaults::pkcs12Default_data()
{
	QTest::addColumn<QString>("keyType");
	QTest::newRow("RSA") << "RSA:2048";
	QTest::newRow("EC") << "EC:prime256v1";
	QTest::newRow("Ed25519") << "ED25519";
}

/* No algorithm chosen: AES-256-CBC with PBES2/PBKDF2-HMAC-SHA256 for
 * the key and the certificates, an HMAC-SHA256 MAC (not PBMAC1, which
 * Windows, Java and many device importers cannot check), 2048 iterations
 * as OpenSSL and Windows use them, definite lengths. openssl reads it
 * without -legacy: no legacy provider is needed. */
void test_service_export_defaults::pkcs12Default()
{
	NEED_OPENSSL();
	QFETCH(QString, keyType);
	pki_x509 *cert = leaf(keyType);
	QVERIFY(cert);
	QString name = exportTo(cert, 15, "default.p12");

	QString info = opensslOk({ "pkcs12", "-in", name, "-info",
			"-noout", "-passin", passin() });
	qInfo().noquote() << "openssl pkcs12 -info:\n" << info;
	QVERIFY2(!info.isEmpty(), "openssl pkcs12 -info without -legacy failed");
	QVERIFY2(info.contains("MAC: sha256, Iteration 2048"), CCHAR(info));
	QVERIFY2(!info.contains("PBMAC1"), CCHAR(info));
	QVERIFY2(info.contains("Shrouded Keybag: PBES2, PBKDF2, AES-256-CBC"),
		CCHAR(info));
	QVERIFY2(info.contains("PKCS7 Encrypted data: PBES2, PBKDF2, "
		"AES-256-CBC"), CCHAR(info));
	QVERIFY2(info.count("PRF hmacWithSHA256") == 2, CCHAR(info));
	QVERIFY2(!info.contains("3DES") && !info.contains("RC2") &&
		!info.contains("MAC: sha1"), CCHAR(info));

	QString der = opensslOk({ "asn1parse", "-inform", "DER", "-in", name,
			"-i" });
	QVERIFY(!der.isEmpty());
	QVERIFY2(!der.contains("l=inf"), "indefinite length in PKCS#12");
}

/* The legacy algorithm is used when it is chosen, and only then */
void test_service_export_defaults::pkcs12LegacyOnRequest()
{
	NEED_OPENSSL();
	pki_x509 *cert = leaf("EC:prime256v1");
	QVERIFY(cert);
	/* a QString: a char * would take the bool assignment ("yes") */
	Settings["pkcs12_enc_algo"] = QString("PBE-SHA1-3DES");
	QString name = exportTo(cert, 15, "legacy.p12");

	int rc;
	QString info = openssl({ "pkcs12", "-in", name, "-info", "-noout",
			"-legacy", "-passin", passin() }, &rc);
	QVERIFY2(rc == 0, CCHAR(info));
	QVERIFY2(info.contains("MAC: sha1"), CCHAR(info));
	QVERIFY2(info.contains("pbeWithSHA1And3-KeyTripleDES-CBC"),
		CCHAR(info));
	QVERIFY2(!info.contains("AES-256-CBC"), CCHAR(info));
}

/* ExportSpec::pkcs12Algorithm overrides the setting for one export;
 * an unknown name is rejected before anything is written */
void test_service_export_defaults::pkcs12AlgorithmPerExport()
{
	NEED_OPENSSL();
	pki_x509 *cert = leaf("EC:prime256v1");
	QVERIFY(cert);
	Settings["pkcs12_enc_algo"] = QString("AES-256-CBC");
	ExportSpec spec;
	spec.items << cert;
	spec.format = pki_export::by_id(15);
	spec.fileName = file("per-export.p12");
	spec.passwordSource = passin();
	spec.pkcs12Algorithm = "PBE-SHA1-3DES";
	Database.model<db_x509>()->exportItems(ctx, spec);

	int rc;
	QString info = openssl({ "pkcs12", "-in", spec.fileName, "-info",
			"-noout", "-legacy", "-passin", passin() }, &rc);
	QVERIFY2(rc == 0, CCHAR(info));
	QVERIFY2(info.contains("pbeWithSHA1And3-KeyTripleDES-CBC"),
		CCHAR(info));
	/* the setting again after the export */
	QCOMPARE(encAlgo::forExport().getEncAlgoNid(), NID_aes_256_cbc);

	spec.pkcs12Algorithm = "DES-CBC";
	spec.fileName = file("unknown.p12");
	try {
		Database.model<db_x509>()->exportItems(ctx, spec);
		QFAIL("unknown algorithm accepted");
	} catch (serviceError &err) {
		QCOMPARE(err.code, QString("invalid_pkcs12_algorithm"));
	}
	QVERIFY(!QFile::exists(spec.fileName));
}

/* The GUI warns on open whenever the PKCS#12 default is legacy */
void test_service_export_defaults::noLegacyWarningByDefault()
{
	QVERIFY(!encAlgo::getDefault().legacy());
	QCOMPARE(encAlgo::getDefault().getEncAlgoNid(), NID_aes_256_cbc);
	QCOMPARE(encAlgo((QString)Settings["pkcs12_enc_algo"])
		.getEncAlgoNid(), NID_aes_256_cbc);
}

void test_service_export_defaults::keyFormats_data()
{
	QTest::addColumn<QString>("keyType");
	QTest::addColumn<int>("format");
	QTest::addColumn<QString>("header");    // first PEM line, "" for DER
	QTest::addColumn<bool>("pbes2");        // PKCS#8 PBES2 encrypted
	QTest::addColumn<bool>("rfc1423");      // Proc-Type: 4,ENCRYPTED

	const QList<QPair<QString, QString> > types {
		{ "RSA", "RSA:2048" }, { "EC", "EC:prime256v1" },
		{ "Ed25519", "ED25519" } };
	for (const auto &t : types) {
		QString trad = t.first == "RSA" ? "RSA PRIVATE KEY" :
			t.first == "EC" ? "EC PRIVATE KEY" : "PRIVATE KEY";
		QByteArray row = t.first.toLatin1();
		const char *n = row.constData();
		QTest::addRow("%s PKCS#8 encrypted", n) << t.second << 28
			<< "ENCRYPTED PRIVATE KEY" << true << false;
		QTest::addRow("%s PKCS#8", n) << t.second << 29
			<< "PRIVATE KEY" << false << false;
		QTest::addRow("%s PEM private", n) << t.second << 20
			<< trad << false << false;
		QTest::addRow("%s DER private", n) << t.second << 25
			<< "" << false << false;
		/* traditional encryption exists for RSA and EC only */
		if (t.first != "Ed25519")
			QTest::addRow("%s PEM encrypted (legacy)", n) << t.second
				<< 21 << trad << false << true;
	}
}

/* Each key format: the encryption it names, nothing else; the round
 * trip through openssl pkey and back into a new database row */
void test_service_export_defaults::keyFormats()
{
	NEED_OPENSSL();
	QFETCH(QString, keyType);
	QFETCH(int, format);
	QFETCH(QString, header);
	QFETCH(bool, pbes2);
	QFETCH(bool, rfc1423);

	pki_key *key = Database.model<db_key>()->newKey(ctx, keyjob(keyType),
					"BTD-52 key");
	QVERIFY(key);
	QString fingerprint = key->fingerprint("der sha256");
	QString name = exportTo(key, format, "key.out");
	QByteArray out = readFile(name);

	if (header.isEmpty()) {
		QVERIFY(!out.contains("-----BEGIN"));
	} else {
		QVERIFY2(out.contains("-----BEGIN " + header.toLatin1() +
			"-----\n"), out.constData());
		QVERIFY(!out.contains("-----BEGIN ENCRYPTED") || pbes2);
	}
	QCOMPARE(out.contains("Proc-Type: 4,ENCRYPTED"), rfc1423);
	if (pbes2) {
		QString der = opensslOk({ "asn1parse", "-in", name, "-i" });
		for (const char *alg : { "PBES2", "PBKDF2", "hmacWithSHA256",
					"aes-256-cbc" })
			QVERIFY2(der.contains(alg), CCHAR(der));
		QVERIFY2(!der.contains("l=inf"), CCHAR(der));
	}

	QStringList args { "pkey", "-in", name, "-pubout" };
	if (header.isEmpty())
		args << "-inform" << "DER";
	if (pbes2 || rfc1423)
		args << "-passin" << passin();
	QVERIFY(!opensslOk(args).isEmpty());

	Database.model<db_key>()->deleteItems(ctx, { key });
	ImportSpec spec;
	spec.files << name;
	spec.passwordSource = passin();
	ImportResult r = Database.importItems(ctx, spec);
	QCOMPARE(r.created.size(), 1);
	pki_key *back = dynamic_cast<pki_key *>(r.created[0]);
	QVERIFY(back);
	QVERIFY(back->isPrivKey());
	QCOMPARE(back->fingerprint("der sha256"), fingerprint);
}

void test_service_export_defaults::pkcs12RoundTrip_data()
{
	pkcs12Default_data();
}

/* PKCS#12: openssl reads key and certificate, the re-import restores
 * both */
void test_service_export_defaults::pkcs12RoundTrip()
{
	NEED_OPENSSL();
	QFETCH(QString, keyType);
	pki_x509 *cert = leaf(keyType);
	QVERIFY(cert);
	pki_key *key = cert->getRefKey();
	QString certFp = cert->fingerprint(EVP_sha256());
	QString keyFp = key->fingerprint("der sha256");
	QString name = exportTo(cert, 15, "roundtrip.p12");

	QString pem = opensslOk({ "pkcs12", "-in", name, "-noenc",
			"-passin", passin() });
	QVERIFY(pem.contains("-----BEGIN CERTIFICATE-----"));
	QVERIFY(pem.contains("-----BEGIN PRIVATE KEY-----"));

	Database.model<db_x509>()->deleteItems(ctx, { cert });
	Database.model<db_key>()->deleteItems(ctx, { key });
	ImportSpec spec;
	spec.files << name;
	spec.passwordSource = passin();
	ImportResult r = Database.importItems(ctx, spec);
	QCOMPARE(r.created.size(), 2);
	bool certBack = false, keyBack = false;
	for (pki_base *pki : r.created) {
		pki_x509 *c = dynamic_cast<pki_x509 *>(pki);
		pki_key *k = dynamic_cast<pki_key *>(pki);
		if (c)
			certBack = c->fingerprint(EVP_sha256()) == certFp;
		if (k)
			keyBack = k->isPrivKey() &&
				k->fingerprint("der sha256") == keyFp;
	}
	QVERIFY(certBack);
	QVERIFY(keyBack);
}

/* The database dump encrypts the keys as PKCS#8 PBES2, not RFC 1423 */
void test_service_export_defaults::dumpWritesPkcs8()
{
	QVERIFY(Database.model<db_key>()->newKey(ctx, keyjob("RSA:2048"),
					"BTD-52 dump"));
	QString dumpDir = file("dump");
	QVERIFY(QDir().mkpath(dumpDir));
	Database.model<db_key>()->dump(dumpDir);

	QStringList files = QDir(dumpDir + "/keys").entryList(QDir::Files);
	QCOMPARE(files.size(), 1);
	QByteArray out = readFile(dumpDir + "/keys/" + files[0]);
	QVERIFY2(out.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----"),
		out.constData());
	QVERIFY(!out.contains("Proc-Type"));
}

/* Database A stores a legacy PKCS#12 algorithm and another hash; B
 * stores neither and must start with the compiled-in defaults. On
 * bxc-main the statics that settings::setAction() fills kept A's values,
 * because Settings.clear() refilled them from those statics (BTD-174). */
void test_service_export_defaults::defaultsDoNotLeakAcrossDatabases()
{
	NEED_OPENSSL();
	QString fileA = dbFile;
	/* back to A also when a check fails: cleanup() removes A's folder */
	struct Restore {
		QString &file;
		QString value;
		~Restore() { file = value; }
	} restore{ dbFile, dbFile };
	Settings["pkcs12_enc_algo"] = QString("PBE-SHA1-3DES");
	Settings["default_hash"] = QString("SHA512");
	Settings["defaultkey"] = QString("EC:secp384r1");
	Settings["string_opt"] = QString("utf8only");
	QVERIFY(encAlgo::getDefault().legacy());
	QCOMPARE(keyjob::defaultjob.toString(), QString("EC:secp384r1"));

	QTemporaryDir dirB(QDir::tempPath() + "/xca-service-XXXXXX");
	QVERIFY(dirB.isValid());
	Database.close();
	dbFile = dirB.filePath("b.xdb");
	openDatabase();
	QVERIFY(!encAlgo::getDefault().legacy());
	QCOMPARE(encAlgo::getDefault().getEncAlgoNid(), NID_aes_256_cbc);
	QCOMPARE(digest::getDefault().name(), QString("SHA256"));
	QCOMPARE(keyjob::defaultjob.toString(), keyjob().toString());
	QCOMPARE(ASN1_STRING_get_default_mask(), (unsigned long)0x2002);
	pki_x509 *cert = leaf("EC:prime256v1");
	QVERIFY(cert);
	QString name = exportTo(cert, 15, "b.p12");
	QString info = opensslOk({ "pkcs12", "-in", name, "-info",
			"-noout", "-passin", passin() });
	qInfo().noquote() << "database B, openssl pkcs12 -info:" << info;
	QVERIFY2(info.contains("AES-256-CBC") && info.contains("MAC: sha256"),
		CCHAR(info));

	/* A keeps what it stores */
	Database.close();
	dbFile = fileA;
	openDatabase();
	QVERIFY(encAlgo::getDefault().legacy());
	QCOMPARE(digest::getDefault().name(), QString("SHA512"));
	QCOMPARE(keyjob::defaultjob.toString(), QString("EC:secp384r1"));
	QCOMPARE(ASN1_STRING_get_default_mask(),
		(unsigned long)B_ASN1_UTF8STRING);
}

/* PBKDF2 salt length and iterations of a PBES2 algorithm identifier */
static bool pbkdf2Params(const X509_ALGOR *alg, int *saltLen, long *iter)
{
	const ASN1_OBJECT *obj;
	int ptype;
	const void *pval;
	X509_ALGOR_get0(&obj, &ptype, &pval, alg);
	if (OBJ_obj2nid(obj) != NID_pbes2 || ptype != V_ASN1_SEQUENCE)
		return false;
	PBE2PARAM *pbe2 = (PBE2PARAM *)ASN1_item_unpack(
		(const ASN1_STRING *)pval, ASN1_ITEM_rptr(PBE2PARAM));
	if (!pbe2)
		return false;
	bool ok = false;
	X509_ALGOR_get0(&obj, &ptype, &pval, pbe2->keyfunc);
	if (OBJ_obj2nid(obj) == NID_id_pbkdf2 && ptype == V_ASN1_SEQUENCE) {
		PBKDF2PARAM *kdf = (PBKDF2PARAM *)ASN1_item_unpack(
			(const ASN1_STRING *)pval, ASN1_ITEM_rptr(PBKDF2PARAM));
		if (kdf && kdf->salt->type == V_ASN1_OCTET_STRING) {
			*saltLen = ASN1_STRING_get_length(kdf->salt->value.octet_string);
			*iter = ASN1_INTEGER_get(kdf->iter);
			ok = true;
		}
		PBKDF2PARAM_free(kdf);
	}
	PBE2PARAM_free(pbe2);
	return ok;
}

/* The parameters as written, not left to OpenSSL's defaults unchecked
 * (BTD-52 review): PBKDF2 with 2048 iterations and a 16-byte salt for the
 * key bag and the certificates, the MAC HMAC-SHA256 with 2048 iterations
 * and a 16-byte salt */
void test_service_export_defaults::pkcs12Parameters()
{
	pki_x509 *cert = leaf("EC:prime256v1");
	QVERIFY(cert);
	QByteArray der = readFile(exportTo(cert, 15, "params.p12"));
	const unsigned char *p = (const unsigned char *)der.constData();
	PKCS12 *p12 = d2i_PKCS12(nullptr, &p, der.size());
	QVERIFY(p12);

	const ASN1_OCTET_STRING *mac, *salt;
	const X509_ALGOR *macAlg;
	const ASN1_INTEGER *macIter;
	PKCS12_get0_mac(&mac, &macAlg, &salt, &macIter, p12);
	const ASN1_OBJECT *obj;
	X509_ALGOR_get0(&obj, nullptr, nullptr, macAlg);
	QCOMPARE(OBJ_obj2nid(obj), NID_sha256);
	QCOMPARE(ASN1_INTEGER_get(macIter), 2048L);
	QCOMPARE(ASN1_STRING_get_length(salt), 16);

	int found = 0;
	STACK_OF(PKCS7) *safes = PKCS12_unpack_authsafes(p12);
	QVERIFY(safes);
	for (int i = 0; i < sk_PKCS7_num(safes); i++) {
		PKCS7 *p7 = sk_PKCS7_value(safes, i);
		int saltLen = 0;
		long iter = 0;
		if (PKCS7_type_is_encrypted(p7)) {
			QVERIFY(pbkdf2Params(
				p7->d.encrypted->enc_data->algorithm,
				&saltLen, &iter));
			QCOMPARE(iter, 2048L);
			QCOMPARE(saltLen, 16);
			found++;
			continue;
		}
		STACK_OF(PKCS12_SAFEBAG) *bags = PKCS12_unpack_p7data(p7);
		for (int j = 0; j < sk_PKCS12_SAFEBAG_num(bags); j++) {
			const PKCS12_SAFEBAG *bag =
				sk_PKCS12_SAFEBAG_value(bags, j);
			if (PKCS12_SAFEBAG_get_nid(bag) !=
			    NID_pkcs8ShroudedKeyBag)
				continue;
			const X509_ALGOR *alg;
			X509_SIG_get0(PKCS12_SAFEBAG_get0_pkcs8(bag), &alg,
					nullptr);
			QVERIFY(pbkdf2Params(alg, &saltLen, &iter));
			QCOMPARE(iter, 2048L);
			QCOMPARE(saltLen, 16);
			found++;
		}
		sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
	}
	sk_PKCS7_pop_free(safes, PKCS7_free);
	PKCS12_free(p12);
	/* the encrypted certificates and the shrouded key bag */
	QCOMPARE(found, 2);
}

static QVariantMap lastPrivateExport()
{
	QVariantMap params;
	for (const AuditEntry &e : AuditLog::entries())
		if (e.action == "key.export_private")
			params = e.params;
	return params;
}

/* The export entry names how the key material is protected:
 * pkcs12_algorithm for PKCS#12, legacy for 3DES/RC2 and RFC 1423 */
void test_service_export_defaults::auditNamesProtection()
{
	pki_x509 *cert = leaf("EC:prime256v1");
	QVERIFY(cert);
	exportTo(cert, 15, "audit.p12");
	QVariantMap p = lastPrivateExport();
	QCOMPARE(p.value("pkcs12_algorithm").toString(),
		QString("AES-256-CBC"));
	QVERIFY(!p.contains("legacy"));

	ExportSpec spec;
	spec.items << cert;
	spec.format = pki_export::by_id(15);
	spec.fileName = file("audit-legacy.p12");
	spec.passwordSource = passin();
	spec.pkcs12Algorithm = "PBE-SHA1-3DES";
	Database.model<db_x509>()->exportItems(ctx, spec);
	p = lastPrivateExport();
	QCOMPARE(p.value("pkcs12_algorithm").toString(),
		QString("PBE-SHA1-3DES"));
	QCOMPARE(p.value("legacy").toBool(), true);

	pki_key *key = cert->getRefKey();
	exportTo(key, 21, "audit-rfc1423.pem");
	p = lastPrivateExport();
	QCOMPARE(p.value("legacy").toBool(), true);
	QVERIFY(!p.contains("pkcs12_algorithm"));

	exportTo(key, 28, "audit-pkcs8.pem");
	p = lastPrivateExport();
	QVERIFY(!p.contains("legacy"));
	QVERIFY(!p.contains("pkcs12_algorithm"));
	QVERIFY(AuditLog::verify().ok());
}

/* A PKCS#12 algorithm with another format is no silent no-op */
void test_service_export_defaults::pkcs12AlgorithmNeedsPkcs12Format()
{
	pki_key *key = Database.model<db_key>()->newKey(ctx,
			keyjob("EC:prime256v1"), "BTD-52 key");
	QVERIFY(key);
	ExportSpec spec;
	spec.items << key;
	spec.format = pki_export::by_id(28);
	spec.fileName = file("not-pkcs12.pem");
	spec.passwordSource = passin();
	spec.pkcs12Algorithm = "PBE-SHA1-3DES";
	try {
		Database.model<db_key>()->exportItems(ctx, spec);
		QFAIL("PKCS#12 algorithm accepted for a PKCS#8 export");
	} catch (serviceError &err) {
		QCOMPARE(err.code, QString("format_not_applicable"));
	}
	QVERIFY(!QFile::exists(spec.fileName));
}

static bool sqlExec(const QString &statement)
{
	QSqlQuery q(QSqlDatabase::database());
	if (q.exec(statement))
		return true;
	qWarning() << statement << q.lastError().text();
	return false;
}

/* The value in the settings table, a null string without a row */
static QString storedSetting(const QString &key)
{
	QSqlQuery q(QSqlDatabase::database());
	q.prepare("SELECT value FROM settings WHERE key_=?");
	q.bindValue(0, key);
	if (q.exec() && q.next())
		return q.value(0).toString();
	return QString();
}

/* The settings of a database of before BTD-52: the old compiled
 * default 3DES, no marker, and "keep legacy" if the user confirmed it */
static bool storeOldSettings(bool keepLegacy)
{
	return sqlExec("DELETE FROM settings WHERE key_ IN "
			"('pkcs12_migrated', 'pkcs12_enc_algo', "
			"'pkcs12_keep_legacy')") &&
		sqlExec("INSERT INTO settings (key_, value) VALUES "
			"('pkcs12_enc_algo', 'PBE-SHA1-3DES')") &&
		(!keepLegacy || sqlExec("INSERT INTO settings (key_, value) "
			"VALUES ('pkcs12_keep_legacy', 'yes')"));
}

static QList<AuditEntry> migrationEntries()
{
	QList<AuditEntry> list;
	for (const AuditEntry &e : AuditLog::entries())
		if (e.action == AuditLog::actionSettingsMigrate)
			list << e;
	return list;
}

/* The stored old compiled default 3DES (the Options dialog wrote it on
 * every OK) becomes AES-256-CBC once, after the unlock, with a message
 * and an audit entry; a legacy algorithm chosen afterwards is kept, and
 * StrictWarning fails on a second message */
void test_service_export_defaults::migrateOldDefault()
{
	QVERIFY(Settings["pkcs12_migrated"]);
	QVERIFY(storeOldSettings(false));

	warning->expectMessage("PBE-SHA1-3DES");
	reopenDatabase();
	QCOMPARE(encAlgo::getDefault().getEncAlgoNid(), NID_aes_256_cbc);
	QCOMPARE(storedSetting("pkcs12_enc_algo"), QString("AES-256-CBC"));
	QCOMPARE(storedSetting("pkcs12_migrated"), QString("yes"));
	QList<AuditEntry> entries = migrationEntries();
	QCOMPARE(entries.size(), 1);
	QCOMPARE(entries[0].objectType, QString("database"));
	QCOMPARE(entries[0].result, QString("success"));
	QCOMPARE(entries[0].params.value("old_pkcs12_algorithm").toString(),
		QString("PBE-SHA1-3DES"));
	QCOMPARE(entries[0].params.value("pkcs12_algorithm").toString(),
		QString("AES-256-CBC"));
	QVERIFY(AuditLog::verify().ok());

	/* chosen now: kept */
	Settings["pkcs12_enc_algo"] = QString("PBE-SHA1-3DES");
	reopenDatabase();
	QVERIFY(encAlgo::getDefault().legacy());
	QCOMPARE(migrationEntries().size(), 1);
}

/* pkcs12_keep_legacy is only set when the user confirmed the legacy
 * algorithm in the warning (Ignore): a choice, so 3DES stays */
void test_service_export_defaults::keepLegacyIsAChoice()
{
	QVERIFY(storeOldSettings(true));
	reopenDatabase();
	QVERIFY(encAlgo::getDefault().legacy());
	QCOMPARE(storedSetting("pkcs12_enc_algo"), QString("PBE-SHA1-3DES"));
	QCOMPARE(storedSetting("pkcs12_keep_legacy"), QString("yes"));
	QVERIFY(Settings["pkcs12_keep_legacy"]);
	QCOMPARE(storedSetting("pkcs12_migrated"), QString("yes"));
	QCOMPARE(migrationEntries().size(), 0);
}

void test_service_export_defaults::migrationIsOneTransaction_data()
{
	QTest::addColumn<QString>("trigger");
	QTest::newRow("marker") << "BEFORE INSERT ON settings "
		"WHEN NEW.key_ = 'pkcs12_migrated'";
	QTest::newRow("audit entry") << "BEFORE INSERT ON audit_log";
}

/* Algorithm, audit entry and marker are one transaction: when one write
 * fails, none is stored, memory keeps the old algorithm, the open goes
 * on without a message, and the next open migrates */
void test_service_export_defaults::migrationIsOneTransaction()
{
	QFETCH(QString, trigger);
	QVERIFY(storeOldSettings(false));
	QVERIFY(sqlExec("CREATE TRIGGER btd52_fault " + trigger +
		" BEGIN SELECT RAISE(ABORT, 'BTD-52 injected'); END"));

	reopenDatabase();
	QVERIFY(encAlgo::getDefault().legacy());
	QVERIFY(!Settings["pkcs12_migrated"]);
	QCOMPARE(storedSetting("pkcs12_enc_algo"), QString("PBE-SHA1-3DES"));
	QVERIFY(storedSetting("pkcs12_migrated").isNull());
	QCOMPARE(migrationEntries().size(), 0);
	QVERIFY(AuditLog::verify().ok());

	QVERIFY(sqlExec("DROP TRIGGER btd52_fault"));
	warning->expectMessage("PBE-SHA1-3DES");
	reopenDatabase();
	QCOMPARE(encAlgo::getDefault().getEncAlgoNid(), NID_aes_256_cbc);
	QCOMPARE(storedSetting("pkcs12_migrated"), QString("yes"));
	QCOMPARE(migrationEntries().size(), 1);
}

/* Settings.clear() with the database still open (a failed password
 * change) keeps the stored values: the statics are read directly */
void test_service_export_defaults::clearKeepsOpenDatabase()
{
	Settings["default_hash"] = QString("SHA512");
	Settings["pkcs12_enc_algo"] = QString("PBE-SHA1-3DES");
	Settings.clear();
	QCOMPARE(digest::getDefault().name(), QString("SHA512"));
	QVERIFY(encAlgo::getDefault().legacy());
}

/* An open whose unlock was cancelled (the BTD-117 path, pwhash set)
 * migrates nothing: no marker, no algorithm, no entry, no message. The
 * next open with the password migrates once with one message, and the
 * one after it shows none (StrictWarning fails on an unexpected one;
 * review of xca#48 MINOR 5, BTD-186) */
void test_service_export_defaults::migrationNeedsUnlock()
{
	QVERIFY(storeOldSettings(false));
	Database.close();
	pwdialog->expect("", pw_cancel);
	try {
		Database.open(dbFile);
	} catch (...) {
		QFAIL("the open without password failed");
	}
	QVERIFY(Database.isOpen());
	QCOMPARE(storedSetting("pkcs12_enc_algo"), QString("PBE-SHA1-3DES"));
	QVERIFY(storedSetting("pkcs12_migrated").isNull());
	QCOMPARE(migrationEntries().size(), 0);

	warning->expectMessage("PBE-SHA1-3DES");
	reopenDatabase();
	QCOMPARE(storedSetting("pkcs12_enc_algo"), QString("AES-256-CBC"));
	QCOMPARE(storedSetting("pkcs12_migrated"), QString("yes"));
	QCOMPARE(migrationEntries().size(), 1);

	reopenDatabase();
	QCOMPARE(migrationEntries().size(), 1);
}

/* BTD-175: the PBKDF2 iteration counts of the encrypted certificates and
 * the shrouded key bag, and the iteration count of the MAC data */
static QList<long> pkcs12Iterations(const QByteArray &der, long *macIter)
{
	QList<long> iters;
	const unsigned char *p = (const unsigned char *)der.constData();
	PKCS12 *p12 = d2i_PKCS12(nullptr, &p, der.size());
	if (!p12)
		return iters;
	const ASN1_INTEGER *mi;
	PKCS12_get0_mac(nullptr, nullptr, nullptr, &mi, p12);
	*macIter = mi ? ASN1_INTEGER_get(mi) : 1;
	STACK_OF(PKCS7) *safes = PKCS12_unpack_authsafes(p12);
	for (int i = 0; i < sk_PKCS7_num(safes); i++) {
		PKCS7 *p7 = sk_PKCS7_value(safes, i);
		int saltLen = 0;
		long iter = 0;
		if (PKCS7_type_is_encrypted(p7)) {
			if (pbkdf2Params(p7->d.encrypted->enc_data->algorithm,
					&saltLen, &iter))
				iters << iter;
			continue;
		}
		STACK_OF(PKCS12_SAFEBAG) *bags = PKCS12_unpack_p7data(p7);
		for (int j = 0; j < sk_PKCS12_SAFEBAG_num(bags); j++) {
			const PKCS12_SAFEBAG *bag =
				sk_PKCS12_SAFEBAG_value(bags, j);
			if (PKCS12_SAFEBAG_get_nid(bag) != NID_pkcs8ShroudedKeyBag)
				continue;
			const X509_ALGOR *alg;
			X509_SIG_get0(PKCS12_SAFEBAG_get0_pkcs8(bag), &alg, nullptr);
			if (pbkdf2Params(alg, &saltLen, &iter))
				iters << iter;
		}
		sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
	}
	sk_PKCS7_pop_free(safes, PKCS7_free);
	PKCS12_free(p12);
	return iters;
}

/* PBMAC1 (RFC 9579) only on request: openssl reads it, the audit entry
 * names the MAC and the iteration count; the default stays HMAC-SHA256
 * with 2048 iterations (BTD-175) */
void test_service_export_defaults::pkcs12Pbmac1()
{
	NEED_OPENSSL();
	pki_x509 *cert = leaf("EC:prime256v1");
	QVERIFY(cert);
	ExportSpec spec;
	spec.items << cert;
	spec.format = pki_export::by_id(15);
	spec.fileName = file("pbmac1.p12");
	spec.passwordSource = passin();
	spec.pkcs12Mac = "pbmac1";
	spec.pkcs12Iterations = 4096;
	Database.model<db_x509>()->exportItems(ctx, spec);

	QString info = opensslOk({ "pkcs12", "-in", spec.fileName, "-info",
			"-noout", "-passin", passin() });
	QVERIFY2(info.contains("MAC: PBMAC1 using PBKDF2, Iteration 4096"),
		CCHAR(info));
	QVERIFY2(info.contains("PBKDF2 PRF: hmacWithSHA256"), CCHAR(info));
	QVERIFY2(info.contains("Shrouded Keybag: PBES2, PBKDF2, AES-256-CBC, "
		"Iteration 4096"), CCHAR(info));
	QVERIFY2(info.contains("PKCS7 Encrypted data: PBES2, PBKDF2, "
		"AES-256-CBC, Iteration 4096"), CCHAR(info));
	QVariantMap p = lastPrivateExport();
	QCOMPARE(p.value("pkcs12_algorithm").toString(), QString("AES-256-CBC"));
	QCOMPARE(p.value("pkcs12_mac").toString(), QString("pbmac1"));
	QCOMPARE(p.value("pkcs12_iterations").toLongLong(), 4096LL);

	/* the default export: HMAC-SHA256, 2048, also in the audit entry */
	QString name = exportTo(cert, 15, "default-mac.p12");
	info = opensslOk({ "pkcs12", "-in", name, "-info", "-noout",
			"-passin", passin() });
	QVERIFY2(info.contains("MAC: sha256, Iteration 2048"), CCHAR(info));
	QVERIFY2(!info.contains("PBMAC1"), CCHAR(info));
	p = lastPrivateExport();
	QCOMPARE(p.value("pkcs12_mac").toString(), QString("hmac-sha256"));
	QCOMPARE(p.value("pkcs12_iterations").toLongLong(), 2048LL);
	QVERIFY(AuditLog::verify().ok());
}

/* The iteration count of one export: the key bag, the certificates and
 * the MAC use it */
void test_service_export_defaults::pkcs12IterationsPerExport()
{
	pki_x509 *cert = leaf("EC:prime256v1");
	QVERIFY(cert);
	ExportSpec spec;
	spec.items << cert;
	spec.format = pki_export::by_id(15);
	spec.fileName = file("iter.p12");
	spec.passwordSource = passin();
	spec.pkcs12Iterations = 5000;
	Database.model<db_x509>()->exportItems(ctx, spec);

	long macIter = 0;
	QList<long> iters = pkcs12Iterations(readFile(spec.fileName), &macIter);
	QCOMPARE(iters, QList<long>({ 5000, 5000 }));
	QCOMPARE(macIter, 5000L);
	QCOMPARE(lastPrivateExport().value("pkcs12_iterations").toLongLong(),
		5000LL);
}

/* The setting pkcs12_iterations is the default of every export of the
 * database; an export may still set its own */
void test_service_export_defaults::pkcs12IterationsSetting()
{
	pki_x509 *cert = leaf("EC:prime256v1");
	QVERIFY(cert);
	QCOMPARE((QString)Settings["pkcs12_iterations"], QString("2048"));
	Settings["pkcs12_iterations"] = QString("10000");
	long macIter = 0;
	QList<long> iters = pkcs12Iterations(readFile(
			exportTo(cert, 15, "setting.p12")), &macIter);
	QCOMPARE(iters, QList<long>({ 10000, 10000 }));
	QCOMPARE(macIter, 10000L);
	QCOMPARE(lastPrivateExport().value("pkcs12_iterations").toLongLong(),
		10000LL);
}

void test_service_export_defaults::pkcs12OptionErrors_data()
{
	QTest::addColumn<int>("format");
	QTest::addColumn<QString>("algorithm");
	QTest::addColumn<QString>("mac");
	QTest::addColumn<int>("iterations");
	QTest::addColumn<QString>("code");
	QTest::newRow("unknown MAC") << 15 << "" << "hmac-md5" << 0
		<< "invalid_pkcs12_mac";
	QTest::newRow("below the minimum") << 15 << "" << "" << 2047
		<< "invalid_pkcs12_iterations";
	QTest::newRow("above the maximum") << 15 << "" << "" << 10000001
		<< "invalid_pkcs12_iterations";
	QTest::newRow("PBMAC1 with legacy") << 15 << "PBE-SHA1-3DES"
		<< "pbmac1" << 0 << "invalid_pkcs12_mac";
	QTest::newRow("iterations with legacy") << 15 << "PBE-SHA1-3DES"
		<< "" << 4096 << "invalid_pkcs12_iterations";
	QTest::newRow("MAC with PKCS#8") << 28 << "" << "pbmac1" << 0
		<< "format_not_applicable";
	QTest::newRow("iterations with PKCS#8") << 28 << "" << "" << 4096
		<< "format_not_applicable";
}

/* Typed errors before anything is written */
void test_service_export_defaults::pkcs12OptionErrors()
{
	QFETCH(int, format);
	QFETCH(QString, algorithm);
	QFETCH(QString, mac);
	QFETCH(int, iterations);
	QFETCH(QString, code);
	pki_x509 *cert = leaf("EC:prime256v1");
	QVERIFY(cert);
	ExportSpec spec;
	spec.items << (format == 15 ? (pki_base *)cert :
				(pki_base *)cert->getRefKey());
	spec.format = pki_export::by_id(format);
	spec.fileName = file("refused.out");
	spec.passwordSource = passin();
	spec.pkcs12Algorithm = algorithm;
	spec.pkcs12Mac = mac;
	spec.pkcs12Iterations = iterations;
	try {
		Database.modelForPki(spec.items[0])->exportItems(ctx, spec);
		QFAIL("export accepted");
	} catch (serviceError &err) {
		QCOMPARE(err.code, code);
	}
	QVERIFY(!QFile::exists(spec.fileName));
}

XCA_SERVICE_TEST_MAIN(test_service_export_defaults)
#include "test_service_export_defaults.moc"
