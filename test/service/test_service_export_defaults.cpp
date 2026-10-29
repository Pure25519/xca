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
#include <QTemporaryDir>

#include <openssl/x509.h>

#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/db_key.h"
#include "lib/db_x509.h"
#include "lib/exception.h"
#include "lib/importexport.h"
#include "lib/issuance.h"
#include "lib/pki_evp.h"
#include "lib/pki_export.h"
#include "lib/pki_pkcs12.h"
#include "lib/pki_x509.h"
#include "lib/settings.h"

#include "ServiceTestCase.h"

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
	void init();
	/* first: a legacy setting stays the static default of encAlgo
	 * when the next database opens */
	void noLegacyWarningByDefault();
	void pkcs12Default_data();
	void pkcs12Default();
	void pkcs12LegacyOnRequest();
	void pkcs12AlgorithmPerExport();
	void keyFormats_data();
	void keyFormats();
	void pkcs12RoundTrip_data();
	void pkcs12RoundTrip();
	void dumpWritesPkcs8();
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

void test_service_export_defaults::init()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#endif
	ServiceTestCase::init();
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

XCA_SERVICE_TEST_MAIN(test_service_export_defaults)
#include "test_service_export_defaults.moc"
