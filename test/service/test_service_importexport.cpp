/* vi: set sw=4 ts=4:
 *
 * Import and export service functions (BTD-34): files made by the openssl
 * program are imported through database_model::importItems(), exported
 * through db_base::exportItems() in PEM, DER, PKCS#8, PKCS#12 and PKCS#7,
 * checked with the openssl program and imported again. Every private key
 * export writes key.export_private without key material or password; a
 * CRL import audits the revocation rows it adds and raises the last CRL
 * number of its CA (BTD-49). A failed export leaves an existing target
 * file as it was, a null item is a service error (BTD-114).
 */

#include <QBuffer>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QSqlError>
#include <QSqlQuery>
#include <QTemporaryDir>

#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/db_crl.h"
#include "lib/db_key.h"
#include "lib/db_x509.h"
#include "lib/exception.h"
#include "lib/importexport.h"
#include "lib/issuance.h"
#include "lib/pki_crl.h"
#include "lib/pki_evp.h"
#include "lib/pki_multi.h"
#include "lib/pki_pkcs12.h"
#include "lib/pki_export.h"
#include "lib/pki_temp.h"
#include "lib/db_temp.h"
#include "lib/pki_x509.h"
#include "lib/sql.h"

#include "ServiceTestCase.h"

#include <openssl/core_names.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/provider.h>
#include <openssl/param_build.h>

static const char exportVar[] = "BTD34_EXPORT_PASS";
static const char exportPass[] = "Export-Secret-34";
static const char p12Var[] = "BTD34_P12_PASS";
static const char p12Pass[] = "P12-Secret-34";

/* Format ids of pki_export::init_elements() */
enum {
	certPem = 1, certPkcs7Chain = 12, certDer = 13, certPkcs12Chain = 14,
	certPkcs12 = 15,
	keyPemPublic = 19, keyPemPrivate = 20, keyDerPublic = 24,
	keyDerPrivate = 25, keyPkcs8Encrypted = 28, keyPkcs8 = 29,
};

class test_service_importexport : public ServiceTestCase
{
	Q_OBJECT

	ServiceContext ctx{ ServiceContext::cli, "os:service-test" };
	QTemporaryDir dir{};

	QString file(const QString &name) const
	{
		return dir.filePath(name);
	}
	QString openssl(const QStringList &args, int *exitCode = nullptr);
	QString opensslOk(const QStringList &args);
	bool opensslRun(const QStringList &args)
	{
		int rc;
		QString out = openssl(args, &rc);
		if (rc != 0)
			qWarning().noquote() << "openssl" << args.join(" ")
				<< "\n" << out;
		return rc == 0;
	}
	/* openssl x509 -fingerprint of a PEM or DER certificate file */
	QString certFingerprint(const QString &name, const QString &form);
	/* openssl pkey -pubout of a key file */
	QString publicKey(const QString &name, const QStringList &extra);
	/* CA key, CA certificate, end-entity key and certificate */
	ImportResult importChain();
	pki_x509 *cert(const QString &name);
	QByteArray exportTo(db_base *db, pki_base *pki, int format,
			const QString &name, const QString &source = QString());
	QList<AuditEntry> entries(const QString &action);
	void checkNoSecret(const QByteArray &secret);
	/* An empty CRL of ca.pem with this CRL number, by openssl ca */
	bool opensslCrl(const QString &name, int number, int days);
	pki_crl *importCrl(const QString &name);
	/* authority.crlNo and crlExpire of the CA in the database */
	QPair<qint64, QString> authorityCrl(pki_x509 *ca);
	/* BTD-16: a key of the type through the service, its public key
	 * as PEM, an RSA CA and a certificate of the CA for a key */
	pki_key *newKey(const QString &type, const QString &name);
	static QString publicPem(pki_key *key);
	pki_x509 *rsaCa();
	pki_x509 *certFor(pki_key *key, pki_x509 *ca);
	/* The privateKey content tag of a PKCS#8 file (DER, PEM or
	 * encrypted PEM with the export password): 0x80 seed, 0x04
	 * expanded key, 0x30 both (RFC 9881) */
	static int mlDsaTag(const QString &name, int format);
	QByteArray exportFormat(db_base *db, pki_base *pki, int format,
			const QString &name, const QString &keyFormat);
	/* PKCS#8 of an ML-DSA-44 key whose "both" encoding holds the seed
	 * of one key and the expanded key of another; as PEM file */
	static PKCS8_PRIV_KEY_INFO *mismatchedMlDsa();
	bool writeMismatchedMlDsa(const QString &name);
	/* Replaces service.xdb with a dump of data/ and opens it */
	void loadDump(const QString &name);
	/* importItems() of one file: the error code, "no_key" if it stored
	 * no key without an error (the PEM reader refused the key, with its
	 * message), or "" if it stored a key; *created the new keys */
	QString importError(const QString &name, QList<pki_base *> *created);
	/* The ML-DSA settings of the default provider match the openssl.cnf
	 * of the cnf run XCA_TEST_MLDSA_CNF (none without it) */
	void checkOpensslConf();

  private slots:
	void initTestCase();
	void importCreatesAndMatches();
	void certificateRoundTrip_data();
	void certificateRoundTrip();
	void keyRoundTrip_data();
	void keyRoundTrip();
	void pkcs12RoundTrip();
	void pkcs7ChainRoundTrip();
	void privateExportAudit();
	void clipboardPrivateKey();
	void privateExportEncrypted_data();
	void privateExportEncrypted();
	void crlImportAuditsRevocations();
	void crlImportRaisesCrlNumber();
	void crlGeneratedAfterImport();
	void templateCopyExport();
	void rejections();
	void exportFailureKeepsFile();
	void exportOverwritesKeyOwnerOnly();
	void exportNullItem();
	void importRollbackHandsBack();
	void fixedKeyRoundTrip_data();
	void fixedKeyRoundTrip();
	void fixedKeyPkcs12_data();
	void fixedKeyPkcs12();
	void mlDsaPrivateFormat_data();
	void mlDsaPrivateFormat();
	void mlDsaPkcs12Expanded();
	void mlDsaWithoutSeed();
	void mlDsaFormatRejected();
	void importOpensslFixed_data();
	void importOpensslFixed();
	void mlDsaEncodingPerKey();
	void mlDsaMismatchRejected();
	void mlDsaUnderOpensslConf();
	void fixedKeyFormatsRefused_data();
	void fixedKeyFormatsRefused();
	void mlDsaSeedlessPasswordChange();
	void mlDsaUndecodableStoredKey();
	void opensslBoolSetting_data();
	void opensslBoolSetting();
	void mlDsaStoredBy51_data();
	void mlDsaStoredBy51();
	void mlDsaOwnPass();
	void keyReadErrorNamesSource();
	void pkcs12CreateFailureFrees();
	void keyIncompleteNamesSource();
};

QString test_service_importexport::openssl(const QStringList &args,
					int *exitCode)
{
#ifdef OPENSSL_PROGRAM
	QProcess p;
	p.setProcessChannelMode(QProcess::MergedChannels);
	/* the openssl program makes the fixtures with its defaults, not
	 * with the openssl.cnf of mlDsaUnderOpensslConf (BTD-16) */
	QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
	env.remove("OPENSSL_CONF");
	p.setProcessEnvironment(env);
	p.start(OPENSSL_PROGRAM, args);
	int rc = p.waitForFinished(30000) ? p.exitCode() : -1;
	if (exitCode)
		*exitCode = rc;
	return QString::fromUtf8(p.readAll());
#else
	(void)args;
	if (exitCode)
		*exitCode = -1;
	return QString();
#endif
}

QString test_service_importexport::opensslOk(const QStringList &args)
{
	int rc;
	QString out = openssl(args, &rc);
	if (rc != 0)
		qWarning().noquote() << "openssl" << args.join(" ") << "\n" << out;
	return rc == 0 ? out : QString();
}

QString test_service_importexport::certFingerprint(const QString &name,
					const QString &form)
{
	return opensslOk({ "x509", "-in", name, "-inform", form, "-noout",
			"-fingerprint", "-sha256" }).trimmed();
}

QString test_service_importexport::publicKey(const QString &name,
					const QStringList &extra)
{
	return opensslOk(QStringList({ "pkey", "-in", name, "-pubout" }) + extra);
}

void test_service_importexport::initTestCase()
{
	ServiceTestCase::initTestCase();
#ifdef OPENSSL_PROGRAM
	qputenv(exportVar, exportPass);
	qputenv(p12Var, p12Pass);
	QStringList ec { "genpkey", "-algorithm", "EC",
			"-pkeyopt", "ec_paramgen_curve:P-256", "-out" };
	QVERIFY(opensslRun(ec + QStringList(file("ca.key"))));
	QVERIFY(opensslRun(ec + QStringList(file("leaf.key"))));
	QVERIFY(opensslRun({ "req", "-x509", "-new", "-key", file("ca.key"),
		"-subj", "/CN=BTD34 CA", "-days", "30", "-out", file("ca.pem"),
		"-addext", "basicConstraints=critical,CA:TRUE",
		"-addext", "keyUsage=critical,keyCertSign,cRLSign" }));
	QVERIFY(opensslRun({ "req", "-new", "-key", file("leaf.key"),
		"-subj", "/CN=BTD34 Leaf", "-out", file("leaf.csr") }));
	QVERIFY(opensslRun({ "x509", "-req", "-in", file("leaf.csr"),
		"-CA", file("ca.pem"), "-CAkey", file("ca.key"),
		"-set_serial", "0x1234ABCD", "-days", "10",
		"-out", file("leaf.pem") }));
	QVERIFY(opensslRun({ "pkcs12", "-export", "-in", file("leaf.pem"),
		"-inkey", file("leaf.key"), "-certfile", file("ca.pem"),
		"-name", "BTD34 Leaf", "-passout", QString("env:%1").arg(p12Var),
		"-out", file("leaf.p12") }));
#endif
}

ImportResult test_service_importexport::importChain()
{
	ImportSpec spec;
	spec.files << file("ca.key") << file("ca.pem")
		<< file("leaf.key") << file("leaf.pem");
	return Database.importItems(ctx, spec);
}

pki_x509 *test_service_importexport::cert(const QString &name)
{
	foreach(pki_x509 *c, Store.getAll<pki_x509>()) {
		if (c->getSubject().getEntryByNid(NID_commonName) == name)
			return c;
	}
	return nullptr;
}

QByteArray test_service_importexport::exportTo(db_base *db, pki_base *pki,
		int format, const QString &name, const QString &source)
{
	ExportSpec spec;
	spec.items << pki;
	spec.format = pki_export::by_id(format);
	spec.fileName = name;
	spec.passwordSource = source;
	return db->exportItems(ctx, spec);
}

QList<AuditEntry> test_service_importexport::entries(const QString &action)
{
	QList<AuditEntry> list;
	foreach(const AuditEntry &e, AuditLog::entries()) {
		if (e.action == action)
			list << e;
	}
	return list;
}

/* Neither the bytes nor their Base64 or hex form nor any line of a PEM
 * body is in the audit log */
void test_service_importexport::checkNoSecret(const QByteArray &secret)
{
	QByteArray log = AuditLog::exportJsonLines();
	QVERIFY(!secret.isEmpty());
	QVERIFY(!log.contains(secret));
	QVERIFY(!log.contains(secret.toBase64()));
	QVERIFY(!log.contains(secret.toHex()));
	foreach(QByteArray line, secret.split('\n')) {
		line = line.trimmed();
		if (line.size() >= 16 && !line.startsWith("-----"))
			QVERIFY2(!log.contains(line), line.constData());
	}
}

/* Import from files made by openssl: four objects created, the same
 * files again only matched; one object.import entry per object */
void test_service_importexport::importCreatesAndMatches()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	ImportResult r = importChain();
	QCOMPARE(r.created.size(), 4);
	QCOMPARE(r.existing.size(), 0);
	QVERIFY(r.failedFiles.isEmpty());
	pki_x509 *leaf = cert("BTD34 Leaf");
	QVERIFY(leaf);
	QCOMPARE(leaf->getSigner(), cert("BTD34 CA"));
	QVERIFY(leaf->getRefKey() && leaf->getRefKey()->isPrivKey());

	QList<AuditEntry> imports = entries("object.import");
	QCOMPARE(imports.size(), 4);
	foreach(const AuditEntry &e, imports) {
		QCOMPARE(e.result, QString("success"));
		QCOMPARE(e.params.value("outcome").toString(), QString("created"));
		QVERIFY(!e.objectId.isEmpty());
		QVERIFY(!e.params.value("fingerprint").toString().isEmpty());
	}
	QCOMPARE(imports[3].objectType, QString("certificate"));
	QCOMPARE(imports[3].objectId, leaf->getSqlItemId().toString());

	r = importChain();
	QCOMPARE(r.created.size(), 0);
	QCOMPARE(r.existing.size(), 4);
	QCOMPARE(entries("object.import").size(), 8);
	QCOMPARE(entries("object.import").last().params.value("outcome")
			.toString(), QString("existing"));
	QVERIFY(AuditLog::verify().ok());
#endif
}

void test_service_importexport::certificateRoundTrip_data()
{
	QTest::addColumn<int>("format");
	QTest::addColumn<QString>("form");
	QTest::newRow("PEM") << (int)certPem << "PEM";
	QTest::newRow("DER") << (int)certDer << "DER";
}

/* Export the certificate, check it with openssl, import it again */
void test_service_importexport::certificateRoundTrip()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	QFETCH(int, format);
	QFETCH(QString, form);
	importChain();
	pki_x509 *leaf = cert("BTD34 Leaf");
	QVERIFY(leaf);
	QString out = file("export-cert." + form.toLower());

	QByteArray bytes = exportTo(Database.model<db_x509>(), leaf, format, out);
	QVERIFY(!bytes.isEmpty());
	QString fp = certFingerprint(out, form);
	QVERIFY(!fp.isEmpty());
	QCOMPARE(fp, certFingerprint(file("leaf.pem"), "PEM"));

	AuditEntry e = entries("object.export").last();
	QCOMPARE(e.result, QString("success"));
	QCOMPARE(e.objectId, leaf->getSqlItemId().toString());
	QCOMPARE(e.params.value("format").toLongLong(), (qint64)format);
	QCOMPARE(e.params.value("file").toString(), out);
	QCOMPARE(entries("key.export_private").size(), 0);

	/* Bytes in, the same certificate out */
	ImportSpec spec;
	spec.data = bytes;
	spec.dataName = "upload." + form.toLower();
	ImportResult r = Database.importItems(ctx, spec);
	QCOMPARE(r.created.size(), 0);
	QCOMPARE(r.existing, QList<pki_base *>() << leaf);
	QVERIFY(AuditLog::verify().ok());
#endif
}

void test_service_importexport::keyRoundTrip_data()
{
	QTest::addColumn<int>("format");
	QTest::addColumn<QStringList>("opensslArgs");
	QTest::addColumn<QString>("header");
	QTest::newRow("PEM") << (int)keyPemPrivate << QStringList()
		<< "-----BEGIN EC PRIVATE KEY-----";
	QTest::newRow("DER") << (int)keyDerPrivate
		<< QStringList({ "-inform", "DER" }) << QString();
	QTest::newRow("PKCS#8 encrypted") << (int)keyPkcs8Encrypted
		<< QStringList({ "-passin", QString("env:%1").arg(exportVar) })
		<< "-----BEGIN ENCRYPTED PRIVATE KEY-----";
}

/* Export the private key, read it with openssl, import it again */
void test_service_importexport::keyRoundTrip()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	QFETCH(int, format);
	QFETCH(QStringList, opensslArgs);
	QFETCH(QString, header);
	importChain();
	pki_key *key = cert("BTD34 Leaf")->getRefKey();
	QVERIFY(key);
	bool encrypted = pki_export::by_id(format)->match_all(F_CRYPT);
	QString source = encrypted ? QString("env:%1").arg(exportVar) : QString();
	QString out = file(QString("export-key-%1").arg(format));

	QByteArray bytes = exportTo(Database.model<db_key>(), key, format,
					out, source);
	if (!header.isEmpty())
		QVERIFY(bytes.contains(header.toLatin1()));
	QString pub = publicKey(out, opensslArgs);
	QVERIFY(!pub.isEmpty());
	QCOMPARE(pub, publicKey(file("leaf.key"), QStringList()));
	if (encrypted) {
		int rc;
		openssl({ "pkey", "-in", out, "-passin", "pass:wrong" }, &rc);
		QVERIFY(rc != 0);
	}
	QCOMPARE(QFile(out).permissions() & (QFile::ReadGroup |
		QFile::ReadOther), QFileDevice::Permissions());

	QList<AuditEntry> priv = entries("key.export_private");
	QCOMPARE(priv.size(), 1);
	QCOMPARE(priv[0].objectType, QString("key"));
	QCOMPARE(priv[0].objectId, key->getSqlItemId().toString());
	QCOMPARE(priv[0].params.value("encrypted").toBool(), encrypted);
	QCOMPARE(priv[0].params.value("fingerprint").toString(),
		key->fingerprint("der sha256"));

	ImportSpec spec;
	spec.files << out;
	spec.passwordSource = source;
	ImportResult r = Database.importItems(ctx, spec);
	QCOMPARE(r.created.size(), 0);
	QCOMPARE(r.existing, QList<pki_base *>() << key);
	QVERIFY(AuditLog::verify().ok());
#endif
}

/* An openssl PKCS#12 file with the password from env: creates key,
 * certificate and CA; the PKCS#12 export of the chain reads back with
 * openssl and imports again as the same three objects */
void test_service_importexport::pkcs12RoundTrip()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	QFile p12(file("leaf.p12"));
	QVERIFY(p12.open(QIODevice::ReadOnly));
	ImportSpec in;
	in.data = p12.readAll();
	in.dataName = "leaf.p12";
	in.passwordSource = QString("env:%1").arg(p12Var);
	ImportResult r = Database.importItems(ctx, in);
	QCOMPARE(r.created.size(), 3);
	pki_x509 *leaf = cert("BTD34 Leaf");
	QVERIFY(leaf);
	QCOMPARE(leaf->getSigner(), cert("BTD34 CA"));
	QVERIFY(leaf->getRefKey() && leaf->getRefKey()->isPrivKey());

	QString out = file("export.p12");
	QString source = QString("env:%1").arg(exportVar);
	exportTo(Database.model<db_x509>(), leaf, certPkcs12Chain, out, source);
	QString certs = opensslOk({ "pkcs12", "-in", out, "-nokeys",
			"-passin", source });
	QCOMPARE(certs.count("-----BEGIN CERTIFICATE-----"), 2);
	QVERIFY(certs.contains("CN=BTD34 Leaf"));
	QVERIFY(certs.contains("CN=BTD34 CA"));
	QString keyPem = opensslOk({ "pkcs12", "-in", out, "-nocerts",
			"-noenc", "-passin", source });
	QFile k(file("p12-key.pem"));
	QVERIFY(k.open(QIODevice::WriteOnly));
	k.write(keyPem.toLatin1());
	k.close();
	QCOMPARE(publicKey(k.fileName(), QStringList()),
		publicKey(file("leaf.key"), QStringList()));

	/* One object.export per certificate of the chain, one
	 * key.export_private for the key of the certificate */
	QCOMPARE(entries("object.export").size(), 2);
	QCOMPARE(entries("key.export_private").size(), 1);
	QCOMPARE(entries("key.export_private")[0].objectId,
		leaf->getRefKey()->getSqlItemId().toString());

	ImportSpec again;
	again.files << out;
	again.passwordSource = source;
	r = Database.importItems(ctx, again);
	QCOMPARE(r.created.size(), 0);
	QCOMPARE(r.existing.size(), 3);
	QVERIFY(AuditLog::verify().ok());
#endif
}

/* The PKCS#7 chain of the end entity holds both certificates */
void test_service_importexport::pkcs7ChainRoundTrip()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	importChain();
	pki_x509 *leaf = cert("BTD34 Leaf");
	QVERIFY(leaf);
	QString out = file("chain.p7b");
	exportTo(Database.model<db_x509>(), leaf, certPkcs7Chain, out);
	QString printed = opensslOk({ "pkcs7", "-in", out, "-inform", "DER",
			"-print_certs" });
	QCOMPARE(printed.count("-----BEGIN CERTIFICATE-----"), 2);
	QVERIFY(printed.contains("CN=BTD34 Leaf"));
	QVERIFY(printed.contains("CN=BTD34 CA"));
	QCOMPARE(entries("object.export").size(), 2);
	QCOMPARE(entries("key.export_private").size(), 0);

	ImportSpec spec;
	spec.files << out;
	ImportResult r = Database.importItems(ctx, spec);
	QCOMPARE(r.existing.size(), 2);
	QVERIFY(r.existing.contains(leaf));
	QVERIFY(r.existing.contains(cert("BTD34 CA")));
	QVERIFY(AuditLog::verify().ok());
#endif
}

/* Acceptance criterion 2: every private key export writes
 * key.export_private, and no audit entry holds key material or the
 * password */
void test_service_importexport::privateExportAudit()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	importChain();
	pki_x509 *leaf = cert("BTD34 Leaf");
	pki_key *key = leaf->getRefKey();
	QString source = QString("env:%1").arg(exportVar);
	QList<QByteArray> outputs;

	outputs << exportTo(Database.model<db_key>(), key, keyPemPrivate,
				QString());
	outputs << exportTo(Database.model<db_key>(), key, keyDerPrivate,
				QString());
	outputs << exportTo(Database.model<db_key>(), key,
				keyPkcs8Encrypted, QString(), source);
	outputs << exportTo(Database.model<db_x509>(), leaf,
				certPkcs12Chain, QString(), source);
	/* PEM + key, OpenVPN */
	outputs << exportTo(Database.model<db_x509>(), leaf, 6, QString());
	outputs << exportTo(Database.model<db_x509>(), leaf, 4, QString());
	QCOMPARE(entries("key.export_private").size(), outputs.size());

	/* The unencrypted private key in DER, as openssl writes it */
	QVERIFY(opensslRun({ "pkey", "-in", file("leaf.key"),
			"-outform", "DER", "-out", file("leaf.der") }));
	QFile derFile(file("leaf.der"));
	QVERIFY(derFile.open(QIODevice::ReadOnly));
	QByteArray der = derFile.readAll();
	QFile keyFile(file("leaf.key"));
	QVERIFY(keyFile.open(QIODevice::ReadOnly));
	QByteArray keyPem = keyFile.readAll();

	checkNoSecret(exportPass);
	checkNoSecret(keyPem);
	checkNoSecret(der);
	foreach(const QByteArray &out, outputs)
		checkNoSecret(out);
	foreach(const AuditEntry &e, entries("key.export_private")) {
		QCOMPARE(e.result, QString("success"));
		QCOMPARE(e.objectId, key->getSqlItemId().toString());
		foreach(const QString &k, e.params.keys())
			QVERIFY2(AuditParams::allowed(k), qPrintable(k));
	}
	QVERIFY(AuditLog::verify().ok());
#endif
}

/* Ctrl+C and dragging export the clipboard text: with a private key
 * clipboard format that is a private key export */
void test_service_importexport::clipboardPrivateKey()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	importChain();
	pki_key *key = cert("BTD34 Leaf")->getRefKey();
	ExportSpec spec;
	spec.items << key;
	spec.clipboard = true;

	Settings["KeyFormat"] = QString::number(keyPemPrivate);
	QByteArray text = Database.model<db_key>()->exportItems(ctx, spec);
	QVERIFY(text.contains("PRIVATE KEY"));
	QCOMPARE(entries("key.export_private").size(), 1);
	QCOMPARE(entries("object.export").last().params.value("format")
			.toString(), QString("clipboard"));
	checkNoSecret(text);

	/* Public key format: no private key export */
	Settings["KeyFormat"] = QString::number(19);
	text = Database.model<db_key>()->exportItems(ctx, spec);
	QVERIFY(text.contains("PUBLIC KEY"));
	QCOMPARE(entries("key.export_private").size(), 1);
#endif
}

/* Regression (BTD-34, review of xca#17): key.export_private records
 * whether the private key left encrypted. The clipboard text of
 * CertFormat 7 ("PEM + PKCS#8") holds a traditional, unencrypted PEM key
 * (pki_evp::pem()), the entry said encrypted=true. privateExportAudit
 * checked the number, the parameter names and the absence of secrets of
 * the entries, not this value, and clipboardPrivateKey used only the key
 * format 20. Likewise a PKCS#12 file with an empty password (accepted
 * from the password dialog, a password source is never empty) was
 * audited as encrypted=true, although anyone reads the key; no test
 * exported with an empty password.
 *
 * Every private key format, as written and as audited:
 *   format                     target           encrypted
 *    4 OpenVPN                 file             no
 *    6 PEM + key               file, clipboard  no
 *    7 PEM + PKCS#8            file             yes (AES-256-CBC)
 *    7 PEM + PKCS#8            clipboard        no
 *   14 PKCS #12 chain          file             yes
 *   14 PKCS #12 chain          file, empty pw   no
 *   15 PKCS #12                file             yes
 *   15 PKCS #12                file, empty pw   no
 *   20 PEM private             file, clipboard  no
 *   21 PEM encrypted           file             yes (AES-256-CBC)
 *   22 SSH2 private            file             no
 *   25 DER private             file             no
 *   26 PVK private (RSA, DSA)  file             no
 *   28 PKCS #8 encrypted       file             yes (AES-256-CBC)
 *   29 PKCS #8                 file, clipboard  no
 *   50 JSON Web Key private    file             no
 *  7, 21, 28 with an empty password: rejected (missing_password), no
 *   key.export_private
 * Checked with the openssl program: an encrypted key reads with the
 * export password and not with a wrong one; PKCS#12 holds the key in a
 * shrouded key bag that does not open with an empty password; a private
 * JWK has its "d" member in clear. */
void test_service_importexport::privateExportEncrypted_data()
{
	QTest::addColumn<bool>("isCert");
	QTest::addColumn<int>("format");
	QTest::addColumn<bool>("clipboard");
	QTest::addColumn<bool>("encrypted");
	QTest::addColumn<bool>("emptyPassword");

	QTest::newRow("4 OpenVPN") << true << 4 << false << false << false;
	QTest::newRow("6 PEM + key") << true << 6 << false << false << false;
	QTest::newRow("6 PEM + key, clipboard") << true << 6 << true << false << false;
	QTest::newRow("7 PEM + PKCS#8") << true << 7 << false << true << false;
	QTest::newRow("7 PEM + PKCS#8, clipboard") << true << 7 << true << false << false;
	QTest::newRow("14 PKCS#12 chain") << true << 14 << false << true << false;
	QTest::newRow("15 PKCS#12") << true << 15 << false << true << false;
	QTest::newRow("20 PEM private") << false << 20 << false << false << false;
	QTest::newRow("20 PEM private, clipboard") << false << 20 << true << false << false;
	QTest::newRow("21 PEM encrypted") << false << 21 << false << true << false;
	QTest::newRow("22 SSH2 private") << false << 22 << false << false << false;
	QTest::newRow("25 DER private") << false << 25 << false << false << false;
	QTest::newRow("26 PVK private") << false << 26 << false << false << false;
	QTest::newRow("28 PKCS#8 encrypted") << false << 28 << false << true << false;
	QTest::newRow("29 PKCS#8") << false << 29 << false << false << false;
	QTest::newRow("29 PKCS#8, clipboard") << false << 29 << true << false << false;
	QTest::newRow("50 JWK private") << false << 50 << false << false << false;
	QTest::newRow("7 PEM + PKCS#8, empty password")
		<< true << 7 << false << false << true;
	QTest::newRow("14 PKCS#12 chain, empty password")
		<< true << 14 << false << false << true;
	QTest::newRow("15 PKCS#12, empty password")
		<< true << 15 << false << false << true;
	QTest::newRow("21 PEM encrypted, empty password")
		<< false << 21 << false << false << true;
	QTest::newRow("28 PKCS#8 encrypted, empty password")
		<< false << 28 << false << false << true;
}

void test_service_importexport::privateExportEncrypted()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	QFETCH(bool, isCert);
	QFETCH(int, format);
	QFETCH(bool, clipboard);
	QFETCH(bool, encrypted);
	QFETCH(bool, emptyPassword);
	QString passin = QString("env:%1").arg(exportVar);
	const pki_export *xport = pki_export::by_id(format);

	importChain();
	pki_x509 *leaf = cert("BTD34 Leaf");
	pki_base *item = isCert ? (pki_base *)leaf : leaf->getRefKey();
	db_base *db = isCert ? (db_base *)Database.model<db_x509>() :
				Database.model<db_key>();
	if (format == 26) {
		/* PVK takes RSA and DSA keys only */
		QVERIFY(opensslRun({ "genpkey", "-algorithm", "RSA",
			"-pkeyopt", "rsa_keygen_bits:2048", "-out", file("rsa.key") }));
		ImportSpec spec;
		spec.files << file("rsa.key");
		ImportResult r = Database.importItems(ctx, spec);
		QCOMPARE(r.created.size(), 1);
		item = r.created[0];
	}

	QByteArray out;
	if (clipboard) {
		Settings[isCert ? "CertFormat" : "KeyFormat"] =
						QString::number(format);
		ExportSpec spec;
		spec.items << item;
		spec.clipboard = true;
		out = db->exportItems(ctx, spec);
	} else if (emptyPassword) {
		/* The password dialog returns an empty password: refused
		 * outside the GUI for every format, PKCS#12 included (review
		 * of xca#62: it protects nothing) */
		pwdialog->expect(QByteArray());
		try {
			exportTo(db, item, format, QString());
			QFAIL("empty password accepted outside the GUI");
		} catch (serviceError &err) {
			QCOMPARE(err.code, QString("missing_password"));
			QCOMPARE(entries("key.export_private").size(), 0);
			QCOMPARE(entries("object.export").last().errorCode,
				QString("missing_password"));
		}
		if (!xport->match_all(F_PKCS12))
			return;
		/* the GUI keeps XCA's behaviour: PKCS#12 accepts it */
		pwdialog->expect(QByteArray());
		ExportSpec spec;
		spec.items << item;
		spec.format = xport;
		out = db->exportItems(ServiceContext(ServiceContext::gui,
						"os:service-test"), spec);
	} else {
		out = exportTo(db, item, format, QString(), passin);
	}
	QList<AuditEntry> keys = entries("key.export_private");
	QCOMPARE(keys.size(), 1);

	QString name = file(QString("encrypted-%1.out").arg(format));
	QFile f(name);
	QVERIFY(f.open(QIODevice::WriteOnly | QIODevice::Truncate));
	f.write(out);
	f.close();

	bool written;
	if (xport->match_all(F_PKCS12)) {
		if (!emptyPassword) {
			QString info = opensslOk({ "pkcs12", "-in", name,
				"-info", "-noenc", "-passin", passin });
			QVERIFY(info.contains("PRIVATE KEY"));
			QVERIFY(info.contains("Shrouded Keybag"));
		}
		int rc;
		QString info = openssl({ "pkcs12", "-in", name, "-info",
				"-noenc", "-passin", "pass:" }, &rc);
		written = !(rc == 0 && info.contains("PRIVATE KEY"));
	} else if (xport->match_all(F_JWK)) {
		QJsonObject jwk = QJsonDocument::fromJson(out).object();
		QVERIFY(jwk.contains("kty"));
		written = !jwk.contains("d");
	} else {
		QVERIFY(opensslRun({ "pkey", "-in", name, "-noout",
				"-passin", passin }));
		int rc;
		openssl({ "pkey", "-in", name, "-noout",
			"-passin", "pass:wrong-password" }, &rc);
		written = rc != 0;
	}
	QCOMPARE(written, encrypted);
	QCOMPARE(keys[0].params.value("encrypted").toBool(), encrypted);
#endif
}

/* Regression (BTD-34): a CRL imported for a CA of the database adds
 * revocation rows. The import wrote them without audit entries, so
 * AuditLog::verify() reported them as unaudited. */
void test_service_importexport::crlImportAuditsRevocations()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	QFile index(file("index.txt"));
	QVERIFY(index.open(QIODevice::WriteOnly | QIODevice::Truncate));
	index.write("R\t300101000000Z\t260101000000Z,keyCompromise\t1234ABCD\t"
		"unknown\t/CN=BTD34 Leaf\n");
	index.close();
	QFile crlnumber(file("crlnumber"));
	QVERIFY(crlnumber.open(QIODevice::WriteOnly | QIODevice::Truncate));
	crlnumber.write("05\n");
	crlnumber.close();
	QFile cnf(file("ca.cnf"));
	QVERIFY(cnf.open(QIODevice::WriteOnly | QIODevice::Truncate));
	cnf.write(QString("[ ca ]\ndefault_ca = CA_default\n"
		"[ CA_default ]\ndatabase = %1\ncrlnumber = %2\n"
		"default_md = sha256\ndefault_crl_days = 7\n")
		.arg(index.fileName(), crlnumber.fileName()).toUtf8());
	cnf.close();
	QVERIFY(opensslRun({ "ca", "-gencrl", "-config", cnf.fileName(),
		"-keyfile", file("ca.key"), "-cert", file("ca.pem"),
		"-out", file("ca.crl") }));

	importChain();
	pki_x509 *ca = cert("BTD34 CA");
	pki_x509 *leaf = cert("BTD34 Leaf");
	QVERIFY(!leaf->isRevoked());

	ImportSpec spec;
	spec.files << file("ca.crl");
	ImportResult r = Database.importItems(ctx, spec);
	QCOMPARE(r.created.size(), 1);
	QCOMPARE(entries("object.import").last().objectType, QString("crl"));

	QList<AuditEntry> revokes = entries(AuditLog::actionRevoke);
	QCOMPARE(revokes.size(), 1);
	QCOMPARE(revokes[0].params.value("ca_id").toLongLong(),
		ca->getSqlItemId().toLongLong());
	QCOMPARE(revokes[0].params.value("serial").toString(),
		QString("1234ABCD"));
	QCOMPARE(revokes[0].objectId, leaf->getSqlItemId().toString());
	AuditVerifyResult v = AuditLog::verify();
	QCOMPARE(v.unauditedRevocations, 0);
	QVERIFY2(v.ok(), v.toJson().constData());
#endif
}

bool test_service_importexport::opensslCrl(const QString &name, int number,
					int days)
{
	QFile index(file("crl-index.txt"));
	QFile crlnumber(file("crl-number"));
	QFile cnf(file("crl-ca.cnf"));
	if (!index.open(QIODevice::WriteOnly | QIODevice::Truncate) ||
	    !crlnumber.open(QIODevice::WriteOnly | QIODevice::Truncate) ||
	    !cnf.open(QIODevice::WriteOnly | QIODevice::Truncate))
		return false;
	index.close();
	crlnumber.write(QString("%1\n").arg(number, 2, 16, QChar('0'))
			.toUtf8());
	crlnumber.close();
	cnf.write(QString("[ ca ]\ndefault_ca = CA_default\n"
		"[ CA_default ]\ndatabase = %1\ncrlnumber = %2\n"
		"default_md = sha256\n")
		.arg(index.fileName(), crlnumber.fileName()).toUtf8());
	cnf.close();
	return opensslRun({ "ca", "-gencrl", "-config", cnf.fileName(),
		"-keyfile", file("ca.key"), "-cert", file("ca.pem"),
		"-crldays", QString::number(days), "-out", file(name) });
}

pki_crl *test_service_importexport::importCrl(const QString &name)
{
	ImportSpec spec;
	spec.files << file(name);
	return dynamic_cast<pki_crl *>(
		Database.importItems(ctx, spec).created.value(0));
}

QPair<qint64, QString> test_service_importexport::authorityCrl(pki_x509 *ca)
{
	XSqlQuery q;
	SQL_PREPARE(q, "SELECT crlNo, crlExpire FROM authority WHERE item=?");
	q.bindValue(0, ca->getSqlItemId());
	q.exec();
	if (!q.first())
		return QPair<qint64, QString>(-1, QString());
	return qMakePair(q.value(0).toLongLong(), q.value(1).toString());
}

/* Regression (BTD-49): a CRL imported for a CA of the database left
 * authority.crlNo and crlExpire alone, only CRL generation set them.
 * The CA's CRL state follows the highest CRL number, not the latest
 * nextUpdate (PLAN.md Phase 4.3, OpenXPKI #980): a lower or equal
 * number changes nothing, even with a later nextUpdate. */
void test_service_importexport::crlImportRaisesCrlNumber()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	QVERIFY(opensslCrl("crl5.crl", 5, 7));
	QVERIFY(opensslCrl("crl3.crl", 3, 30));
	QVERIFY(opensslCrl("crl5-later.crl", 5, 60));

	importChain();
	pki_x509 *ca = cert("BTD34 CA");
	QCOMPARE(authorityCrl(ca).first, 0LL);

	pki_crl *crl5 = importCrl("crl5.crl");
	QVERIFY(crl5);
	QCOMPARE(crl5->getIssuer(), ca);
	QString expire5 = crl5->getNextUpdate().toPlain();
	QCOMPARE(authorityCrl(ca), qMakePair(5LL, expire5));
	QCOMPARE(ca->getCrlNumber().toDec(), QString("5"));
	AuditEntry e = entries("object.import").last();
	QCOMPARE(e.objectType, QString("crl"));
	QCOMPARE(e.params.value("ca_id").toLongLong(),
		ca->getSqlItemId().toLongLong());
	QCOMPARE(e.params.value("crl_number").toLongLong(), 5LL);
	QCOMPARE(e.params.value("next_update").toString(),
		AuditLog::rfc3339(crl5->getNextUpdate()));
	QCOMPARE(e.params.value("authority_updated").toBool(), true);

	/* lower number with a later nextUpdate, then the same number */
	foreach(const QString &name, QStringList({ "crl3.crl",
						"crl5-later.crl" })) {
		pki_crl *crl = importCrl(name);
		QVERIFY2(crl, qPrintable(name));
		QVERIFY(crl->getNextUpdate() > crl5->getNextUpdate());
		QCOMPARE(authorityCrl(ca), qMakePair(5LL, expire5));
		QCOMPARE(ca->getCrlNumber().toDec(), QString("5"));
		e = entries("object.import").last();
		QCOMPARE(e.params.value("crl_number").toLongLong(),
			crl->getCrlNumber().toDec().toLongLong());
		QCOMPARE(e.params.value("authority_updated").toBool(), false);
	}
	AuditVerifyResult v = AuditLog::verify();
	QVERIFY2(v.ok(), v.toJson().constData());
#endif
}

/* Regression (BTD-49): after the import of CRL 5 the next generated CRL
 * got number 1, below a CRL already known for the CA (certstrap rule 7) */
void test_service_importexport::crlGeneratedAfterImport()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	QVERIFY(opensslCrl("crl5.crl", 5, 7));
	importChain();
	pki_x509 *ca = cert("BTD34 CA");
	QVERIFY(importCrl("crl5.crl"));

	pki_crl *next = Database.model<db_crl>()->newCrl(ctx, crljob(ca));
	QVERIFY(next);
	QFile der(file("next.crl"));
	QVERIFY(der.open(QIODevice::WriteOnly | QIODevice::Truncate));
	der.write(next->i2d());
	der.close();
	QCOMPARE(opensslOk({ "crl", "-in", der.fileName(), "-inform", "DER",
		"-noout", "-crlnumber" }).trimmed(), QString("crlNumber=0x06"));
	QCOMPARE(authorityCrl(ca), qMakePair(6LL,
		next->getNextUpdate().toPlain()));
#endif
}

/* Regression (BTD-34): a copied template (Duplicate in the Templates
 * tab) had no pki type, was stored with items.type 0 and could not be
 * exported: exportItems() rejected it as wrong_object_type. Found by
 * the GUI regression case gui.export.template. */
void test_service_importexport::templateCopyExport()
{
	pki_temp *orig = new pki_temp("BTD34 template");
	ImportSpec spec;
	spec.items << orig;
	ImportResult r = Database.importItems(ctx, spec);
	QCOMPARE(r.created.size(), 1);

	pki_temp *copy = new pki_temp(static_cast<pki_temp *>(r.created[0]));
	copy->setIntName("BTD34 template copy");
	QCOMPARE(copy->getType(), tmpl);
	spec.items = QList<pki_base *>() << copy;
	r = Database.importItems(ctx, spec);
	QCOMPARE(r.created.size(), 1);
	QCOMPARE(entries("object.import").last().objectType, QString("template"));

	QByteArray out = exportTo(Database.model<db_temp>(), r.created[0], 35,
				QString());
	QVERIFY(out.contains("-----BEGIN XCA TEMPLATE-----"));
	QCOMPARE(entries("object.export").last().objectType, QString("template"));
}

/* Rejections: one failure entry each, with the error code */
void test_service_importexport::rejections()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	/* Wrong PKCS#12 password from the source: XCA's parser warns once
	 * before the source is asked again */
	QFile p12(file("leaf.p12"));
	QVERIFY(p12.open(QIODevice::ReadOnly));
	ImportSpec in;
	in.data = p12.readAll();
	in.dataName = "leaf.p12";
	in.passwordSource = "pass:wrong";
	warning->expectMessage("Password verify error");
	try {
		Database.importItems(ctx, in);
		QFAIL("importItems() did not throw");
	} catch (serviceError &err) {
		QCOMPARE(err.code, QString("wrong_password"));
	}
	AuditEntry e = AuditLog::entries().last();
	QCOMPARE(e.action, QString("object.import"));
	QCOMPARE(e.result, QString("failure"));
	QCOMPARE(e.errorCode, QString("wrong_password"));
	QCOMPARE(Store.getAll<pki_x509>().size(), 0);

	/* No PKI data; longer junk: test_service_loaders::noTemplate
	 * (BTD-88) */
	ImportSpec junk;
	junk.data = "abc";
	junk.dataName = "junk.txt";
	try {
		Database.importItems(ctx, junk);
		QFAIL("importItems() did not throw");
	} catch (serviceError &err) {
		QCOMPARE(err.code, QString("no_pki_data"));
	}

	/* A private key format for a certificate without key */
	ImportSpec certOnly;
	certOnly.files << file("ca.pem");
	pki_x509 *ca = dynamic_cast<pki_x509 *>(
		Database.importItems(ctx, certOnly).created.value(0));
	QVERIFY(ca);
	try {
		exportTo(Database.model<db_x509>(), ca, certPkcs12Chain,
			file("nokey.p12"), "pass:x");
		QFAIL("exportItems() did not throw");
	} catch (serviceError &err) {
		QCOMPARE(err.code, QString("format_not_applicable"));
	}
	QVERIFY(!QFile::exists(file("nokey.p12")));
	e = AuditLog::entries().last();
	QCOMPARE(e.action, QString("object.export"));
	QCOMPARE(e.errorCode, QString("format_not_applicable"));

	/* An encrypting format without a password source: the headless
	 * default has none */
	importChain();
	pki_key *key = cert("BTD34 Leaf")->getRefKey();
	PwDialogHeadless *h = new PwDialogHeadless();
	pwdialog->delegateTo(h);
	try {
		exportTo(Database.model<db_key>(), key, keyPkcs8Encrypted,
			file("nopass.pk8"));
		QFAIL("exportItems() did not throw");
	} catch (serviceError &err) {
		QCOMPARE(err.code, QString("missing_password"));
	}
	QVERIFY(!QFile::exists(file("nopass.pk8")));
	QCOMPARE(entries("key.export_private").size(), 0);
	QVERIFY(AuditLog::verify().ok());
#endif
}

/* The files in the test directory, also hidden ones: a temporary file
 * of an export would show here */
static QStringList dirFiles(const QTemporaryDir &dir)
{
	return QDir(dir.path()).entryList(QDir::Files | QDir::Hidden |
					QDir::System, QDir::Name);
}

/* A COMMIT that fails after the file was written: the export entries
 * violate a deferred foreign key, which SQLite checks only at COMMIT.
 * The previous content of the target file stays, a new target is not
 * created, the failure is audited (BTD-114). Before, the written file
 * was removed again, also when it had existed before. */
void test_service_importexport::exportFailureKeepsFile()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	importChain();
	pki_x509 *leaf = cert("BTD34 Leaf");
	QVERIFY(leaf);
	QByteArray previous("previous content, not PKI data\n");
	QFile old(file("existing.pem"));
	QVERIFY(old.open(QIODevice::WriteOnly));
	QCOMPARE(old.write(previous), (qint64)previous.size());
	old.close();
	QStringList files = dirFiles(dir);

	QSqlQuery q;
	QVERIFY2(q.exec("PRAGMA foreign_keys = ON"),
		CCHAR(q.lastError().text()));
	QVERIFY2(q.exec("CREATE TABLE btd114_guard (item INTEGER "
		"REFERENCES items(id) DEFERRABLE INITIALLY DEFERRED)"),
		CCHAR(q.lastError().text()));
	QVERIFY2(q.exec("CREATE TEMP TRIGGER btd114_fail_commit AFTER "
		"INSERT ON audit_log WHEN NEW.action = 'object.export' "
		"AND NEW.result = 'success' BEGIN "
		"INSERT INTO btd114_guard VALUES (-1); END"),
		CCHAR(q.lastError().text()));

	foreach(const QString &name, QStringList({ "existing.pem",
						"new.pem" })) {
		qsizetype before = entries("object.export").size();
		warning->expectMessage("FOREIGN KEY constraint failed");
		QString code;
		try {
			exportTo(Database.model<db_x509>(), leaf, certPem,
				file(name));
		} catch (serviceError &err) {
			code = err.code;
		} catch (errorEx &err) {
			code = "errorEx: " + err.getString();
		}
		if (name == "existing.pem") {
			QVERIFY(QFile::exists(file(name)));
			QFile f(file(name));
			QVERIFY(f.open(QIODevice::ReadOnly));
			QCOMPARE(f.readAll(), previous);
		} else {
			QVERIFY(!QFile::exists(file(name)));
		}
		/* no temporary file of the export is left */
		QCOMPARE(dirFiles(dir), files);
		QCOMPARE(code, QString("database_error"));
		QList<AuditEntry> exports = entries("object.export");
		QCOMPARE(exports.size(), before + 1);
		QCOMPARE(exports.last().result, QString("failure"));
		QCOMPARE(exports.last().errorCode, QString("database_error"));
	}
	QVERIFY(q.exec("DROP TRIGGER temp.btd114_fail_commit"));
	QVERIFY(q.exec("DROP TABLE btd114_guard"));
	QVERIFY(q.exec("PRAGMA foreign_keys = OFF"));

	/* The database is usable again: the same export succeeds and
	 * replaces the file */
	exportTo(Database.model<db_x509>(), leaf, certPem,
		file("existing.pem"));
	QCOMPARE(certFingerprint(file("existing.pem"), "PEM"),
		certFingerprint(file("leaf.pem"), "PEM"));
	QCOMPARE(entries("object.export").last().result, QString("success"));
	QVERIFY(AuditLog::verify().ok());
	QVERIFY(QFile::remove(file("existing.pem")));
#endif
}

/* A private key replaces an existing, world-readable file: the result
 * is readable by the owner only, as a new key file (BTD-114) */
void test_service_importexport::exportOverwritesKeyOwnerOnly()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	importChain();
	pki_key *key = cert("BTD34 Leaf")->getRefKey();
	QFile old(file("key.pem"));
	QVERIFY(old.open(QIODevice::WriteOnly));
	old.write("old\n");
	old.close();
	QStringList files = dirFiles(dir);
	QVERIFY(old.setPermissions(QFile::ReadOwner | QFile::WriteOwner |
				QFile::ReadGroup | QFile::ReadOther));

	exportTo(Database.model<db_key>(), key, keyPemPrivate,
		file("key.pem"));
	QCOMPARE(publicKey(file("key.pem"), {}),
		publicKey(file("leaf.key"), {}));
	QFile::Permissions others = QFile::ReadGroup | QFile::WriteGroup |
		QFile::ExeGroup | QFile::ReadOther | QFile::WriteOther |
		QFile::ExeOther;
	QVERIFY(!(QFile::permissions(file("key.pem")) & others));
	QCOMPARE(dirFiles(dir), files);
	QVERIFY(QFile::remove(file("key.pem")));
#endif
}

/* A null item is rejected before any use, audited as a failure; before
 * BTD-114 a list of one null item crashed at the "name" parameter */
void test_service_importexport::exportNullItem()
{
	ExportSpec spec;
	spec.items << nullptr;
	spec.format = pki_export::by_id(certPem);
	spec.fileName = file("null.pem");
	try {
		Database.model<db_x509>()->exportItems(ctx, spec);
		QFAIL("exportItems() did not throw");
	} catch (serviceError &err) {
		QCOMPARE(err.code, QString("wrong_object_type"));
	}
	QVERIFY(!QFile::exists(file("null.pem")));
	AuditEntry e = AuditLog::entries().last();
	QCOMPARE(e.action, QString("object.export"));
	QCOMPARE(e.result, QString("failure"));
	QCOMPARE(e.errorCode, QString("wrong_object_type"));
	QVERIFY(!e.params.contains("name"));
	QVERIFY(AuditLog::verify().ok());
}

/* Rows of the items table: only what was committed */
static int committedItems()
{
	QSqlQuery q("SELECT COUNT(*) FROM items");
	return q.next() ? q.value(0).toInt() : -1;
}

/* The object.import entry of the second object fails after its insert:
 * the database rolls back both, and both leave the store and the views
 * again and go back to the caller through ImportSpec::unstored; the
 * retry stores them. Before, they stayed in memory with the id of a
 * rolled-back row: shown as stored, gone after a restart, and a new
 * import of the same file found them as "already in the database"
 * (BTD-114, mr-processor review of xca#29). */
void test_service_importexport::importRollbackHandsBack()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	pki_multi read;
	read.probeAnything(file("ca.pem"));
	read.probeAnything(file("leaf.pem"));
	QList<pki_base *> given = read.pull();
	QCOMPARE(given.size(), 2);

	QSqlQuery q;
	QVERIFY2(q.exec("CREATE TEMP TRIGGER btd114_fail_audit BEFORE "
		"INSERT ON audit_log WHEN NEW.action = 'object.import' "
		"AND NEW.result = 'success' "
		"AND NEW.params LIKE '%BTD34 Leaf%' BEGIN "
		"SELECT RAISE(ABORT, 'BTD-114 test: audit refused'); END"),
		CCHAR(q.lastError().text()));
	QList<pki_base *> unstored;
	ImportSpec spec;
	spec.items = given;
	spec.unstored = &unstored;
	try {
		Database.importItems(ctx, spec);
		QFAIL("importItems() did not throw");
	} catch (errorEx &) {
	}
	QVERIFY(q.exec("DROP TRIGGER temp.btd114_fail_audit"));

	QCOMPARE(Store.getAll<pki_base>().size(), 0);
	QCOMPARE(Database.model<db_x509>()->rowCount(QModelIndex()), 0);
	QCOMPARE(committedItems(), 0);
	QCOMPARE(unstored.size(), 2);
	foreach(pki_base *pki, unstored) {
		QVERIFY(given.contains(pki));
		QVERIFY(!pki->getSqlItemId().isValid());
	}
	AuditEntry e = AuditLog::entries().last();
	QCOMPARE(e.action, QString("object.import"));
	QCOMPARE(e.result, QString("failure"));

	ImportSpec retry;
	retry.items = unstored;
	ImportResult result = Database.importItems(ctx, retry);
	QCOMPARE(result.created.size(), 2);
	QCOMPARE(result.existing.size(), 0);
	QCOMPARE(committedItems(), 2);
	QVERIFY(AuditLog::verify().ok());
#endif
}

/* -- BTD-16: Ed448, ML-DSA and SLH-DSA keys ------------------------------ */

pki_key *test_service_importexport::newKey(const QString &type,
				const QString &name)
{
	return Database.model<db_key>()->newKey(ctx, keyjob(type), name);
}

QString test_service_importexport::publicPem(pki_key *key)
{
	BIO *b = BIO_new(BIO_s_mem());
	PEM_write_bio_PUBKEY(b, key->getPubKey());
	char *data;
	long len = BIO_get_mem_data(b, &data);
	QString pem = QString::fromLatin1(data, len);
	BIO_free(b);
	return pem;
}

pki_x509 *test_service_importexport::rsaCa()
{
	pki_key *key = newKey("RSA:2048", "BTD16 CA key");
	IssuanceSpec spec;
	spec.name = "BTD16 CA";
	spec.subject.addEntryByNid(NID_commonName, "BTD16 CA");
	spec.key = key;
	spec.notBefore = a1time();
	spec.notAfter = a1time(QDateTime::currentDateTimeUtc().addDays(30));
	spec.hashAlgo = digest(NID_sha256);
	spec.extensions.basicCA = ExtensionSpec::bc_ca;
	spec.extensions.keyUsage << "keyCertSign" << "cRLSign";
	return Database.model<db_x509>()->newCert(ctx, spec);
}

pki_x509 *test_service_importexport::certFor(pki_key *key, pki_x509 *ca)
{
	IssuanceSpec spec;
	spec.name = key->getIntName() + " cert";
	spec.subject.addEntryByNid(NID_commonName, spec.name);
	spec.key = key;
	spec.signer = ca;
	spec.notBefore = a1time();
	spec.notAfter = a1time(QDateTime::currentDateTimeUtc().addDays(10));
	spec.hashAlgo = digest(NID_sha256);
	spec.extensions.basicCA = ExtensionSpec::bc_not_ca;
	spec.extensions.keyUsage << "digitalSignature";
	return Database.model<db_x509>()->newCert(ctx, spec);
}

int test_service_importexport::mlDsaTag(const QString &name, int format)
{
	QFile f(name);
	if (!f.open(QIODevice::ReadOnly))
		return -1;
	QByteArray data = f.readAll();
	BIO *b = BIO_new_mem_buf(data.constData(), data.size());
	PKCS8_PRIV_KEY_INFO *p8 = nullptr;
	if (format == keyDerPrivate) {
		p8 = d2i_PKCS8_PRIV_KEY_INFO_bio(b, nullptr);
	} else if (format == keyPkcs8Encrypted) {
		X509_SIG *sig = PEM_read_bio_PKCS8(b, nullptr, nullptr, nullptr);
		if (sig)
			p8 = PKCS8_decrypt(sig, exportPass, strlen(exportPass));
		X509_SIG_free(sig);
	} else {
		p8 = PEM_read_bio_PKCS8_PRIV_KEY_INFO(b, nullptr, nullptr,
							nullptr);
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

QByteArray test_service_importexport::exportFormat(db_base *db, pki_base *pki,
		int format, const QString &name, const QString &keyFormat)
{
	ExportSpec spec;
	spec.items << pki;
	spec.format = pki_export::by_id(format);
	spec.fileName = name;
	if (spec.format->match_all(F_CRYPT))
		spec.passwordSource = QString("env:%1").arg(
			spec.format->match_all(F_PKCS12) ? p12Var : exportVar);
	spec.privateKeyFormat = keyFormat;
	return db->exportItems(ctx, spec);
}

void test_service_importexport::fixedKeyRoundTrip_data()
{
	QTest::addColumn<QString>("type");
	QTest::addColumn<int>("format");

	static const QList<QPair<int, const char *>> formats {
		{ keyPemPublic, "PEM public" }, { keyDerPublic, "DER public" },
		{ keyPemPrivate, "PEM private" }, { keyDerPrivate, "DER private" },
		{ keyPkcs8, "PKCS#8" }, { keyPkcs8Encrypted, "PKCS#8 encrypted" },
	};
	for (const char *type : { "ED448", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
			"SLH-DSA-SHA2-128s", "SLH-DSA-SHAKE-256f" }) {
		for (const auto &f : formats)
			QTest::newRow(qPrintable(QString("%1 %2").arg(type, f.second)))
				<< type << f.first;
	}
}

/* Every key format of a new type reads back with openssl pkey to the
 * same public key, and imports again: into the same database as the
 * stored key, into an empty one as a new key of the same type */
void test_service_importexport::fixedKeyRoundTrip()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	QFETCH(QString, type);
	QFETCH(int, format);
	const pki_export *xport = pki_export::by_id(format);
	bool priv = xport->match_all(F_PRIVATE);
	bool encrypted = xport->match_all(F_CRYPT);

	db_key *keys = Database.model<db_key>();
	pki_key *key = newKey(type, "fixed");
	QVERIFY(key);
	QString pub = publicPem(key);
	QString out = file(QString("fixed-%1").arg(format));
	exportFormat(keys, key, format, out, QString());

	QStringList extra;
	if (!priv)
		extra << "-pubin";
	if (xport->match_all(F_DER))
		extra << "-inform" << "DER";
	if (encrypted)
		extra << "-passin" << QString("env:%1").arg(exportVar);
	QCOMPARE(publicKey(out, extra), pub);
	QCOMPARE(entries("key.export_private").size(), priv ? 1 : 0);

	ImportSpec spec;
	spec.files << out;
	if (encrypted)
		spec.passwordSource = QString("env:%1").arg(exportVar);
	ImportResult r = Database.importItems(ctx, spec);
	QCOMPARE(r.created.size(), 0);
	QCOMPARE(r.existing, QList<pki_base *>() << key);

	/* Into a database without the key */
	keys->deleteItems(ctx, QList<pki_base *>() << key);
	QCOMPARE(Store.getAll<pki_key>().size(), 0);
	r = Database.importItems(ctx, spec);
	QCOMPARE(r.created.size(), 1);
	pki_key *back = dynamic_cast<pki_key *>(r.created[0]);
	QVERIFY(back);
	QCOMPARE(back->getKeyTypeString(), type);
	QCOMPARE(back->isPrivKey(), priv);
	QCOMPARE(publicPem(back), pub);
	reopenDatabase();
	QCOMPARE(Store.getAll<pki_key>().size(), 1);
	back = Store.getAll<pki_key>()[0];
	QCOMPARE(back->getKeyTypeString(), type);
	if (priv) {
		EVP_PKEY *pkey = back->decryptKey();
		QVERIFY(pkey);
		QCOMPARE(EVP_PKEY_eq(pkey, back->getPubKey()), 1);
		EVP_PKEY_free(pkey);
	}
	QVERIFY(AuditLog::verify().ok());
#endif
}

void test_service_importexport::fixedKeyPkcs12_data()
{
	QTest::addColumn<QString>("type");

	for (const char *type : { "ED448", "ML-DSA-65", "SLH-DSA-SHA2-128s" })
		QTest::newRow(type) << type;
}

/* PKCS#12 of a certificate (issued by an RSA CA, BTD-164 brings the
 * signing with the new keys) with an Ed448, ML-DSA or SLH-DSA key:
 * openssl pkcs12 reads the key, XCA imports the file again */
void test_service_importexport::fixedKeyPkcs12()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	QFETCH(QString, type);
	pki_x509 *ca = rsaCa();
	QVERIFY(ca);
	pki_key *key = newKey(type, "p12-key");
	QVERIFY(key);
	pki_x509 *crt = certFor(key, ca);
	QVERIFY(crt);
	QString pub = publicPem(key);

	QString out = file("fixed.p12");
	exportFormat(Database.model<db_x509>(), crt, certPkcs12, out, QString());
	QString keyPem = file("fixed-from-p12.pem");
	QVERIFY(opensslRun({ "pkcs12", "-in", out, "-nocerts", "-noenc",
		"-passin", QString("env:%1").arg(p12Var), "-out", keyPem }));
	QCOMPARE(publicKey(keyPem, QStringList()), pub);
	QList<AuditEntry> priv = entries("key.export_private");
	QCOMPARE(priv.size(), 1);
	QCOMPARE(priv[0].params.value("pkcs12_algorithm").toString(),
		QString("AES-256-CBC"));

	ImportSpec spec;
	spec.files << out;
	spec.passwordSource = QString("env:%1").arg(p12Var);
	ImportResult r = Database.importItems(ctx, spec);
	QCOMPARE(r.created.size(), 0);
	QVERIFY(r.existing.contains(key));
	QVERIFY(r.existing.contains(crt));
#endif
}

void test_service_importexport::mlDsaPrivateFormat_data()
{
	QTest::addColumn<QString>("keyFormat");
	QTest::addColumn<int>("format");
	QTest::addColumn<int>("tag");

	static const QList<QPair<int, const char *>> formats {
		{ keyDerPrivate, "DER" }, { keyPkcs8, "PKCS#8" },
		{ keyPemPrivate, "PEM" }, { keyPkcs8Encrypted, "PKCS#8 encrypted" },
	};
	static const QList<QPair<const char *, int>> keyFormats {
		{ "seed", 0x80 }, { "expanded", 0x04 }, { "both", 0x30 },
	};
	for (const auto &k : keyFormats) {
		for (const auto &f : formats)
			QTest::newRow(qPrintable(QString("%1 %2").arg(k.first, f.second)))
				<< k.first << f.first << k.second;
	}
	/* Without a choice: OpenSSL's default, both */
	QTest::newRow("default DER") << "" << int(keyDerPrivate) << 0x30;
}

/* RFC 9881: the ML-DSA private key as seed, expanded key or both; each
 * variant reads with openssl pkey to the same public key, the choice is
 * in the audit entries, and the stored key keeps its seed */
void test_service_importexport::mlDsaPrivateFormat()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	QFETCH(QString, keyFormat);
	QFETCH(int, format);
	QFETCH(int, tag);

	pki_key *key = newKey("ML-DSA-65", "mldsa");
	QVERIFY(key);
	QString out = file("mldsa-key");
	exportFormat(Database.model<db_key>(), key, format, out, keyFormat);
	QCOMPARE(mlDsaTag(out, format), tag);

	QStringList extra;
	if (format == keyDerPrivate)
		extra << "-inform" << "DER";
	if (format == keyPkcs8Encrypted)
		extra << "-passin" << QString("env:%1").arg(exportVar);
	QCOMPARE(publicKey(out, extra), publicPem(key));

	/* As written: the default writes both (BTD-16 review of xca#51) */
	QString written = keyFormat.isEmpty() ? QString("both") : keyFormat;
	for (const char *action : { "object.export", "key.export_private" }) {
		QList<AuditEntry> e = entries(action);
		QCOMPARE(e.size(), 1);
		QCOMPARE(e[0].params.value("ml_dsa_encoding").toString(),
			written);
	}

	/* The database still holds both, whatever the export wrote */
	EVP_PKEY *pkey = key->decryptKey();
	QVERIFY(pkey);
	size_t len = 0;
	QVERIFY(EVP_PKEY_get_octet_string_param(pkey,
		OSSL_PKEY_PARAM_ML_DSA_SEED, nullptr, 0, &len));
	QCOMPARE(len, size_t(32));
	EVP_PKEY_free(pkey);
#endif
}

/* The case of XiPKI on JDK 25, which reads the expanded key only: a
 * PKCS#12 file with the expanded ML-DSA key */
void test_service_importexport::mlDsaPkcs12Expanded()
{
	pki_x509 *ca = rsaCa();
	QVERIFY(ca);
	pki_key *key = newKey("ML-DSA-87", "p12-mldsa");
	QVERIFY(key);
	pki_x509 *crt = certFor(key, ca);
	QVERIFY(crt);
	QString out = file("expanded.p12");
	exportFormat(Database.model<db_x509>(), crt, certPkcs12, out,
			"expanded");

	QFile f(out);
	QVERIFY(f.open(QIODevice::ReadOnly));
	QByteArray data = f.readAll();
	const unsigned char *p = (const unsigned char *)data.constData();
	PKCS12 *p12 = d2i_PKCS12(nullptr, &p, data.size());
	QVERIFY(p12);
	EVP_PKEY *pkey = nullptr;
	X509 *x = nullptr;
	QVERIFY(PKCS12_parse(p12, p12Pass, &pkey, &x, nullptr));
	size_t len = 0;
	/* read from the expanded key alone: no seed */
	QVERIFY(!EVP_PKEY_get_octet_string_param(pkey,
		OSSL_PKEY_PARAM_ML_DSA_SEED, nullptr, 0, &len) || len == 0);
	QCOMPARE(EVP_PKEY_eq(pkey, key->getPubKey()), 1);
	ign_openssl_error();
	EVP_PKEY_free(pkey);
	X509_free(x);
	PKCS12_free(p12);
	QCOMPARE(entries("key.export_private")[0].params.value(
		"ml_dsa_encoding").toString(), QString("expanded"));
}

/* A key imported as expanded key only has no seed: the expanded key and
 * the default export work, "seed" and "both" fail with seed_unavailable
 * and a failure entry; the database keeps the key without seed */
void test_service_importexport::mlDsaWithoutSeed()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	QString full = file("genpkey-mldsa.pem");
	QString expanded = file("expanded-only.pem");
	QVERIFY(opensslRun({ "genpkey", "-algorithm", "ML-DSA-44", "-out", full }));
	QVERIFY(opensslRun({ "pkey", "-in", full, "-out", expanded,
		"-provparam", "ml-dsa.output_formats=priv-only" }));
	ImportSpec spec;
	spec.files << expanded;
	ImportResult r = Database.importItems(ctx, spec);
	QCOMPARE(r.created.size(), 1);
	pki_key *key = dynamic_cast<pki_key *>(r.created[0]);
	QVERIFY(key && key->isPrivKey());

	db_key *keys = Database.model<db_key>();
	for (const char *fmt : { "seed", "both" }) {
		int before = entries("object.export").size();
		try {
			exportFormat(keys, key, keyPkcs8, file("no-seed.pem"), fmt);
			QFAIL("exported a seed the key does not have");
		} catch (serviceError &err) {
			QCOMPARE(err.code, QString("seed_unavailable"));
		}
		QList<AuditEntry> e = entries("object.export");
		QCOMPARE(e.size(), before + 1);
		QCOMPARE(e.last().result, QString("failure"));
		QCOMPARE(e.last().errorCode, QString("seed_unavailable"));
		QCOMPARE(e.last().params.value("ml_dsa_encoding").toString(),
			QString(fmt));
	}
	QVERIFY(!QFile::exists(file("no-seed.pem")));
	QCOMPARE(entries("key.export_private").size(), 0);

	for (const char *fmt : { "expanded", "" }) {
		QString out = file(QString("expanded-%1.pem").arg(fmt));
		exportFormat(keys, key, keyPkcs8, out, fmt);
		QCOMPARE(mlDsaTag(out, keyPkcs8), 0x04);
		QCOMPARE(publicKey(out, QStringList()),
			publicKey(full, QStringList()));
		/* also the default names what it wrote: the expanded key */
		QCOMPARE(entries("key.export_private").last().params.value(
			"ml_dsa_encoding").toString(), QString("expanded"));
	}
	reopenDatabase();
	key = Store.getAll<pki_key>()[0];
	EVP_PKEY *pkey = key->decryptKey();
	QVERIFY(pkey);
	QCOMPARE(EVP_PKEY_eq(pkey, key->getPubKey()), 1);
	EVP_PKEY_free(pkey);
	QVERIFY(AuditLog::verify().ok());
#endif
}

/* Unknown encodings, other key types, public formats and the clipboard
 * have no ML-DSA private key format */
void test_service_importexport::mlDsaFormatRejected()
{
	db_key *keys = Database.model<db_key>();
	pki_key *mldsa = newKey("ML-DSA-65", "mldsa");
	pki_key *slh = newKey("SLH-DSA-SHA2-128f", "slh");
	pki_key *rsa = newKey("RSA:2048", "rsa");
	QVERIFY(mldsa && slh && rsa);

	struct { pki_key *key; int format; const char *fmt; bool clipboard;
		const char *code; } cases[] = {
		{ mldsa, keyPkcs8, "raw", false, "invalid_ml_dsa_encoding" },
		{ slh, keyPkcs8, "seed", false, "format_not_applicable" },
		{ rsa, keyPkcs8, "expanded", false, "format_not_applicable" },
		{ mldsa, keyPemPublic, "seed", false, "format_not_applicable" },
		{ mldsa, keyPkcs8, "seed", true, "format_not_applicable" },
	};
	for (const auto &c : cases) {
		ExportSpec spec;
		spec.items << c.key;
		spec.format = pki_export::by_id(c.format);
		spec.privateKeyFormat = c.fmt;
		spec.clipboard = c.clipboard;
		try {
			keys->exportItems(ctx, spec);
			QFAIL(qPrintable(QString("accepted %1 for %2").arg(c.fmt,
				c.key->getIntName())));
		} catch (serviceError &err) {
			QCOMPARE(err.code, QString(c.code));
		}
	}
	QCOMPARE(entries("key.export_private").size(), 0);
	QVERIFY(AuditLog::verify().ok());
}

void test_service_importexport::importOpensslFixed_data()
{
	QTest::addColumn<QString>("type");
	QTest::addColumn<QString>("outputFormat");
	QTest::addColumn<bool>("encrypted");

	for (const char *type : { "ED448", "ML-DSA-44", "ML-DSA-65",
			"ML-DSA-87", "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f",
			"SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
			"SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f",
			"SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
			"SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f",
			"SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f" })
		QTest::newRow(type) << type << "" << false;
	for (const char *of : { "seed-only", "priv-only", "seed-priv" })
		QTest::newRow(qPrintable(QString("ML-DSA-65 %1").arg(of)))
			<< "ML-DSA-65" << of << false;
	QTest::newRow("ML-DSA-87 encrypted") << "ML-DSA-87" << "" << true;
	QTest::newRow("SLH-DSA encrypted") << "SLH-DSA-SHAKE-128s" << "" << true;
}

/* Keys made by the openssl program import with their type, also ML-DSA
 * in each RFC 9881 encoding and encrypted PKCS#8 */
void test_service_importexport::importOpensslFixed()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	QFETCH(QString, type);
	QFETCH(QString, outputFormat);
	QFETCH(bool, encrypted);

	QString gen = file("gen.pem");
	QString in = file("in.pem");
	QVERIFY(opensslRun({ "genpkey", "-algorithm", type, "-out", gen }));
	QStringList args { "pkey", "-in", gen, "-out", in };
	if (!outputFormat.isEmpty())
		args << "-provparam" << "ml-dsa.output_formats=" + outputFormat;
	if (encrypted)
		args << "-aes-256-cbc" << "-passout"
			<< QString("env:%1").arg(exportVar);
	QVERIFY(opensslRun(args));

	ImportSpec spec;
	spec.files << in;
	if (encrypted)
		spec.passwordSource = QString("env:%1").arg(exportVar);
	ImportResult r = Database.importItems(ctx, spec);
	QCOMPARE(r.created.size(), 1);
	pki_key *key = dynamic_cast<pki_key *>(r.created[0]);
	QVERIFY(key);
	QCOMPARE(key->getKeyTypeString(), type);
	QVERIFY(key->isPrivKey());
	QCOMPARE(publicPem(key), publicKey(gen, QStringList()));
	QCOMPARE(entries("object.import").size(), 1);
#endif
}

PKCS8_PRIV_KEY_INFO *test_service_importexport::mismatchedMlDsa()
{
	EVP_PKEY *a = EVP_PKEY_Q_keygen(nullptr, nullptr, "ML-DSA-44");
	EVP_PKEY *b = EVP_PKEY_Q_keygen(nullptr, nullptr, "ML-DSA-44");
	unsigned char seed[32], priv[2560];
	size_t seedLen = 0, privLen = 0;
	bool ok = a && b &&
		EVP_PKEY_get_octet_string_param(a, OSSL_PKEY_PARAM_ML_DSA_SEED,
			seed, sizeof seed, &seedLen) && seedLen == sizeof seed &&
		EVP_PKEY_get_octet_string_param(b, OSSL_PKEY_PARAM_PRIV_KEY,
			priv, sizeof priv, &privLen) && privLen == sizeof priv;
	EVP_PKEY_free(a);
	EVP_PKEY_free(b);
	if (!ok)
		return nullptr;
	/* both = SEQUENCE { OCTET STRING seed, OCTET STRING expandedKey } */
	QByteArray inner;
	inner.append("\x04\x20", 2).append((const char *)seed, sizeof seed);
	inner.append("\x04\x82\x0a\x00", 4).append((const char *)priv,
							sizeof priv);
	QByteArray both("\x30\x82", 2);
	both.append(char(inner.size() >> 8)).append(char(inner.size() & 0xff));
	both += inner;
	unsigned char *data = (unsigned char *)OPENSSL_memdup(both.constData(),
							both.size());
	PKCS8_PRIV_KEY_INFO *p8 = PKCS8_PRIV_KEY_INFO_new();
	ok = p8 && data && PKCS8_pkey_set0(p8, OBJ_nid2obj(NID_ML_DSA_44), 0,
				V_ASN1_UNDEF, nullptr, data, both.size());
	if (!ok) {
		OPENSSL_free(data);
		PKCS8_PRIV_KEY_INFO_free(p8);
		p8 = nullptr;
	}
	ign_openssl_error();
	return p8;
}

bool test_service_importexport::writeMismatchedMlDsa(const QString &name)
{
	PKCS8_PRIV_KEY_INFO *p8 = mismatchedMlDsa();
	BIO *b = p8 ? BIO_new_file(QFile::encodeName(name).constData(), "w") :
			nullptr;
	bool ok = b && PEM_write_bio_PKCS8_PRIV_KEY_INFO(b, p8);
	BIO_free(b);
	PKCS8_PRIV_KEY_INFO_free(p8);
	ign_openssl_error();
	return ok;
}

void test_service_importexport::loadDump(const QString &name)
{
	Database.close();
	QVERIFY(QFile::remove(dbFile));
	{
		QFile dump(QString(SERVICE_TEST_DATA "/") + name);
		QVERIFY(dump.open(QIODevice::ReadOnly));
		QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "dump");
		db.setDatabaseName(dbFile);
		QVERIFY(db.open());
		QSqlQuery q(db);
		QString statement;
		while (!dump.atEnd()) {
			statement += QString::fromUtf8(dump.readLine());
			if (!statement.trimmed().endsWith(';'))
				continue;
			QVERIFY2(q.exec(statement), CCHAR(q.lastError().text()));
			statement.clear();
		}
		db.close();
	}
	QSqlDatabase::removeDatabase("dump");
	openDatabase();
}

void test_service_importexport::checkOpensslConf()
{
	/* mode of test/service/CMakeLists.txt: setting and value */
	static const QMap<QString, QPair<QString, QString> > cnf {
		{ "output", { "ml-dsa.output_formats", "priv-only" } },
		{ "retain", { "ml-dsa.retain_seed", "no" } },
		{ "prefer", { "ml-dsa.prefer_seed", "no" } },
		{ "prefer-false", { "ml-dsa.prefer_seed", "false" } },
		{ "prefer-0", { "ml-dsa.prefer_seed", "0" } },
		{ "prefer-off", { "ml-dsa.prefer_seed", "off" } },
	};
	QString mode = qEnvironmentVariable("XCA_TEST_MLDSA_CNF");
	QVERIFY2(mode.isEmpty() || cnf.contains(mode),
		qPrintable("unknown cnf mode " + mode));

	QMap<QString, QString> found;
	OSSL_PROVIDER *prov = OSSL_PROVIDER_load(nullptr, "default");
	QVERIFY(prov);
	for (const char *name : { "ml-dsa.output_formats",
				"ml-dsa.retain_seed", "ml-dsa.prefer_seed" }) {
		const char *value = nullptr;
		OSSL_PARAM params[] = {
			OSSL_PARAM_construct_utf8_ptr(name, (char **)&value, 0),
			OSSL_PARAM_END
		};
		if (OSSL_PROVIDER_get_conf_parameters(prov, params) &&
		    OSSL_PARAM_modified(params) && value)
			found[name] = value;
	}
	OSSL_PROVIDER_unload(prov);
	ign_openssl_error();

	QMap<QString, QString> expected;
	if (!mode.isEmpty())
		expected[cnf[mode].first] = cnf[mode].second;
	auto text = [](const QMap<QString, QString> &m) {
		QStringList l;
		for (auto i = m.cbegin(); i != m.cend(); ++i)
			l << i.key() + "=" + i.value();
		return l.isEmpty() ? QString("nothing") : l.join(", ");
	};
	QVERIFY2(found == expected, qPrintable(QString("OPENSSL_CONF=%1: the "
		"default provider has %2, the cnf of mode '%3' sets %4")
		.arg(qEnvironmentVariable("OPENSSL_CONF"), text(found), mode,
			text(expected))));
}

QString test_service_importexport::importError(const QString &name,
				QList<pki_base *> *created)
{
	ImportSpec spec;
	spec.files << name;
	try {
		ImportResult r = Database.importItems(ctx, spec);
		created->clear();
		for (pki_base *pki : r.created) {
			if (dynamic_cast<pki_key *>(pki))
				*created << pki;
		}
		/* imported, but no key */
		return created->isEmpty() ? QString("no_key") : QString();
	} catch (errorEx &err) {
		created->clear();
		serviceError *se = dynamic_cast<serviceError *>(&err);
		return se ? se->code : "errorEx: " + err.getString();
	}
}

/* ml_dsa_encoding only on the entries of ML-DSA keys, with what was
 * written: a "PEM private" export of an RSA and an ML-DSA key */
void test_service_importexport::mlDsaEncodingPerKey()
{
	pki_key *rsa = newKey("RSA:2048", "rsa");
	pki_key *mldsa = newKey("ML-DSA-65", "mldsa");
	pki_key *slh = newKey("SLH-DSA-SHA2-128f", "slh");
	QVERIFY(rsa && mldsa && slh);
	ExportSpec spec;
	spec.items << rsa << mldsa << slh;
	spec.format = pki_export::by_id(keyPemPrivate);
	spec.fileName = file("three.pem");
	Database.model<db_key>()->exportItems(ctx, spec);

	for (const char *action : { "object.export", "key.export_private" }) {
		QList<AuditEntry> e = entries(action);
		QCOMPARE(e.size(), 3);
		for (const AuditEntry &a : e) {
			bool isMlDsa = a.params.value("name").toString() == "mldsa";
			QCOMPARE(a.params.contains("ml_dsa_encoding"), isMlDsa);
			if (isMlDsa)
				QCOMPARE(a.params.value("ml_dsa_encoding").toString(),
					QString("both"));
		}
	}
}

/* A "both" encoding whose seed does not belong to its expanded key is
 * rejected on import: no key, whatever openssl.cnf says about
 * ml-dsa.prefer_seed (mlDsaUnderOpensslConf) */
void test_service_importexport::mlDsaMismatchRejected()
{
	QString name = file("mismatch.pem");
	QVERIFY(writeMismatchedMlDsa(name));
	QList<pki_base *> created;
	warning->expectMessage("cannot be read");
	QString err = importError(name, &created);
	QVERIFY2(!err.isEmpty(), "the mismatched key was imported");
	QCOMPARE(created.size(), 0);
	QCOMPARE(Store.getAll<pki_key>().size(), 0);
	/* and no XCA template of the same file (BTD-88) */
	QCOMPARE(Store.getAll<pki_temp>().size(), 0);
}

/* With and without an openssl.cnf that changes the ML-DSA handling of
 * the default provider. ctest runs this function also as
 * test_service_importexport_cnf_{output,retain,prefer} with
 * OPENSSL_CONF=data/mldsa-<mode>.cnf and XCA_TEST_MLDSA_CNF=<mode>:
 * - output_formats = priv-only: stored keys keep their seed (the store
 *   writes in its own context)
 * - retain_seed = no: the default provider still hands the seed over
 *   (EVP_PKEY_todata), stored keys keep it
 * - prefer_seed = no (also false, 0, off: prefer-false, prefer-0,
 *   prefer-off, BTD-194): the default provider reads a key without its
 *   seed; the import is refused with a message instead of losing the seed
 * A seed that does not belong to the expanded key never gets in.
 * Each run first checks that OpenSSL loaded its cnf (checkOpensslConf). */
void test_service_importexport::mlDsaUnderOpensslConf()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	checkOpensslConf();
	if (QTest::currentTestFailed())
		return;
	bool refused = qEnvironmentVariable("XCA_TEST_MLDSA_CNF")
			.startsWith("prefer");

	/* Generated, stored, read back: seed and expanded key */
	pki_key *key = newKey("ML-DSA-65", "generated");
	QVERIFY(key);
	reopenDatabase();
	key = Store.getAll<pki_key>()[0];
	EVP_PKEY *pkey = key->decryptKey();
	QVERIFY(pkey);
	size_t len = 0;
	QVERIFY(EVP_PKEY_get_octet_string_param(pkey,
		OSSL_PKEY_PARAM_ML_DSA_SEED, nullptr, 0, &len));
	QCOMPARE(len, size_t(32));
	EVP_PKEY_free(pkey);
	QString out = file("generated.der");
	exportFormat(Database.model<db_key>(), key, keyDerPrivate, out, "");
	QCOMPARE(mlDsaTag(out, keyDerPrivate), 0x30);

	/* An openssl key with seed and expanded key */
	QString both = file("both.pem");
	QVERIFY(opensslRun({ "genpkey", "-algorithm", "ML-DSA-44", "-out",
		both, "-provparam", "ml-dsa.output_formats=seed-priv" }));
	QList<pki_base *> created;
	if (refused)
		warning->expectMessage("ml-dsa.retain_seed or ml-dsa.prefer_seed");
	QString err = importError(both, &created);
	if (refused) {
		/* refused, and not taken for a template either (BTD-88) */
		QCOMPARE(err, QString("no_pki_data"));
		QCOMPARE(created.size(), 0);
		QCOMPARE(Store.getAll<pki_temp>().size(), 0);
	} else {
		QCOMPARE(err, QString());
		QCOMPARE(created.size(), 1);
		pki_key *imported = dynamic_cast<pki_key *>(created[0]);
		QVERIFY(imported);
		reopenDatabase();
		for (pki_key *k : Store.getAll<pki_key>()) {
			if (k->getKeyTypeString() != "ML-DSA-44")
				continue;
			pkey = k->decryptKey();
			QVERIFY(pkey);
			len = 0;
			QVERIFY(EVP_PKEY_get_octet_string_param(pkey,
				OSSL_PKEY_PARAM_ML_DSA_SEED, nullptr, 0, &len));
			QCOMPARE(len, size_t(32));
			EVP_PKEY_free(pkey);
		}
	}

	/* An expanded-only key (no seed in the input, as XiPKI writes it):
	 * accepted in every mode, PEM and DER, nothing is lost (BTD-204) */
	for (const char *form : { "PEM", "DER" }) {
		QString priv = file(QString("priv-only.%1").arg(form));
		QVERIFY(opensslRun({ "genpkey", "-algorithm", "ML-DSA-44",
			"-outform", form, "-out", priv, "-provparam",
			"ml-dsa.output_formats=priv-only" }));
		created.clear();
		err = importError(priv, &created);
		QVERIFY2(err.isEmpty(), qPrintable(QString("%1: %2")
			.arg(form, err)));
		QCOMPARE(created.size(), 1);
		pkey = dynamic_cast<pki_key *>(created[0])->decryptKey();
		QVERIFY(pkey);
		len = 0;
		bool seed = EVP_PKEY_get_octet_string_param(pkey,
			OSSL_PKEY_PARAM_ML_DSA_SEED, nullptr, 0, &len) && len;
		ign_openssl_error();
		QVERIFY(!seed);
		EVP_PKEY_free(pkey);
	}

	/* Encrypted PKCS#8: the second decode for the seed check takes the
	 * password the loader was given. Expanded-only is accepted, a
	 * seed-priv key is refused under prefer_seed off (BTD-204) */
	for (const char *format : { "priv-only", "seed-priv" }) {
		QString plain = file(QString("%1.plain.pem").arg(format));
		QString enc = file(QString("%1.p8").arg(format));
		QVERIFY(opensslRun({ "genpkey", "-algorithm", "ML-DSA-44", "-out",
			plain, "-provparam",
			QString("ml-dsa.output_formats=%1").arg(format) }));
		QVERIFY(opensslRun({ "pkcs8", "-topk8", "-in", plain, "-out", enc,
			"-v2", "aes-256-cbc", "-passout", "pass:BTD204-p8" }));
		bool refuse = refused && QString(format) == "seed-priv";
		if (refuse)
			warning->expectMessage(
				"ml-dsa.retain_seed or ml-dsa.prefer_seed");
		ImportSpec spec;
		spec.files << enc;
		spec.passwordSource = "pass:BTD204-p8";
		int keys = Store.getAll<pki_key>().size();
		try {
			Database.importItems(ctx, spec);
		} catch (errorEx &) {
		}
		QCOMPARE(Store.getAll<pki_key>().size(), keys + (refuse ? 0 : 1));
	}

	/* The seed-priv key once more as unnamed data: the refusal under
	 * prefer_seed off names no empty source (BTD-204) */
	if (refused) {
		QFile f(both);
		QVERIFY(f.open(QIODevice::ReadOnly));
		ImportSpec spec;
		spec.data = f.readAll();
		warning->expectMessage("the seed of the ML-DSA key may be lost");
		try {
			Database.importItems(ctx, spec);
		} catch (errorEx &) {
		}
	}

	/* A seed of another key is rejected in every mode */
	QString mismatch = file("mismatch.pem");
	QVERIFY(writeMismatchedMlDsa(mismatch));
	created.clear();
	/* refused on reading: by the default provider, or with prefer_seed
	 * = no because the seed would be lost */
	warning->expectMessage(refused ?
		"ml-dsa.retain_seed or ml-dsa.prefer_seed" : "cannot be read");
	err = importError(mismatch, &created);
	QVERIFY2(!err.isEmpty(), "the mismatched key was imported");
	QCOMPARE(created.size(), 0);
	QVERIFY(AuditLog::verify().ok());
#endif
}

void test_service_importexport::fixedKeyFormatsRefused_data()
{
	QTest::addColumn<QString>("type");
	QTest::addColumn<int>("format");

	/* PEM encrypted (legacy), SSH2 private/public, PVK, JWK */
	for (const char *type : { "ED448", "ML-DSA-65", "SLH-DSA-SHAKE-128f" }) {
		for (int f : { 21, 22, 23, 26, 50, 51 })
			QTest::newRow(qPrintable(QString("%1 %2").arg(type).arg(f)))
				<< type << f;
	}
}

/* Formats the new key types do not have are refused by the service,
 * not only hidden in the export dialog */
void test_service_importexport::fixedKeyFormatsRefused()
{
	QFETCH(QString, type);
	QFETCH(int, format);
	pki_key *key = newKey(type, "fixed");
	QVERIFY(key);
	try {
		exportFormat(Database.model<db_key>(), key, format,
				file("refused"), "");
		QFAIL("format accepted");
	} catch (serviceError &err) {
		QCOMPARE(err.code, QString("format_not_applicable"));
	}
	QVERIFY(!QFile::exists(file("refused")));
}

/* A database password change re-encrypts an ML-DSA key without seed
 * (stored before, data/schema8-bxc3-mldsa.sql) also when openssl.cnf
 * sets ml-dsa.prefer_seed = no: the seed check belongs to the import,
 * not to every encryption (review of xca#52). The cnf runs of ctest
 * call this function too. */
void test_service_importexport::mlDsaSeedlessPasswordChange()
{
	checkOpensslConf();
	if (QTest::currentTestFailed())
		return;
	loadDump("schema8-bxc3-mldsa.sql");
	QList<pki_key *> keys = Store.getAll<pki_key>();
	QCOMPARE(keys.size(), 2);
	Passwd pass;
	pass = "BTD16-new-db-pass";
	try {
		Database.model<db_key>()->changeDatabasePassword(pass);
	} catch (errorEx &err) {
		QFAIL(qPrintable("password change failed: " + err.getString()));
	}
	for (pki_key *key : keys) {
		EVP_PKEY *pkey = key->decryptKey();
		QVERIFY(pkey);
		size_t len = 0;
		bool seed = EVP_PKEY_get_octet_string_param(pkey,
			OSSL_PKEY_PARAM_ML_DSA_SEED, nullptr, 0, &len) && len;
		ign_openssl_error();
		QCOMPARE(seed, key->getIntName() == "fixture-mldsa-seed");
		QCOMPARE(EVP_PKEY_eq(pkey, key->getPubKey()), 1);
		EVP_PKEY_free(pkey);
	}
}

/* A stored ML-DSA key that decrypts but that OpenSSL refuses (its seed
 * belongs to another key) is an error naming the key, not a NULL key
 * that decryptKey() retried 200 times (review of xca#52) */
void test_service_importexport::mlDsaUndecodableStoredKey()
{
	pki_key *key = newKey("ML-DSA-44", "undecodable");
	QVERIFY(key);
	QVariant item = key->getSqlItemId();

	PKCS8_PRIV_KEY_INFO *p8 = mismatchedMlDsa();
	QVERIFY(p8);
	X509_SIG *sig = PKCS8_encrypt(-1, EVP_aes_256_cbc(), dbPassword,
			strlen(dbPassword), nullptr, 0, PKCS5_DEFAULT_ITER, p8);
	PKCS8_PRIV_KEY_INFO_free(p8);
	QVERIFY(sig);
	unsigned char *der = nullptr;
	int len = i2d_X509_SIG(sig, &der);
	X509_SIG_free(sig);
	QVERIFY(len > 0);
	QByteArray b64 = QByteArray((const char *)der, len).toBase64();
	OPENSSL_free(der);
	{
		QSqlQuery q(QSqlDatabase::database());
		q.prepare("UPDATE private_keys SET private=? WHERE item=?");
		q.bindValue(0, QString::fromLatin1(b64));
		q.bindValue(1, item);
		QVERIFY2(q.exec(), CCHAR(q.lastError().text()));
	}
	reopenDatabase();
	key = Store.getAll<pki_key>()[0];
	try {
		EVP_PKEY *pkey = key->decryptKey();
		EVP_PKEY_free(pkey);
		QFAIL("decryptKey() returned a key");
	} catch (errorEx &err) {
		QVERIFY2(err.getString().contains("'undecodable' in the "
			"database cannot be read"), CCHAR(err.getString()));
	}
	ign_openssl_error();
}

void test_service_importexport::opensslBoolSetting_data()
{
	QTest::addColumn<QString>("value");
	QTest::addColumn<bool>("on");

	for (const char *off : { "no", "No", "NO", "0", "false", "False",
				"off", "OFF" })
		QTest::newRow(off) << off << false;
	for (const char *on : { "yes", "Yes", "1", "true", "TRUE", "on",
				"On" })
		QTest::newRow(on) << on << true;
	/* anything else keeps the default, like the provider */
	QTest::newRow("unset") << QString() << true;
	QTest::newRow("empty") << "" << true;
	QTest::newRow("other") << "nein" << true;
	QTest::newRow("00") << "00" << true;
}

/* An OpenSSL boolean setting as the provider reads it: 1, yes, true, on
 * and 0, no, false, off (BTD-194); the default for anything else */
void test_service_importexport::opensslBoolSetting()
{
	QFETCH(QString, value);
	QFETCH(bool, on);
	QByteArray v = value.toLatin1();
	const char *setting = value.isNull() ? nullptr : v.constData();
	QCOMPARE(openssl_bool(setting, true), on);
	/* the default only for values OpenSSL does not know */
	bool known = QStringList({ "no", "0", "false", "off", "yes", "1",
		"true", "on" }).contains(value, Qt::CaseInsensitive);
	QCOMPARE(openssl_bool(setting, false), known ? on : false);
}

void test_service_importexport::mlDsaStoredBy51_data()
{
	QTest::addColumn<QString>("name");
	QTest::addColumn<bool>("seed");
	QTest::addColumn<QString>("keyFormat");
	QTest::addColumn<int>("tag");

	QTest::newRow("seed-priv") << "seed-priv" << true << "" << 0x30;
	QTest::newRow("seed-only") << "seed-only" << true << "" << 0x30;
	QTest::newRow("priv-only") << "priv-only" << false << "expanded"
				<< 0x04;
}

/* ML-DSA keys as xca#51 stored them, in the encoding of the default
 * OpenSSL context (data/schema8-bxc3-mldsa51.sql): each decrypts with
 * the seed it had, and its export is read by openssl pkey (BTD-194) */
void test_service_importexport::mlDsaStoredBy51()
{
	QFETCH(QString, name);
	QFETCH(bool, seed);
	QFETCH(QString, keyFormat);
	QFETCH(int, tag);

	loadDump("schema8-bxc3-mldsa51.sql");
	pki_key *key = nullptr;
	for (pki_key *k : Store.getAll<pki_key>()) {
		if (k->getIntName() == "fixture51-" + name)
			key = k;
	}
	QVERIFY(key);
	EVP_PKEY *pkey = key->decryptKey();
	QVERIFY(pkey);
	size_t len = 0;
	bool hasSeed = EVP_PKEY_get_octet_string_param(pkey,
		OSSL_PKEY_PARAM_ML_DSA_SEED, nullptr, 0, &len) && len;
	ign_openssl_error();
	QCOMPARE(hasSeed, seed);
	QCOMPARE(EVP_PKEY_eq(pkey, key->getPubKey()), 1);
	EVP_PKEY_free(pkey);
#ifdef OPENSSL_PROGRAM
	QString out = file(name + ".der");
	exportFormat(Database.model<db_key>(), key, keyDerPrivate, out,
			keyFormat);
	QCOMPARE(mlDsaTag(out, keyDerPrivate), tag);
	QCOMPARE(publicKey(out, { "-inform", "DER" }), publicPem(key));
#endif
}

/* An individual password on an ML-DSA key (db_key::setOwnPass(), the
 * path of the key context menu), set and removed: after each step, in a
 * reopened database, the key decrypts with its seed (BTD-194) */
void test_service_importexport::mlDsaOwnPass()
{
	QVERIFY(newKey("ML-DSA-65", "own password"));
	/* the model of the database open now: check() reopens it */
	auto setOwnPass = [this](enum pki_key::passType own) {
		db_key *keys = Database.model<db_key>();
		keys->setOwnPass(keys->index(Store.getAll<pki_key>()[0]), own);
	};
	auto check = [this](enum pki_key::passType own) {
		reopenDatabase();
		QList<pki_key *> keys = Store.getAll<pki_key>();
		QCOMPARE(keys.size(), 1);
		QCOMPARE(keys[0]->getOwnPass(), own);
		if (own == pki_key::ptPrivate)
			pwdialog->expect("BTD194-own-pass");
		EVP_PKEY *pkey = keys[0]->decryptKey();
		QVERIFY(pkey);
		size_t len = 0;
		QVERIFY(EVP_PKEY_get_octet_string_param(pkey,
			OSSL_PKEY_PARAM_ML_DSA_SEED, nullptr, 0, &len));
		QCOMPARE(len, size_t(32));
		QCOMPARE(EVP_PKEY_eq(pkey, keys[0]->getPubKey()), 1);
		EVP_PKEY_free(pkey);
	};

	/* the new password, asked once when the key is encrypted */
	pwdialog->expect("BTD194-own-pass");
	setOwnPass(pki_key::ptPrivate);
	check(pki_key::ptPrivate);
	if (QTest::currentTestFailed())
		return;

	/* removed: the old password once to decrypt */
	pwdialog->expect("BTD194-own-pass");
	setOwnPass(pki_key::ptCommon);
	check(pki_key::ptCommon);
}

/* A key OpenSSL refuses (its seed belongs to another key): the error
 * names the source, never as empty quotes, and gives the reason of
 * OpenSSL, from a file and from unnamed data (BTD-194) */
void test_service_importexport::keyReadErrorNamesSource()
{
	QString name = file("mismatch.pem");
	QVERIFY(writeMismatchedMlDsa(name));

	QFile f(name);
	QVERIFY(f.open(QIODevice::ReadOnly));
	QByteArray pem = f.readAll();

	/* the import of data without a name, through pki_multi */
	ImportSpec spec;
	spec.data = pem;
	warning->expectMessage("The key cannot be read: error:");
	try {
		Database.importItems(ctx, spec);
	} catch (errorEx &) {
	}
	QCOMPARE(Store.getAll<pki_key>().size(), 0);

	/* the import of the file, through pki_multi */
	QList<pki_base *> created;
	warning->expectMessage(QString("The key in '%1' cannot be read: "
				"error:").arg(name));
	QVERIFY(!importError(name, &created).isEmpty());
	QCOMPARE(created.size(), 0);

	/* the PEM reader of pki_evp alone */
	pki_evp key;
	try {
		key.fromPEMbyteArray(pem, name);
		QFAIL("the key was read");
	} catch (errorEx &err) {
		QString msg = err.getString();
		QVERIFY2(msg.startsWith(QString("The key in '%1' cannot be "
			"read: error:").arg(name)), qPrintable(msg));
	}
	ign_openssl_error();
}

/* PKCS12_create() fails for a certificate and a key that do not belong
 * together. writePKCS12() throws and frees the decrypted key, the
 * certificate stack and the PKCS#12 structure on that path; the ASan
 * build (ADDRESS_SANITIZER=ON) reports a leak otherwise (BTD-194) */
void test_service_importexport::pkcs12CreateFailureFrees()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	/* imported, not issued: the ASan run sees only this path */
	importChain();
	pki_x509 *ca = cert("BTD34 CA"), *leaf = cert("BTD34 Leaf");
	QVERIFY(ca && leaf);
	pki_key *caKey = ca->getRefKey();
	QVERIFY(caKey);

	/* the end-entity certificate with the key of the CA */
	pki_pkcs12 p12(leaf->getIntName(), leaf, caKey);
	p12.append_item(ca);
	encAlgo enc = encAlgo::forExport();
	Passwd pass;
	pass = "BTD194-p12";
	QBuffer buf;
	QVERIFY(buf.open(QIODevice::WriteOnly));
	try {
		p12.writePKCS12(buf, enc, pass);
		QFAIL("PKCS#12 written for a key of another certificate");
	} catch (errorEx &err) {
		QVERIFY2(err.getString().contains("cannot be created: error:"),
			qPrintable(err.getString()));
	}
	QCOMPARE(buf.size(), qint64(0));
	ign_openssl_error();
#endif
}

/* An EC key whose public part belongs to another key: OpenSSL reads it,
 * EVP_PKEY_check() refuses it. The message names the file, and unnamed
 * data gets no empty quotes (BTD-204) */
void test_service_importexport::keyIncompleteNamesSource()
{
	EVP_PKEY *a = EVP_EC_gen("P-256"), *b = EVP_EC_gen("P-256");
	QVERIFY(a && b);
	BIGNUM *priv = nullptr;
	unsigned char pub[133];
	size_t publen = 0;
	QVERIFY(EVP_PKEY_get_bn_param(a, OSSL_PKEY_PARAM_PRIV_KEY, &priv));
	QVERIFY(EVP_PKEY_get_octet_string_param(b, OSSL_PKEY_PARAM_PUB_KEY,
			pub, sizeof pub, &publen));
	OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
	OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
			"prime256v1", 0);
	OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, priv);
	OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
			pub, publen);
	OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
	EVP_PKEY *mixed = nullptr;
	QVERIFY(EVP_PKEY_fromdata_init(pctx) > 0);
	QVERIFY(EVP_PKEY_fromdata(pctx, &mixed, EVP_PKEY_KEYPAIR, params) > 0);
	EVP_PKEY_CTX_free(pctx);
	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(bld);
	BN_free(priv);
	EVP_PKEY_free(a);
	EVP_PKEY_free(b);
	BioByteArray pem;
	QVERIFY(PEM_write_bio_PrivateKey(pem, mixed, nullptr, nullptr, 0,
			nullptr, nullptr));
	EVP_PKEY_free(mixed);
	QString name = file("mixed.pem");
	QFile f(name);
	QVERIFY(f.open(QIODevice::WriteOnly));
	f.write(pem.byteArray());
	f.close();

	QList<pki_base *> created;
	warning->expectMessage(QString("The key from file '%1' is incomplete "
				"or inconsistent").arg(name));
	QVERIFY(!importError(name, &created).isEmpty());
	QCOMPARE(created.size(), 0);

	ImportSpec spec;
	spec.data = pem.byteArray();
	warning->expectMessage("The key is incomplete or inconsistent");
	try {
		Database.importItems(ctx, spec);
	} catch (errorEx &) {
	}
	QCOMPARE(Store.getAll<pki_key>().size(), 0);
	ign_openssl_error();
}

XCA_SERVICE_TEST_MAIN(test_service_importexport)
#include "test_service_importexport.moc"
