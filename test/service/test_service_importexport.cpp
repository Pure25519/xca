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
#include "lib/pki_crl.h"
#include "lib/pki_evp.h"
#include "lib/pki_multi.h"
#include "lib/pki_export.h"
#include "lib/pki_temp.h"
#include "lib/db_temp.h"
#include "lib/pki_x509.h"
#include "lib/sql.h"

#include "ServiceTestCase.h"

static const char exportVar[] = "BTD34_EXPORT_PASS";
static const char exportPass[] = "Export-Secret-34";
static const char p12Var[] = "BTD34_P12_PASS";
static const char p12Pass[] = "P12-Secret-34";

/* Format ids of pki_export::init_elements() */
enum {
	certPem = 1, certPkcs7Chain = 12, certDer = 13, certPkcs12Chain = 14,
	keyPemPrivate = 20, keyDerPrivate = 25, keyPkcs8Encrypted = 28,
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
};

QString test_service_importexport::openssl(const QStringList &args,
					int *exitCode)
{
#ifdef OPENSSL_PROGRAM
	QProcess p;
	p.setProcessChannelMode(QProcess::MergedChannels);
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
		/* The password dialog returns an empty password */
		pwdialog->expect(QByteArray());
		try {
			out = exportTo(db, item, format, QString());
			QVERIFY2(xport->match_all(F_PKCS12),
				"empty password accepted");
		} catch (serviceError &err) {
			QVERIFY(!xport->match_all(F_PKCS12));
			QCOMPARE(err.code, QString("missing_password"));
			QCOMPARE(entries("key.export_private").size(), 0);
			QCOMPARE(entries("object.export").last().errorCode,
				QString("missing_password"));
			return;
		}
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

	/* No PKI data. Short: the template loader takes any 8 bytes or
	 * more as an XCA template (upstream behaviour) */
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

XCA_SERVICE_TEST_MAIN(test_service_importexport)
#include "test_service_importexport.moc"
