/* vi: set sw=4 ts=4:
 *
 * Checks before every signature (BTD-55): path length explicit (0 and
 * absent differ, never an implicit 0) and counted along the issuer chain;
 * the issuer is a v3 CA with keyCertSign whose validity covers the new
 * certificate and whose key belongs to it; the CSR signature is verified;
 * the issuer of a stored certificate is found by key, not by DN alone;
 * the chain rules of OPC UA (OPC 10000-6 6.2, PLAN.md 14.4) when the spec
 * asks for them.
 */

#include <QDir>
#include <QFile>
#include <QProcess>
#include <QTemporaryDir>

#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/db_key.h"
#include "lib/db_x509.h"
#include "lib/db_x509req.h"
#include "lib/exception.h"
#include "lib/importexport.h"
#include "lib/issuance.h"
#include "lib/pki_evp.h"
#include "lib/pki_export.h"
#include "lib/pki_temp.h"
#include "lib/pki_x509.h"
#include "lib/pki_x509req.h"
#include "lib/request.h"
#include "lib/template.h"

#include "ServiceTestCase.h"

class test_service_signing : public ServiceTestCase
{
	Q_OBJECT

	ServiceContext ctx{ ServiceContext::cli, "os:service-test" };
	QTemporaryDir dir{};

	static pki_key *newKey(const QString &name, const QString &job)
	{
		return Database.model<db_key>()->newKey(keyjob(job), name);
	}
	static x509name dn(const QString &cn)
	{
		x509name n;
		n.addEntryByNid(NID_countryName, "DE");
		n.addEntryByNid(NID_organizationName, "BxC Security");
		n.addEntryByNid(NID_commonName, cn);
		return n;
	}
	static IssuanceSpec caSpec(const QString &cn, pki_key *key,
			pki_x509 *signer, const QString &pathLen = QString());
	static IssuanceSpec leafSpec(const QString &cn, pki_key *key,
			pki_x509 *signer);
	pki_x509 *issue(const IssuanceSpec &spec);
	void expectRejected(const IssuanceSpec &spec, const QString &code);
	QString openssl(const QStringList &args);
	bool importFiles(const QStringList &files);
	pki_x509 *cert(const QString &cn);
	void writePem(pki_x509 *cert, const QString &file);
	void verifyChain(const QList<pki_x509 *> &chain);
	static QString extText(pki_x509 *cert, int nid);

  private slots:
	void pathLength();
	void pathLengthParsing_data();
	void pathLengthParsing();
	void requestPathLength();
	void templateKeepsPathLength_data();
	void templateKeepsPathLength();
	void issuerChecks_data();
	void issuerChecks();
	void csrSignatureVerified();
	void issuerFoundByKey_data();
	void issuerFoundByKey();
	void opcChainsPass_data();
	void opcChainsPass();
	void opcChainRules_data();
	void opcChainRules();
	void insecureDigest_data();
	void insecureDigest();
	void duplicateExtension();
};

IssuanceSpec test_service_signing::caSpec(const QString &cn, pki_key *key,
			pki_x509 *signer, const QString &pathLen)
{
	IssuanceSpec spec;
	spec.name = cn;
	spec.subject = dn(cn);
	spec.key = key;
	spec.signer = signer;
	spec.notBefore = a1time();
	spec.notAfter = a1time(QDateTime::currentDateTimeUtc().addDays(
				signer ? 1825 : 3650));
	spec.hashAlgo = digest(NID_sha256);
	spec.extensions.basicCA = ExtensionSpec::bc_ca;
	spec.extensions.basicCritical = true;
	spec.extensions.pathLen = pathLen;
	spec.extensions.subjectKeyId = true;
	spec.extensions.authorityKeyId = true;
	spec.extensions.keyUsage << "keyCertSign" << "cRLSign";
	spec.extensions.keyUsageCritical = true;
	return spec;
}

IssuanceSpec test_service_signing::leafSpec(const QString &cn, pki_key *key,
			pki_x509 *signer)
{
	IssuanceSpec spec;
	spec.name = cn;
	spec.subject = dn(cn);
	spec.key = key;
	spec.signer = signer;
	spec.notBefore = a1time();
	spec.notAfter = a1time(QDateTime::currentDateTimeUtc().addDays(90));
	spec.hashAlgo = digest(NID_sha256);
	spec.extensions.basicCA = ExtensionSpec::bc_not_ca;
	spec.extensions.basicCritical = true;
	spec.extensions.subjectKeyId = true;
	spec.extensions.authorityKeyId = true;
	spec.extensions.keyUsage << "digitalSignature";
	spec.extensions.extKeyUsage << "serverAuth" << "clientAuth";
	spec.extensions.subjectAltName = "DNS:" + cn;
	return spec;
}

pki_x509 *test_service_signing::issue(const IssuanceSpec &spec)
{
	try {
		return Database.model<db_x509>()->newCert(ctx, spec);
	} catch (errorEx &err) {
		qWarning() << "newCert failed:" << err.getString();
		return nullptr;
	}
}

/* A typed rejection, audited as a failure with the same code */
void test_service_signing::expectRejected(const IssuanceSpec &spec,
			const QString &code)
{
	int before = AuditLog::entries().size();
	QString got;
	try {
		Database.model<db_x509>()->newCert(ctx, spec);
		got = "<issued>";
	} catch (serviceError &err) {
		got = err.code;
	} catch (errorEx &err) {
		got = "<errorEx: " + err.getString() + ">";
	}
	QCOMPARE(got, code);
	QList<AuditEntry> entries = AuditLog::entries();
	QCOMPARE(entries.size(), before + 1);
	QCOMPARE(entries.last().action, QString("certificate.issue"));
	QCOMPARE(entries.last().result, QString("failure"));
	QCOMPARE(entries.last().errorCode, code);
	QVERIFY(AuditLog::verify().ok());
}

QString test_service_signing::openssl(const QStringList &args)
{
#ifdef OPENSSL_PROGRAM
	QProcess p;
	p.setProcessChannelMode(QProcess::MergedChannels);
	p.setWorkingDirectory(dir.path());
	p.start(OPENSSL_PROGRAM, args);
	if (!p.waitForFinished(60000) || p.exitCode() != 0) {
		qWarning() << "openssl" << args << "failed:" << p.readAll();
		return QString();
	}
	return QString::fromUtf8(p.readAll()) + " ";
#else
	Q_UNUSED(args);
	return QString();
#endif
}

bool test_service_signing::importFiles(const QStringList &files)
{
	ImportSpec spec;
	foreach(QString f, files)
		spec.files << dir.filePath(f);
	try {
		Database.importItems(ctx, spec);
	} catch (errorEx &err) {
		qWarning() << "import failed:" << err.getString();
		return false;
	}
	return true;
}

pki_x509 *test_service_signing::cert(const QString &cn)
{
	foreach(pki_x509 *c, Store.getAll<pki_x509>()) {
		if (c->getSubject().getEntryByNid(NID_commonName) == cn)
			return c;
	}
	return nullptr;
}

void test_service_signing::writePem(pki_x509 *c, const QString &file)
{
	BIO *b = BIO_new_file(QFile::encodeName(file).constData(), "w");
	QVERIFY(b);
	QVERIFY(PEM_write_bio_X509(b, c->getCert()));
	BIO_free(b);
}

/* chain: leaf first, root last */
void test_service_signing::verifyChain(const QList<pki_x509 *> &chain)
{
	QString root = dir.filePath("v-root.pem");
	QString untrusted = dir.filePath("v-untrusted.pem");
	QString leaf = dir.filePath("v-leaf.pem");
	writePem(chain.last(), root);
	QFile::remove(untrusted);
	QStringList args{ "verify", "-x509_strict", "-CAfile", root };
	if (chain.size() > 2) {
		QFile out(untrusted);
		QVERIFY(out.open(QIODevice::WriteOnly));
		for (int i = 1; i < chain.size() - 1; i++)
			chain[i]->writeCert(out, true);
		out.close();
		args << "-untrusted" << untrusted;
	}
	writePem(chain.first(), leaf);
	args << leaf;
	QString out = openssl(args);
	QVERIFY2(out.contains("v-leaf.pem: OK"), CCHAR(out));
}

QString test_service_signing::extText(pki_x509 *c, int nid)
{
	X509 *x = c->getCert();
	int i = X509_get_ext_by_NID(x, nid, -1);
	if (i < 0)
		return QString();
	const X509_EXTENSION *ext = X509_get_ext(x, i);
	BIO *b = BIO_new(BIO_s_mem());
	X509V3_EXT_print(b, ext, 0, 0);
	char *data;
	long len = BIO_get_mem_data(b, &data);
	QString s = QString::fromUtf8(data, len);
	BIO_free(b);
	return (X509_EXTENSION_get_critical(ext) ? "critical: " : "") + s;
}

/* AC 1: root without pathLen, intermediates with pathLen 1 and 0; the
 * path length of every CA above counts, not only the issuer's */
void test_service_signing::pathLength()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	pki_x509 *root = issue(caSpec("Root CA",
			newKey("root", "EC:prime256v1"), nullptr));
	QVERIFY(root);
	pki_x509 *mid = issue(caSpec("Mid CA",
			newKey("mid", "EC:prime256v1"), root, "1"));
	QVERIFY(mid);
	pki_x509 *sub = issue(caSpec("Sub CA",
			newKey("sub", "EC:prime256v1"), mid, "0"));
	QVERIFY(sub);
	pki_x509 *leaf = issue(leafSpec("leaf.example",
			newKey("leaf", "EC:prime256v1"), sub));
	QVERIFY(leaf);

	QCOMPARE(extText(root, NID_basic_constraints),
		QString("critical: CA:TRUE"));
	QCOMPARE(extText(mid, NID_basic_constraints),
		QString("critical: CA:TRUE, pathlen:1"));
	QCOMPARE(extText(sub, NID_basic_constraints),
		QString("critical: CA:TRUE, pathlen:0"));
	verifyChain({ leaf, sub, mid, root });

	/* pathLen 0: no CA below Sub CA */
	expectRejected(caSpec("Too Deep CA",
			newKey("deep", "EC:prime256v1"), sub), "path_length_exceeded");

	/* Mid CA allows one CA below it: a second level without its own
	 * pathLen is still bounded by Mid CA */
	pki_x509 *open = issue(caSpec("Open Sub CA",
			newKey("open", "EC:prime256v1"), mid));
	QVERIFY(open);
	expectRejected(caSpec("Below Open CA",
			newKey("below", "EC:prime256v1"), open),
			"path_length_exceeded");
	/* End entities are never limited by pathLen */
	QVERIFY(issue(leafSpec("leaf2.example",
			newKey("leaf2", "EC:prime256v1"), open)));
#endif
}

void test_service_signing::pathLengthParsing_data()
{
	QTest::addColumn<QString>("pathLen");
	QTest::addColumn<QString>("expected");   // basicConstraints or code

	QTest::newRow("absent") << "" << "critical: CA:TRUE";
	QTest::newRow("zero") << "0" << "critical: CA:TRUE, pathlen:0";
	QTest::newRow("three") << "3" << "critical: CA:TRUE, pathlen:3";
	QTest::newRow("text") << "abc" << "invalid_path_length";
	QTest::newRow("negative") << "-1" << "invalid_path_length";
	QTest::newRow("fraction") << "1.5" << "invalid_path_length";
	QTest::newRow("plus sign") << "+1" << "invalid_path_length";
	QTest::newRow("blank") << " " << "invalid_path_length";
}

/* Never an implicit pathLen 0: toInt() made 0 of every non-number */
void test_service_signing::pathLengthParsing()
{
	QFETCH(QString, pathLen);
	QFETCH(QString, expected);

	IssuanceSpec spec = caSpec("Root CA", newKey("root", "EC:prime256v1"),
				nullptr, pathLen);
	if (expected.startsWith("critical")) {
		pki_x509 *root = issue(spec);
		QVERIFY(root);
		QCOMPARE(extText(root, NID_basic_constraints), expected);
	} else {
		expectRejected(spec, expected);
	}
}

/* A request of a CA asks for the same explicit path length */
void test_service_signing::requestPathLength()
{
	RequestSpec spec;
	spec.name = "ca-request";
	spec.subject = dn("Requested CA");
	spec.key = newKey("req", "EC:prime256v1");
	spec.hashAlgo = digest(NID_sha256);
	spec.extensions.basicCA = ExtensionSpec::bc_ca;
	spec.extensions.pathLen = "abc";
	QString code;
	try {
		Database.model<db_x509req>()->newRequest(ctx, spec);
		code = "<created>";
	} catch (serviceError &err) {
		code = err.code;
	}
	QCOMPARE(code, QString("invalid_path_length"));
	QCOMPARE(AuditLog::entries().last().errorCode, code);
	spec.extensions.pathLen = "0";
	QVERIFY(Database.model<db_x509req>()->newRequest(ctx, spec));
}

void test_service_signing::templateKeepsPathLength_data()
{
	QTest::addColumn<QString>("pathLen");
	QTest::newRow("absent") << "";
	QTest::newRow("zero") << "0";
	QTest::newRow("two") << "2";
	QTest::newRow("text") << "abc";
}

/* A template must not turn an invalid path length into 0; issuing from it
 * then fails with invalid_path_length instead of a silent pathlen:0 */
void test_service_signing::templateKeepsPathLength()
{
	QFETCH(QString, pathLen);

	TemplateSpec ts;
	ts.name = "ca-template";
	ts.extensions.basicCA = ExtensionSpec::bc_ca;
	ts.extensions.pathLen = pathLen;
	pki_temp temp("ca-template");
	ts.toTemplate(&temp);
	QCOMPARE(TemplateSpec::fromTemplate(&temp).extensions.pathLen, pathLen);
}

void test_service_signing::issuerChecks_data()
{
	QTest::addColumn<QString>("variant");
	QTest::addColumn<QString>("code");

	QTest::newRow("issuer not a CA") << "no_ca" << "issuer_not_ca";
	QTest::newRow("issuer without keyCertSign") << "no_keycertsign"
				<< "issuer_no_keycertsign";
	QTest::newRow("issuer without key usage") << "no_key_usage"
				<< "issuer_no_keycertsign";
	QTest::newRow("expired issuer") << "expired" << "issuer_expired";
	QTest::newRow("issuer not yet valid") << "not_yet_valid"
				<< "issuer_not_yet_valid";
	QTest::newRow("wrong CA key") << "wrong_key" << "issuer_key_mismatch";
	QTest::newRow("v1 issuer") << "v1" << "issuer_v1";
}

/* AC 2: one negative test per issuer check, each a typed error */
void test_service_signing::issuerChecks()
{
	QFETCH(QString, variant);
	QFETCH(QString, code);
	QDateTime now = QDateTime::currentDateTimeUtc();
	pki_x509 *issuer = nullptr;

	if (variant == "no_ca") {
		pki_x509 *root = issue(caSpec("Root CA",
				newKey("root", "EC:prime256v1"), nullptr));
		QVERIFY(root);
		issuer = issue(leafSpec("not-a-ca.example",
				newKey("nca", "EC:prime256v1"), root));
	} else if (variant == "no_keycertsign" || variant == "no_key_usage") {
		IssuanceSpec s = caSpec("Odd Root CA",
				newKey("root", "EC:prime256v1"), nullptr);
		s.extensions.keyUsage.clear();
		if (variant == "no_keycertsign")
			s.extensions.keyUsage << "cRLSign" << "digitalSignature";
		issuer = issue(s);
	} else if (variant == "expired") {
		IssuanceSpec s = caSpec("Old Root CA",
				newKey("root", "EC:prime256v1"), nullptr);
		s.notBefore = a1time(now.addDays(-60));
		s.notAfter = a1time(now.addDays(-1));
		issuer = issue(s);
	} else if (variant == "not_yet_valid") {
		IssuanceSpec s = caSpec("Future Root CA",
				newKey("root", "EC:prime256v1"), nullptr);
		s.notBefore = a1time(now.addDays(10));
		s.notAfter = a1time(now.addDays(400));
		issuer = issue(s);
	} else if (variant == "wrong_key") {
		pki_key *other = newKey("other", "EC:prime256v1");
		issuer = issue(caSpec("Root CA",
				newKey("root", "EC:prime256v1"), nullptr));
		QVERIFY(issuer && other);
		/* the certificate points at a private key that is not its own */
		issuer->setRefKey(other);
	} else if (variant == "v1") {
#ifndef OPENSSL_PROGRAM
		QSKIP("openssl program not found");
#else
		/* OpenSSL 4 writes version 3 unless asked for version 1 */
		QVERIFY(!openssl({ "req", "-x509", "-x509v1", "-newkey", "ec",
			"-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
			"-keyout", "v1.key", "-out", "v1.pem",
			"-subj", "/CN=V1 Root", "-days", "30" }).isEmpty());
		QVERIFY(importFiles({ "v1.key", "v1.pem" }));
		issuer = cert("V1 Root");
		QVERIFY(issuer);
		QCOMPARE(X509_get_version(issuer->getCert()), (long)X509_VERSION_1);
#endif
	}
	QVERIFY(issuer);
	expectRejected(leafSpec("leaf.example",
			newKey("leaf", "EC:prime256v1"), issuer), code);
}

/* Proof of possession: a CSR whose signature does not verify is never
 * signed */
void test_service_signing::csrSignatureVerified()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	pki_x509 *root = issue(caSpec("Root CA",
			newKey("root", "EC:prime256v1"), nullptr));
	QVERIFY(root);
	QVERIFY(!openssl({ "req", "-new", "-newkey", "ec", "-pkeyopt",
		"ec_paramgen_curve:P-256", "-nodes", "-keyout", "ee.key",
		"-outform", "DER", "-out", "ee.der",
		"-subj", "/CN=device.example" }).isEmpty());
	QFile f(dir.filePath("ee.der"));
	QVERIFY(f.open(QIODevice::ReadOnly));
	QByteArray der = f.readAll();
	f.close();
	/* the last byte belongs to the signature value */
	der[der.size() - 1] = der[der.size() - 1] ^ 0x01;
	QFile t(dir.filePath("tampered.der"));
	QVERIFY(t.open(QIODevice::WriteOnly));
	t.write(der);
	t.close();

	pki_x509req *req = new pki_x509req("tampered");
	req->fload(dir.filePath("tampered.der"));
	req = dynamic_cast<pki_x509req *>(
			Database.model<db_x509req>()->insert(req));
	QVERIFY(req);
	QVERIFY(!req->verify());

	IssuanceSpec spec = leafSpec("device.example", nullptr, root);
	spec.request = req;
	spec.subject = req->getSubject();
	expectRejected(spec, "invalid_csr_signature");
	QVERIFY(!req->getDone());
#endif
}

void test_service_signing::issuerFoundByKey_data()
{
	QTest::addColumn<bool>("withAki");
	QTest::newRow("leaf with AKI") << true;
	QTest::newRow("leaf without AKI") << false;
}

/* AC 3: two CAs with the same DN; the issuer of the leaf is the one whose
 * key signed it, also after a reopen and in the chain export */
void test_service_signing::issuerFoundByKey()
{
	QFETCH(bool, withAki);

	IssuanceSpec a = caSpec("Twin CA", newKey("twin-a", "EC:prime256v1"),
				nullptr);
	a.name = "twin-a";
	a.notAfter = a1time(QDateTime::currentDateTimeUtc().addDays(1000));
	pki_x509 *caA = issue(a);
	IssuanceSpec b = caSpec("Twin CA", newKey("twin-b", "EC:prime256v1"),
				nullptr);
	b.name = "twin-b";
	/* the later notAfter made findIssuer() prefer it */
	b.notAfter = a1time(QDateTime::currentDateTimeUtc().addDays(2000));
	pki_x509 *caB = issue(b);
	QVERIFY(caA && caB);

	IssuanceSpec l = leafSpec("leaf.example",
			newKey("leaf", "EC:prime256v1"), caA);
	l.extensions.authorityKeyId = withAki;
	pki_x509 *leaf = issue(l);
	QVERIFY(leaf);
	QCOMPARE(leaf->getSigner(), caA);

	QList<pki_base *> chain = Database.model<db_x509>()->exportedObjects(
			{ leaf }, pki_export::by_id(12));   // PKCS#7 chain
	QCOMPARE(chain, QList<pki_base *>() << leaf << caA);

	reopenDatabase();
	leaf = cert("leaf.example");
	QVERIFY(leaf);
	QVERIFY(leaf->getSigner());
	QCOMPARE(leaf->getSigner()->getIntName(), QString("twin-a"));

	/* An imported certificate finds its issuer by the signature, even
	 * when the other twin has the later notAfter */
	writePem(leaf, dir.filePath("leaf.pem"));
	Database.model<db_x509>()->deleteItems(ctx, { leaf });
	QVERIFY(!cert("leaf.example"));
	QVERIFY(importFiles({ "leaf.pem" }));
	leaf = cert("leaf.example");
	QVERIFY(leaf && leaf->getSigner());
	QCOMPARE(leaf->getSigner()->getIntName(), QString("twin-a"));
	QList<pki_base *> chain2 = Database.model<db_x509>()->exportedObjects(
			{ leaf }, pki_export::by_id(12));
	QCOMPARE(chain2.size(), 2);
	QCOMPARE(chain2[1]->getIntName(), QString("twin-a"));
}

void test_service_signing::opcChainsPass_data()
{
	QTest::addColumn<QString>("rootKey");
	QTest::addColumn<QString>("issuingKey");
	QTest::addColumn<QString>("leafKey");

	QTest::newRow("ot-rsa") << "RSA:4096" << "RSA:3072" << "RSA:2048";
	QTest::newRow("ot-p256") << "EC:secp384r1" << "EC:prime256v1"
				<< "EC:prime256v1";
}

/* AC 4, positive: the lab hierarchies of PLAN.md 14.1 pass the OPC rules
 * and verify */
void test_service_signing::opcChainsPass()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	QFETCH(QString, rootKey);
	QFETCH(QString, issuingKey);
	QFETCH(QString, leafKey);

	IssuanceSpec r = caSpec("OT Root CA", newKey("root", rootKey), nullptr);
	r.chainRules = IssuanceSpec::chain_opcua;
	pki_x509 *root = issue(r);
	QVERIFY(root);
	IssuanceSpec i = caSpec("OT Issuing CA", newKey("issuing", issuingKey),
				root, "0");
	i.chainRules = IssuanceSpec::chain_opcua;
	pki_x509 *issuing = issue(i);
	QVERIFY(issuing);
	IssuanceSpec l = leafSpec("plc10.example", newKey("leaf", leafKey),
				issuing);
	l.chainRules = IssuanceSpec::chain_opcua;
	pki_x509 *leaf = issue(l);
	QVERIFY(leaf);
	verifyChain({ leaf, issuing, root });
#endif
}

void test_service_signing::opcChainRules_data()
{
	QTest::addColumn<QString>("variant");
	QTest::addColumn<QString>("code");

	QTest::newRow("P-384 issuing CA, P-256 leaf") << "p384_issuer"
				<< "opc_chain_curve_mismatch";
	QTest::newRow("PSS-signed RSA root") << "pss_root"
				<< "opc_chain_rsa_pss";
	QTest::newRow("RSA-4096 leaf under RSA-2048 CA") << "rsa_longer_leaf"
				<< "opc_chain_key_longer_than_issuer";
	QTest::newRow("RSA-1024 leaf") << "rsa_small_leaf"
				<< "opc_chain_rsa_key_size";
	QTest::newRow("CA without cRLSign") << "no_crlsign"
				<< "opc_chain_issuer_no_crlsign";
	QTest::newRow("ML-DSA root") << "mldsa_root" << "opc_chain_pqc";
	QTest::newRow("EC leaf under RSA CA") << "mixed" << "opc_chain_algorithm_mix";
}

/* AC 4, negative: each OPC rule is a typed error with chain_opcua; the
 * same chain is accepted under plain RFC 5280 rules */
void test_service_signing::opcChainRules()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	QFETCH(QString, variant);
	QFETCH(QString, code);
	pki_x509 *issuer = nullptr;
	QString leafKey = "EC:prime256v1";

	if (variant == "p384_issuer") {
		issuer = issue(caSpec("P384 CA",
				newKey("ca", "EC:secp384r1"), nullptr));
	} else if (variant == "rsa_longer_leaf") {
		issuer = issue(caSpec("RSA2048 CA",
				newKey("ca", "RSA:2048"), nullptr));
		leafKey = "RSA:4096";
	} else if (variant == "rsa_small_leaf") {
		issuer = issue(caSpec("RSA2048 CA",
				newKey("ca", "RSA:2048"), nullptr));
		leafKey = "RSA:1024";
	} else if (variant == "mixed") {
		issuer = issue(caSpec("RSA2048 CA",
				newKey("ca", "RSA:2048"), nullptr));
	} else if (variant == "no_crlsign") {
		IssuanceSpec s = caSpec("No CRL CA",
				newKey("ca", "EC:prime256v1"), nullptr);
		s.extensions.keyUsage = QStringList{ "keyCertSign" };
		issuer = issue(s);
	} else if (variant == "pss_root") {
		QVERIFY(!openssl({ "req", "-x509", "-newkey", "rsa:2048",
			"-nodes", "-keyout", "pss.key", "-out", "pss.pem",
			"-subj", "/CN=PSS Root", "-days", "30",
			"-sigopt", "rsa_padding_mode:pss",
			"-sigopt", "rsa_pss_saltlen:32",
			"-addext", "basicConstraints=critical,CA:TRUE",
			"-addext", "keyUsage=critical,keyCertSign,cRLSign" })
			.isEmpty());
		QVERIFY(importFiles({ "pss.key", "pss.pem" }));
		issuer = cert("PSS Root");
		leafKey = "RSA:2048";
	} else if (variant == "mldsa_root") {
		/* ML-DSA root outside the database's key store; the P-256
		 * issuing CA below it signs the leaf */
		QVERIFY(!openssl({ "req", "-x509", "-newkey", "ML-DSA-65",
			"-nodes", "-keyout", "mldsa.key", "-out", "mldsa.pem",
			"-subj", "/CN=PQC Root", "-days", "30",
			"-addext", "basicConstraints=critical,CA:TRUE",
			"-addext", "keyUsage=critical,keyCertSign,cRLSign" })
			.isEmpty());
		QVERIFY(!openssl({ "req", "-new", "-newkey", "ec", "-pkeyopt",
			"ec_paramgen_curve:P-256", "-nodes", "-keyout", "ica.key",
			"-out", "ica.csr", "-subj", "/CN=PQC Issuing CA" })
			.isEmpty());
		QFile ext(dir.filePath("ica.ext"));
		QVERIFY(ext.open(QIODevice::WriteOnly));
		ext.write("basicConstraints=critical,CA:TRUE,pathlen:0\n"
			"keyUsage=critical,keyCertSign,cRLSign\n"
			"subjectKeyIdentifier=hash\n"
			"authorityKeyIdentifier=keyid\n");
		ext.close();
		QVERIFY(!openssl({ "x509", "-req", "-in", "ica.csr",
			"-CA", "mldsa.pem", "-CAkey", "mldsa.key", "-days", "30",
			"-extfile", "ica.ext", "-out", "ica.pem" }).isEmpty());
		QVERIFY(importFiles({ "mldsa.pem", "ica.key", "ica.pem" }));
		issuer = cert("PQC Issuing CA");
		QVERIFY(issuer);
		QVERIFY(issuer->getSigner());
	}
	QVERIFY(issuer);

	IssuanceSpec l = leafSpec("plc.example", newKey("leaf", leafKey),
				issuer);
	l.chainRules = IssuanceSpec::chain_opcua;
	expectRejected(l, code);

	l.chainRules = IssuanceSpec::chain_rfc5280;
	l.name = "plc-rfc5280";
	QVERIFY(issue(l));
#endif
}

void test_service_signing::insecureDigest_data()
{
	QTest::addColumn<int>("nid");
	QTest::newRow("SHA-1") << (int)NID_sha1;
	QTest::newRow("MD5") << (int)NID_md5;
}

/* No certificate is signed with an insecure digest (BTD-53 note 3, also
 * the rule of BTD-65), self-signed or not */
void test_service_signing::insecureDigest()
{
	QFETCH(int, nid);
	IssuanceSpec root = caSpec("Root CA", newKey("root", "RSA:2048"),
				nullptr);
	root.hashAlgo = digest(nid);
	expectRejected(root, "signature_hash_not_allowed");
	root.hashAlgo = digest(NID_sha256);
	pki_x509 *ca = issue(root);
	QVERIFY(ca);
	IssuanceSpec leaf = leafSpec("leaf.example",
			newKey("leaf", "RSA:2048"), ca);
	leaf.hashAlgo = digest(nid);
	expectRejected(leaf, "signature_hash_not_allowed");
}

/* Never two instances of one extension (BTD-53 note 4): the Advanced tab
 * adds a second keyUsage next to the one of the key usage list */
void test_service_signing::duplicateExtension()
{
	IssuanceSpec spec = caSpec("Root CA", newKey("root", "EC:prime256v1"),
				nullptr);
	spec.extensions.advanced = "keyUsage=digitalSignature\n";
	expectRejected(spec, "duplicate_extension");
}

XCA_SERVICE_TEST_MAIN(test_service_signing)
#include "test_service_signing.moc"
