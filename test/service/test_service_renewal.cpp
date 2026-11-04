/* vi: set sw=4 ts=4:
 *
 * Renewal and re-key as a service function (BTD-56): db_x509::renew()
 * issues through the same checks as db_x509::newCert(), copies subject
 * and extensions of the predecessor, stores the predecessor link
 * (table renewals) and writes one audit entry certificate.renew per
 * certificate. Several renewals are one transaction. A key revoked for
 * keyCompromise is never used again.
 */

#include <QDir>
#include <QFile>
#include <QProcess>
#include <QSqlQuery>
#include <QTemporaryDir>

#include <openssl/x509.h>
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
#include "lib/pki_x509.h"
#include "lib/pki_x509req.h"
#include "lib/profile.h"
#include "lib/profile_store.h"

#include "ServiceTestCase.h"

class test_service_renewal : public ServiceTestCase
{
	Q_OBJECT

	ServiceContext ctx{ ServiceContext::cli, "os:service-test" };
	QTemporaryDir dir{};

	static db_x509 *certs()
	{
		return Database.model<db_x509>();
	}
	static pki_key *newKey(const QString &name,
			const QString &job = "EC:prime256v1")
	{
		return Database.model<db_key>()->newKey(keyjob(job), name);
	}
	pki_x509 *issue(const IssuanceSpec &spec);
	pki_x509 *rootCa(const QString &cn, int days = 3650);
	pki_x509 *leaf(const QString &cn, pki_x509 *ca, pki_key *key = nullptr);
	static RenewalSpec renewal(pki_x509 *old, pki_key *newKey = nullptr);
	QString renewCode(const QList<RenewalSpec> &specs);
	QString openssl(const QStringList &args);
	bool importFiles(const QStringList &files);
	static pki_x509 *cert(const QString &cn);
	static QList<QByteArray> extensions(pki_x509 *c, bool withKeyIds);
	static QStringList renewalRow(pki_x509 *c);

  private slots:
	void renewKeepsKeySubjectAndExtensions();
	void rekeyLeaf();
	void rekeySelfSigned();
	void validityCappedAtIssuer();
	void keyCompromise_data();
	void keyCompromise();
	void allOrNothing();
	void keepSerial();
	void issuerChecks_data();
	void issuerChecks();
	void opcChainRules();
};

pki_x509 *test_service_renewal::issue(const IssuanceSpec &spec)
{
	try {
		return certs()->newCert(ctx, spec);
	} catch (errorEx &err) {
		qWarning() << "newCert failed:" << err.getString();
		return nullptr;
	}
}

pki_x509 *test_service_renewal::rootCa(const QString &cn, int days)
{
	IssuanceSpec spec;
	spec.name = cn;
	spec.subject.addEntryByNid(NID_organizationName, "BxC Security");
	spec.subject.addEntryByNid(NID_commonName, cn);
	spec.key = newKey(cn + " key");
	spec.notBefore = a1time(QDateTime::currentDateTimeUtc().addDays(-1));
	spec.notAfter = a1time(QDateTime::currentDateTimeUtc().addDays(days));
	spec.hashAlgo = digest(NID_sha256);
	spec.extensions.basicCA = ExtensionSpec::bc_ca;
	spec.extensions.basicCritical = true;
	spec.extensions.pathLen = "1";
	spec.extensions.subjectKeyId = true;
	spec.extensions.keyUsage << "keyCertSign" << "cRLSign";
	spec.extensions.keyUsageCritical = true;
	return issue(spec);
}

/* A leaf with every kind of extension the copy must keep */
pki_x509 *test_service_renewal::leaf(const QString &cn, pki_x509 *ca,
			pki_key *key)
{
	IssuanceSpec spec;
	spec.name = cn;
	spec.subject.addEntryByNid(NID_organizationName, "BxC Security");
	spec.subject.addEntryByNid(NID_commonName, cn);
	spec.key = key ? key : newKey(cn + " key");
	spec.signer = ca;
	spec.notBefore = a1time(QDateTime::currentDateTimeUtc().addDays(-1));
	spec.notAfter = a1time(QDateTime::currentDateTimeUtc().addDays(90));
	spec.hashAlgo = digest(NID_sha256);
	ExtensionSpec &e = spec.extensions;
	e.basicCA = ExtensionSpec::bc_not_ca;
	e.basicCritical = true;
	e.subjectKeyId = true;
	e.authorityKeyId = true;
	e.keyUsage << "digitalSignature";
	e.keyUsageCritical = true;
	e.extKeyUsage << "serverAuth" << "1.3.6.1.4.1.99999.7";
	e.subjectAltName = "DNS:" + cn + ", IP:10.0.0.10, URI:urn:bxc:" + cn;
	e.crlDistPoints = "URI:http://pki.example/root.crl";
	return issue(spec);
}

RenewalSpec test_service_renewal::renewal(pki_x509 *old, pki_key *newKey)
{
	RenewalSpec r;
	r.predecessor = old;
	r.newKey = newKey;
	r.notBefore = a1time(QDateTime::currentDateTimeUtc());
	r.validity = IsoDuration::parse("P1Y");
	r.hashAlgo = digest(NID_sha256);
	return r;
}

/* The error code of a refused renewal, "<renewed>" if it went through */
QString test_service_renewal::renewCode(const QList<RenewalSpec> &specs)
{
	try {
		certs()->renew(ctx, specs);
		return "<renewed>";
	} catch (serviceError &err) {
		return err.code;
	} catch (errorEx &err) {
		return "<errorEx: " + err.getString() + ">";
	}
}

QString test_service_renewal::openssl(const QStringList &args)
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

bool test_service_renewal::importFiles(const QStringList &files)
{
	ImportSpec spec;
	for (const QString &f : files)
		spec.files << dir.filePath(f);
	try {
		Database.importItems(ctx, spec);
	} catch (errorEx &err) {
		qWarning() << "import failed:" << err.getString();
		return false;
	}
	return true;
}

pki_x509 *test_service_renewal::cert(const QString &cn)
{
	for (pki_x509 *c : Store.getAll<pki_x509>()) {
		if (c->getSubject().getEntryByNid(NID_commonName) == cn)
			return c;
	}
	return nullptr;
}

/* Each extension as DER, in order; the key identifiers left out unless
 * withKeyIds */
QList<QByteArray> test_service_renewal::extensions(pki_x509 *c,
			bool withKeyIds)
{
	QList<QByteArray> l;
	X509 *x = c->getCert();
	for (int i = 0; i < X509_get_ext_count(x); i++) {
		const X509_EXTENSION *ext = X509_get_ext(x, i);
		int nid = OBJ_obj2nid(X509_EXTENSION_get_object(ext));
		if (!withKeyIds && (nid == NID_subject_key_identifier ||
				nid == NID_authority_key_identifier)) {
			l << QByteArray(OBJ_nid2sn(nid));
			continue;
		}
		unsigned char *der = nullptr;
		int len = i2d_X509_EXTENSION(ext, &der);
		l << QByteArray((const char *)der, len);
		OPENSSL_free(der);
	}
	return l;
}

/* predecessor|predecessor_serial|rekey of the renewals row of c */
QStringList test_service_renewal::renewalRow(pki_x509 *c)
{
	QSqlQuery q;
	q.prepare("SELECT predecessor, predecessor_serial, rekey FROM "
		"renewals WHERE item=?");
	q.bindValue(0, c->getSqlItemId());
	if (!q.exec() || !q.next())
		return QStringList();
	return QStringList{ q.value(0).toString(), q.value(1).toString(),
			q.value(2).toString() };
}

/* AC 1: same key, subject and every extension byte for byte in the same
 * order, a new serial, the link and one audit entry */
void test_service_renewal::renewKeepsKeySubjectAndExtensions()
{
	pki_x509 *ca = rootCa("Renewal Root CA");
	QVERIFY(ca);
	pki_x509 *old = leaf("plc10.example", ca);
	QVERIFY(old);
	int before = AuditLog::entries().size();

	QList<pki_x509 *> list = certs()->renew(ctx, { renewal(old) });
	QCOMPARE(list.size(), 1);
	pki_x509 *nu = list[0];
	QVERIFY(nu != old);
	QVERIFY(nu->getSerial() != old->getSerial());
	QCOMPARE(nu->getSubject(), old->getSubject());
	QCOMPARE(EVP_PKEY_eq(X509_get0_pubkey(nu->getCert()),
		X509_get0_pubkey(old->getCert())), 1);
	QCOMPARE(extensions(nu, true), extensions(old, true));
	QCOMPARE(nu->getSigner(), ca);
	QCOMPARE(nu->getIntName(), old->getIntName());
	QCOMPARE(nu->pkiSource, renewed);
	QCOMPARE(renewalRow(nu), (QStringList{
		old->getSqlItemId().toString(), old->getSerial().toHex(), "0" }));

	QList<AuditEntry> added = AuditLog::entries().mid(before);
	QCOMPARE(added.size(), 1);
	const AuditEntry &e = added[0];
	QCOMPARE(e.action, QString("certificate.renew"));
	QCOMPARE(e.result, QString("success"));
	QCOMPARE(e.channel, QString("cli"));
	QCOMPARE(e.objectId, nu->getSqlItemId().toString());
	QCOMPARE(e.params["predecessor_serial"].toString(),
		old->getSerial().toHex());
	QCOMPARE(e.params["predecessor_id"].toLongLong(),
		old->getSqlItemId().toLongLong());
	QCOMPARE(e.params["rekey"].toBool(), false);
	QCOMPARE(e.params["serial"].toString(), nu->getSerial().toHex());
	QVERIFY(AuditLog::verify().ok());
}

/* AC 1: a re-key gets the new key and its own subject key identifier,
 * everything else stays */
void test_service_renewal::rekeyLeaf()
{
	pki_x509 *ca = rootCa("Rekey Root CA");
	pki_x509 *old = leaf("plc11.example", ca);
	QVERIFY(ca && old);
	pki_key *key = newKey("plc11 new key", "RSA:2048");

	pki_x509 *nu = certs()->renew(ctx, { renewal(old, key) })[0];
	QCOMPARE(EVP_PKEY_eq(X509_get0_pubkey(nu->getCert()),
		key->getPubKey()), 1);
	QCOMPARE(nu->getRefKey(), key);
	QCOMPARE(extensions(nu, false), extensions(old, false));
	QVERIFY(extensions(nu, true) != extensions(old, true));
	/* the subject key identifier is the one of the new key */
	ASN1_OCTET_STRING *ski = (ASN1_OCTET_STRING *)X509_get_ext_d2i(
		nu->getCert(), NID_subject_key_identifier, nullptr, nullptr);
	QVERIFY(ski);
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int len = 0;
	QVERIFY(X509_pubkey_digest(nu->getCert(), EVP_sha1(), md, &len));
	QCOMPARE(QByteArray((const char *)ASN1_STRING_get0_data(ski),
			ASN1_STRING_get_length(ski)),
		QByteArray((const char *)md, len));
	ASN1_OCTET_STRING_free(ski);
	/* the authority key identifier still names the CA */
	QCOMPARE(QByteArray((const char *)ASN1_STRING_get0_data(
			X509_get0_authority_key_id(nu->getCert())), 20),
		QByteArray((const char *)ASN1_STRING_get0_data(
			X509_get0_subject_key_id(ca->getCert())), 20));
	QCOMPARE(renewalRow(nu).value(2), QString("1"));
	QCOMPARE(AuditLog::entries().last().params["rekey"].toBool(), true);
}

/* A self-signed root re-keyed: it signs itself with the new key, its
 * key identifiers are the new key's */
void test_service_renewal::rekeySelfSigned()
{
	IssuanceSpec spec;
	spec.name = "Rollover Root";
	spec.subject.addEntryByNid(NID_commonName, spec.name);
	spec.key = newKey("old root key");
	spec.notBefore = a1time(QDateTime::currentDateTimeUtc().addDays(-1));
	spec.notAfter = a1time(QDateTime::currentDateTimeUtc().addYears(5));
	spec.hashAlgo = digest(NID_sha256);
	spec.extensions.basicCA = ExtensionSpec::bc_ca;
	spec.extensions.subjectKeyId = true;
	spec.extensions.keyUsage << "keyCertSign" << "cRLSign";
	/* an AKI on a root, as imported roots often have */
	spec.extensions.advanced = "authorityKeyIdentifier=keyid:always";
	pki_x509 *old = issue(spec);
	QVERIFY(old);
	QVERIFY(X509_get0_authority_key_id(old->getCert()));
	pki_key *key = newKey("new root key");

	pki_x509 *nu = certs()->renew(ctx, { renewal(old, key) })[0];
	QCOMPARE(nu->getSigner(), nu);
	EVP_PKEY *pub = X509_get0_pubkey(nu->getCert());
	QCOMPARE(X509_verify(nu->getCert(), pub), 1);
	QCOMPARE(EVP_PKEY_eq(pub, key->getPubKey()), 1);
	const ASN1_OCTET_STRING *ski = X509_get0_subject_key_id(nu->getCert());
	const ASN1_OCTET_STRING *aki = X509_get0_authority_key_id(nu->getCert());
	QVERIFY(ski && aki);
	QCOMPARE(ASN1_OCTET_STRING_cmp(ski, aki), 0);
	QVERIFY(ASN1_OCTET_STRING_cmp(ski,
			X509_get0_subject_key_id(old->getCert())) != 0);
}

/* BTD-51: a renewal never outlives its CA; the cap is audited */
void test_service_renewal::validityCappedAtIssuer()
{
	pki_x509 *ca = rootCa("Short Root CA", 200);
	pki_x509 *old = leaf("plc12.example", ca);
	QVERIFY(ca && old);
	RenewalSpec r = renewal(old);
	r.validity = IsoDuration::parse("P5Y");

	pki_x509 *nu = certs()->renew(ctx, { r })[0];
	QCOMPARE(nu->getNotAfter(), ca->getNotAfter());
	AuditEntry e = AuditLog::entries().last();
	QCOMPARE(e.params["validity_capped"].toBool(), true);
	QVERIFY(e.params.contains("requested_not_after"));
}

void test_service_renewal::keyCompromise_data()
{
	QTest::addColumn<QString>("reason");
	QTest::addColumn<QString>("sameKey");
	QTest::addColumn<QString>("newKey");

	QTest::newRow("keyCompromise") << "Key Compromise"
		<< "key_compromised" << "<renewed>";
	QTest::newRow("superseded") << "Superseded"
		<< "<renewed>" << "<renewed>";
}

/* AC 2: a key revoked for keyCompromise is refused with a typed error
 * (audited); a re-key works and carries the warning */
void test_service_renewal::keyCompromise()
{
	QFETCH(QString, reason);
	QFETCH(QString, sameKey);
	QFETCH(QString, newKey);

	pki_x509 *ca = rootCa("Compromise Root CA");
	pki_x509 *old = leaf("plc13.example", ca);
	QVERIFY(ca && old);
	x509rev rev;
	rev.setReason(reason);
	certs()->revoke(ctx, old, rev);
	QVERIFY(old->isRevoked());
	int stored = Store.getAll<pki_x509>().size();

	QCOMPARE(renewCode({ renewal(old) }), sameKey);
	AuditEntry e = AuditLog::entries().last();
	QCOMPARE(e.action, QString("certificate.renew"));
	if (sameKey != "<renewed>") {
		QCOMPARE(e.result, QString("failure"));
		QCOMPARE(e.errorCode, sameKey);
		QCOMPARE(Store.getAll<pki_x509>().size(), stored);
	}
	/* the same key passed as "new" key is no re-key */
	QCOMPARE(renewCode({ renewal(old, old->getRefKey()) }), sameKey);

	QCOMPARE(renewCode({ renewal(old, this->newKey("plc13 new key")) }),
		newKey);
	e = AuditLog::entries().last();
	QCOMPARE(e.result, QString("success"));
	QCOMPARE(e.params.value("warning").toString(),
		reason == "Key Compromise" ? QString("predecessor_key_compromised")
					   : QString());
	QVERIFY(AuditLog::verify().ok());
}

/* AC 4: several renewals are one transaction. The second one fails (MD5
 * is never signed): neither is stored, there is no link, and exactly
 * one failure entry is kept after the rollback */
void test_service_renewal::allOrNothing()
{
	pki_x509 *ca = rootCa("Batch Root CA");
	pki_x509 *a = leaf("plc14.example", ca);
	pki_x509 *b = leaf("plc15.example", ca);
	QVERIFY(ca && a && b);
	int stored = Store.getAll<pki_x509>().size();
	int before = AuditLog::entries().size();
	RenewalSpec bad = renewal(b);
	bad.hashAlgo = digest(NID_md5);

	QCOMPARE(renewCode({ renewal(a), bad }),
		QString("signature_hash_not_allowed"));
	QCOMPARE(Store.getAll<pki_x509>().size(), stored);
	QSqlQuery q;
	QVERIFY(q.exec("SELECT COUNT(*) FROM renewals") && q.next());
	QCOMPARE(q.value(0).toInt(), 0);
	QList<AuditEntry> added = AuditLog::entries().mid(before);
	QCOMPARE(added.size(), 1);
	QCOMPARE(added[0].action, QString("certificate.renew"));
	QCOMPARE(added[0].result, QString("failure"));
	QCOMPARE(added[0].errorCode, QString("signature_hash_not_allowed"));
	QCOMPARE(added[0].params["predecessor_serial"].toString(),
		b->getSerial().toHex());
	QVERIFY(AuditLog::verify().ok());

	/* both fine: both stored, one entry each */
	QList<pki_x509 *> renewed = certs()->renew(ctx,
				{ renewal(a), renewal(b) });
	QCOMPARE(renewed.size(), 2);
	QCOMPARE(Store.getAll<pki_x509>().size(), stored + 2);
	QCOMPARE(AuditLog::entries().size(), before + 3);
}

/* The dialog's "keep serial" (with replace): the successor has the
 * predecessor's serial, audited as serial_kept */
void test_service_renewal::keepSerial()
{
	pki_x509 *ca = rootCa("Serial Root CA");
	pki_x509 *old = leaf("plc16.example", ca);
	QVERIFY(ca && old);
	a1int serial = old->getSerial();
	RenewalSpec r = renewal(old);
	r.keepSerial = true;

	pki_x509 *nu = certs()->renew(ctx, { r })[0];
	QCOMPARE(nu->getSerial(), serial);
	QCOMPARE(AuditLog::entries().last().params["serial_kept"].toBool(),
		true);
	certs()->deleteItems(ctx, { old });
	QCOMPARE(cert("plc16.example"), nu);
}

void test_service_renewal::issuerChecks_data()
{
	QTest::addColumn<QString>("variant");
	QTest::addColumn<QString>("code");

	QTest::newRow("issuer not a CA") << "no_ca" << "issuer_not_ca";
	QTest::newRow("issuer without keyCertSign") << "no_keycertsign"
				<< "issuer_no_keycertsign";
	QTest::newRow("expired issuer") << "expired" << "issuer_expired";
	QTest::newRow("issuer not yet valid") << "not_yet_valid"
				<< "issuer_not_yet_valid";
	QTest::newRow("path length") << "path_length"
				<< "path_length_exceeded";
	QTest::newRow("wrong CA key") << "wrong_key" << "issuer_key_mismatch";
}

/* AC 5: a renewal under an issuer that fails a check is refused with the
 * same typed error as a new issuance, audited as certificate.renew. The
 * chains are made by openssl, which checks nothing of the issuer. */
void test_service_renewal::issuerChecks()
{
	QFETCH(QString, variant);
	QFETCH(QString, code);
	pki_x509 *old = nullptr;
	RenewalSpec r;

	if (variant == "not_yet_valid") {
		pki_x509 *ca = rootCa("Young Root CA");
		old = leaf("young.example", ca);
		QVERIFY(old);
		r = renewal(old);
		/* before the start of the issuer */
		r.notBefore = a1time(QDateTime::currentDateTimeUtc().addDays(-5));
	} else if (variant == "wrong_key") {
		pki_x509 *ca = rootCa("Swapped Root CA");
		old = leaf("swapped.example", ca);
		QVERIFY(old);
		ca->setRefKey(newKey("other key"));
		r = renewal(old);
	} else {
#ifndef OPENSSL_PROGRAM
		QSKIP("openssl program not found");
#else
		QString caExt = variant == "no_ca" ?
			"basicConstraints=critical,CA:FALSE" :
			variant == "no_keycertsign" ?
			"keyUsage=critical,digitalSignature,cRLSign" :
			variant == "path_length" ?
			"basicConstraints=critical,CA:TRUE,pathlen:0" :
			"basicConstraints=critical,CA:TRUE";
		QStringList ca { "req", "-x509", "-newkey", "ec", "-pkeyopt",
			"ec_paramgen_curve:P-256", "-nodes", "-keyout", "ca.key",
			"-out", "ca.pem", "-subj", "/CN=Odd CA", "-addext",
			caExt };
		if (variant == "expired")
			ca << "-not_before" << "20200101000000Z"
			   << "-not_after" << "20210101000000Z";
		else
			ca << "-days" << "365";
		QVERIFY(!openssl(ca).isEmpty());
		QVERIFY(!openssl({ "req", "-new", "-newkey", "ec", "-pkeyopt",
			"ec_paramgen_curve:P-256", "-nodes", "-keyout", "ee.key",
			"-out", "ee.csr", "-subj", "/CN=odd.example" }).isEmpty());
		QFile ext(dir.filePath("ee.ext"));
		QVERIFY(ext.open(QIODevice::WriteOnly));
		/* a sub CA below pathlen:0, a leaf otherwise */
		ext.write(variant == "path_length" ?
			"basicConstraints=critical,CA:TRUE\n"
			"keyUsage=critical,keyCertSign,cRLSign\n" :
			"basicConstraints=critical,CA:FALSE\n"
			"keyUsage=critical,digitalSignature\n");
		ext.close();
		QVERIFY(!openssl({ "x509", "-req", "-in", "ee.csr", "-CA",
			"ca.pem", "-CAkey", "ca.key", "-out", "ee.pem",
			"-extfile", "ee.ext", "-days", "300" }).isEmpty());
		QVERIFY(importFiles({ "ca.key", "ca.pem", "ee.key", "ee.pem" }));
		old = cert("odd.example");
		QVERIFY(old && cert("Odd CA"));
		/* XCA links no issuer that is not a CA or lacks keyCertSign
		 * (certs.ca, X509_check_issued); such a predecessor has no
		 * signer (unknown_issuer). The link set by hand shows that
		 * the checks still guard the renewal. */
		if (!old->getSigner())
			old->setSigner(cert("Odd CA"));
		QCOMPARE(old->getSigner(), cert("Odd CA"));
		r = renewal(old);
#endif
	}
	int stored = Store.getAll<pki_x509>().size();
	int before = AuditLog::entries().size();
	QCOMPARE(renewCode({ r }), code);
	QCOMPARE(Store.getAll<pki_x509>().size(), stored);
	QList<AuditEntry> added = AuditLog::entries().mid(before);
	QCOMPARE(added.size(), 1);
	QCOMPARE(added[0].action, QString("certificate.renew"));
	QCOMPARE(added[0].result, QString("failure"));
	QCOMPARE(added[0].errorCode, code);
}

/* AC 5, OPC chain rules: a certificate issued under a stored opcua profile
 * is renewed under it again (policies, chain rules, issued_profiles); a
 * re-key to another curve than the CA's is refused like an issuance */
void test_service_renewal::opcChainRules()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	ProfileStore::importFile(ctx, "profile",
		SERVICE_TEST_DATA "/profiles/opcua-server.json");
	pki_x509 *ca = rootCa("OPC Root CA");
	QVERIFY(ca);
	ProfileStore::assign(ctx, ca, "profile", "opcua-server");
	QVERIFY(!openssl({ "req", "-new", "-newkey", "ec", "-pkeyopt",
		"ec_paramgen_curve:P-256", "-nodes", "-keyout", "srv.key",
		"-out", "srv.csr", "-subj", "/O=BxC/CN=srv", "-addext",
		"subjectAltName=URI:urn:bxc:srv,DNS:srv" }).isEmpty());
	pki_x509req *req = new pki_x509req("srv");
	req->fload(dir.filePath("srv.csr"));
	req = dynamic_cast<pki_x509req *>(
			Database.model<db_x509req>()->insert(req));
	QVERIFY(req);
	Registration reg;
	reg.applicationUri = "urn:bxc:srv";
	pki_x509 *old = ProfileStore::issue(ctx, ca, "opcua-server", req,
				nullptr, reg);
	QVERIFY(old);

	pki_x509 *nu = certs()->renew(ctx, { renewal(old) })[0];
	AuditEntry e = AuditLog::entries().last();
	QCOMPARE(e.params["profile"].toString(), QString("opcua-server"));
	QCOMPARE(e.params["profile_version"].toInt(), 1);
	QSqlQuery q;
	QVERIFY(q.exec(QString("SELECT profile FROM issued_profiles WHERE "
		"item=%1").arg(nu->getSqlItemId().toLongLong())) && q.next());
	QCOMPARE(q.value(0).toString(), QString("opcua-server"));

	pki_key *p384 = newKey("srv p384", "EC:secp384r1");
	int before = AuditLog::entries().size();
	QCOMPARE(renewCode({ renewal(old, p384) }),
		QString("opc_chain_curve_mismatch"));
	QCOMPARE(AuditLog::entries().size(), before + 1);
	QCOMPARE(AuditLog::entries().last().action, QString("certificate.renew"));
#endif
}

XCA_SERVICE_TEST_MAIN(test_service_renewal)
#include "test_service_renewal.moc"
