/* vi: set sw=4 ts=4:
 *
 * Revocation and CRL generation through the service functions of
 * BTD-33: db_x509::revoke(), unrevoke(), setRevocations(),
 * certBySerial() and db_crl::newCrl(). Every CRL is checked with
 * openssl crl -CAfile; one audit entry per operation, the chain and the
 * revocations table verify.
 */

#include <QFile>
#include <QProcess>
#include <QTemporaryDir>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "lib/PwDialogCore.h"
#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/db_crl.h"
#include "lib/db_key.h"
#include "lib/db_x509.h"
#include "lib/exception.h"
#include "lib/issuance.h"
#include "lib/json_report.h"
#include "lib/pass_info.h"
#include "lib/pki_crl.h"
#include "lib/pki_evp.h"
#include "lib/pki_x509.h"

#include "ServiceTestCase.h"

class test_service_revocation : public ServiceTestCase
{
	Q_OBJECT

	ServiceContext ctx{ ServiceContext::cli, "os:service-test" };
	QTemporaryDir dir{};

	static db_x509 *certs()
	{
		return Database.model<db_x509>();
	}
	static db_crl *crls()
	{
		return Database.model<db_crl>();
	}
	static pki_key *newKey(const QString &name)
	{
		return Database.model<db_key>()->newKey(
				keyjob("EC:prime256v1"), name);
	}
	pki_x509 *issue(const QString &cn, pki_key *key, pki_x509 *signer,
			const QDateTime &notBefore, const QDateTime &notAfter,
			bool subjectKeyId = true);
	pki_x509 *rootCa(const QString &cn, pki_key *key = nullptr,
			bool subjectKeyId = true);
	pki_x509 *endEntity(const QString &cn, pki_x509 *ca, int days = 90);
	static x509rev reason(const QString &name);
	pki_crl *crl(pki_x509 *ca, int days = -1);
	QString openssl(const QStringList &args, int *exitCode);
	QString writePem(pki_x509 *cert);
	QString writeDer(pki_crl *crl);
	QString crlText(pki_crl *crl, pki_x509 *ca);
	static qint64 revocationRows();
	static void lastEntry(const QString &action, const QString &result,
				const QString &code = QString());

  private slots:
	void revokeUnrevokeCrl();
	void emptyCrl();
	void crlValidityFromCa();
	void rejected_data();
	void rejected();
	void expiredEntryLeavesCrl();
	void manageRevocations();
	void certBySerial();
	void crlIssuerChecks_data();
	void crlIssuerChecks();
	void sameCodeForCertificateAndCrl_data();
	void sameCodeForCertificateAndCrl();
	void passwordProtectedCaKey();
	void reasonStates();
};

pki_x509 *test_service_revocation::issue(const QString &cn, pki_key *key,
		pki_x509 *signer, const QDateTime &notBefore,
		const QDateTime &notAfter, bool subjectKeyId)
{
	IssuanceSpec spec;
	spec.name = cn;
	spec.subject.addEntryByNid(NID_organizationName, "BxC Security");
	spec.subject.addEntryByNid(NID_commonName, cn);
	spec.key = key;
	spec.signer = signer;
	spec.notBefore = a1time(notBefore);
	spec.notAfter = a1time(notAfter);
	spec.hashAlgo = digest(NID_sha256);
	spec.extensions.subjectKeyId = subjectKeyId;
	spec.extensions.authorityKeyId = true;
	if (signer) {
		spec.extensions.basicCA = ExtensionSpec::bc_not_ca;
		spec.extensions.keyUsage << "digitalSignature";
	} else {
		spec.extensions.basicCA = ExtensionSpec::bc_ca;
		spec.extensions.basicCritical = true;
		spec.extensions.keyUsage << "keyCertSign" << "cRLSign";
	}
	try {
		return certs()->newCert(ctx, spec);
	} catch (errorEx &err) {
		qWarning() << "newCert failed:" << err.getString();
		return nullptr;
	}
}

pki_x509 *test_service_revocation::rootCa(const QString &cn, pki_key *key,
				bool subjectKeyId)
{
	QDateTime now = QDateTime::currentDateTimeUtc();
	return issue(cn, key ? key : newKey(cn + " key"), nullptr,
			now.addDays(-30), now.addYears(10), subjectKeyId);
}

pki_x509 *test_service_revocation::endEntity(const QString &cn, pki_x509 *ca,
				int days)
{
	QDateTime now = QDateTime::currentDateTimeUtc();
	return issue(cn, newKey(cn + " key"), ca, now.addDays(-30),
			now.addDays(days));
}

/* An entry as another CA tool writes it: reasonCode absent (code -1),
 * explicit or any number (BTD-170) */
static x509rev revoked(const a1int &serial, int code)
{
	X509_REVOKED *r = X509_REVOKED_new();
	ASN1_INTEGER *sn = serial.get();
	X509_REVOKED_set_serialNumber(r, sn);
	ASN1_INTEGER_free(sn);
	ASN1_TIME *t = ASN1_TIME_set(nullptr, time(nullptr) - 3600);
	X509_REVOKED_set_revocationDate(r, t);
	ASN1_TIME_free(t);
	if (code >= 0) {
		ASN1_ENUMERATED *e = ASN1_ENUMERATED_new();
		ASN1_ENUMERATED_set(e, code);
		X509_REVOKED_add1_ext_i2d(r, NID_crl_reason, e, 0, 0);
		ASN1_ENUMERATED_free(e);
	}
	x509rev rev(r);
	X509_REVOKED_free(r);
	return rev;
}

/* The reasonCode of an encoded entry, -1 without the extension */
static int encodedReason(const x509rev &rev)
{
	X509_REVOKED *r = rev.get();
	int crit = -1;
	ASN1_ENUMERATED *e = static_cast<ASN1_ENUMERATED *>(
		X509_REVOKED_get_ext_d2i(r, NID_crl_reason, &crit, nullptr));
	int code = e ? (int)ASN1_ENUMERATED_get(e) : -1;
	ASN1_ENUMERATED_free(e);
	X509_REVOKED_free(r);
	return code;
}

x509rev test_service_revocation::reason(const QString &name)
{
	x509rev rev;
	rev.setReason(name);
	return rev;
}

/* A CRL with the CA's defaults, as the GUI and --crlgen create it */
pki_crl *test_service_revocation::crl(pki_x509 *ca, int days)
{
	crljob job(ca);
	if (days >= 0)
		job.nextUpdate = job.lastUpdate.addDays(days);
	try {
		return crls()->newCrl(ctx, job);
	} catch (errorEx &err) {
		qWarning() << "newCrl failed:" << err.getString();
		return nullptr;
	}
}

QString test_service_revocation::openssl(const QStringList &args,
					int *exitCode)
{
	QProcess p;
	p.setProcessChannelMode(QProcess::MergedChannels);
	p.start(OPENSSL_PROGRAM, args);
	if (!p.waitForFinished(30000))
		*exitCode = -1;
	else
		*exitCode = p.exitCode();
	return QString::fromUtf8(p.readAll());
}

QString test_service_revocation::writePem(pki_x509 *cert)
{
	QString name = dir.filePath(QString("cert-%1.pem")
				.arg(cert->getSqlItemId().toString()));
	BIO *b = BIO_new_file(QFile::encodeName(name).constData(), "w");
	PEM_write_bio_X509(b, cert->getCert());
	BIO_free(b);
	return name;
}

QString test_service_revocation::writeDer(pki_crl *crl)
{
	QString name = dir.filePath(QString("crl-%1.der")
				.arg(crl->getSqlItemId().toString()));
	QFile f(name);
	if (f.open(QIODevice::WriteOnly))
		f.write(crl->i2d());
	return name;
}

/* openssl crl -text of a DER CRL whose signature verifies with ca */
QString test_service_revocation::crlText(pki_crl *crl, pki_x509 *ca)
{
	int rc;
	QString out = openssl({ "crl", "-inform", "DER", "-in", writeDer(crl),
			"-CAfile", writePem(ca), "-text", "-noout" }, &rc);
	if (rc != 0 || !out.contains("verify OK"))
		qWarning() << out;
	return rc == 0 && out.contains("verify OK") ? out : QString();
}

qint64 test_service_revocation::revocationRows()
{
	XSqlQuery q("SELECT COUNT(*) FROM revocations");
	return q.first() ? q.value(0).toLongLong() : -1;
}

void test_service_revocation::lastEntry(const QString &action,
			const QString &result, const QString &code)
{
	AuditEntry e = AuditLog::entries().last();
	QCOMPARE(e.action, action);
	QCOMPARE(e.result, result);
	QCOMPARE(e.errorCode, code);
}

/* Acceptance criterion 1: revoke with keyCompromise, CRL lists it,
 * unrevoke, the next CRL does not; one entry per step, chain verifies */
void test_service_revocation::revokeUnrevokeCrl()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	pki_x509 *ca = rootCa("Revocation Root CA");
	pki_x509 *ee = endEntity("device-1", ca);
	pki_x509 *other = endEntity("device-2", ca);
	QVERIFY(ca && ee && other);
	QString serial = ee->getSerial().toHex();
	int entries = AuditLog::entries().size();

	certs()->revoke(ctx, ee, reason("Key Compromise"));
	QCOMPARE(AuditLog::entries().size(), ++entries);
	AuditEntry e = AuditLog::entries().last();
	QCOMPARE(e.action, QString("certificate.revoke"));
	QCOMPARE(e.result, QString("success"));
	QCOMPARE(e.objectType, QString("certificate"));
	QCOMPARE(e.objectId, ee->getSqlItemId().toString());
	QCOMPARE(e.params["serial"].toString(), serial);
	QCOMPARE(e.params["ca_id"].toLongLong(),
		ca->getSqlItemId().toLongLong());
	QCOMPARE(e.params["reason"].toString(), QString("Key Compromise"));
	QCOMPARE(e.params["reason_bit"].toLongLong(), 1);
	QVERIFY(!e.params["revocation_date"].toString().isEmpty());
	QVERIFY(ee->isRevoked());
	QVERIFY(!other->isRevoked());
	QCOMPARE(revocationRows(), 1);
	QVERIFY(AuditLog::verify().ok());

	pki_crl *first = crl(ca);
	QVERIFY(first);
	QCOMPARE(AuditLog::entries().size(), ++entries);
	e = AuditLog::entries().last();
	QCOMPARE(e.action, QString("crl.generate"));
	QCOMPARE(e.objectType, QString("crl"));
	QCOMPARE(e.objectId, first->getSqlItemId().toString());
	QCOMPARE(e.params["crl_number"].toLongLong(), 1);
	QCOMPARE(e.params["count"].toLongLong(), 1);
	QCOMPARE(e.params["der_size"].toLongLong(),
		(qint64)first->i2d().size());
	QString text = crlText(first, ca);
	QVERIFY(!text.isEmpty());
	QVERIFY2(text.contains("Serial Number: " + serial), CCHAR(text));
	QVERIFY2(text.contains("Key Compromise"), CCHAR(text));
	QVERIFY(!text.contains(other->getSerial().toHex()));
	QVERIFY(AuditLog::verify().ok());

	certs()->unrevoke(ctx, ee);
	QCOMPARE(AuditLog::entries().size(), ++entries);
	e = AuditLog::entries().last();
	QCOMPARE(e.action, QString("certificate.unrevoke"));
	QCOMPARE(e.result, QString("success"));
	QCOMPARE(e.params["serial"].toString(), serial);
	QVERIFY(!ee->isRevoked());
	QCOMPARE(revocationRows(), 0);

	pki_crl *second = crl(ca);
	QVERIFY(second);
	QCOMPARE(AuditLog::entries().size(), ++entries);
	QCOMPARE(AuditLog::entries().last().params["crl_number"].toLongLong(),
		2);
	text = crlText(second, ca);
	QVERIFY(!text.isEmpty());
	QVERIFY2(!text.contains(serial), CCHAR(text));

	AuditVerifyResult v = AuditLog::verify();
	QVERIFY2(v.ok(), v.toJson().constData());
	QCOMPARE(v.unauditedRevocations, 0);

	/* Persisted, CRL numbers keep increasing after a reopen */
	QVariant caId = ca->getSqlItemId();
	reopenDatabase();
	ca = Store.lookupPki<pki_x509>(caId);
	QVERIFY(ca);
	QCOMPARE(ca->getCrlNumber().toDec(), QString("2"));
	pki_crl *third = crl(ca);
	QVERIFY(third);
	QCOMPARE(third->getCrlNumber().toDec(), QString("3"));
	QVERIFY(AuditLog::verify().ok());
#endif
}

/* OPC UA rules: the first CRL of a CA, without revocations */
void test_service_revocation::emptyCrl()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	pki_x509 *ca = rootCa("Empty CRL CA");
	QVERIFY(ca);
	pki_crl *c = crl(ca);
	QVERIFY(c);
	QVERIFY(!crlText(c, ca).isEmpty());

	/* DER, v2, no revokedCertificates field at all: the fields of
	 * TBSCertList are version, signature, issuer, thisUpdate,
	 * nextUpdate and the extensions [0] */
	int rc;
	QString der = writeDer(c);
	QString parsed = openssl({ "asn1parse", "-inform", "DER",
				"-in", der }, &rc);
	QCOMPARE(rc, 0);
	qInfo().noquote() << "openssl asn1parse of the empty CRL:\n" + parsed;
	QStringList tbs;
	int outer = 0;
	for (const QString &line : parsed.split('\n')) {
		/* the fields of the first d=1 element, tbsCertList */
		if (line.contains(":d=1 "))
			outer++;
		if (outer != 1 || !line.contains(":d=2 "))
			continue;
		QString tag = line.section(':', 2).trimmed();
		tbs << tag.section(' ', 0, 0) + (tag.startsWith("cont") ?
				" " + tag.section(' ', 1, 3) : "");
	}
	QCOMPARE(tbs, QStringList({ "INTEGER", "SEQUENCE", "SEQUENCE",
			"UTCTIME", "UTCTIME", "cont [ 0 ]" }));
	QFile f(der);
	QVERIFY(f.open(QIODevice::ReadOnly));
	QByteArray ba = f.readAll();
	QCOMPARE(ba, c->i2d());
	const unsigned char *p = (const unsigned char *)ba.constData();
	X509_CRL *x = d2i_X509_CRL(nullptr, &p, ba.size());
	QVERIFY(x);
	QCOMPARE(X509_CRL_get_version(x), 1L);
	QVERIFY(!X509_CRL_get_REVOKED(x));

	/* AKI with the CA's key identifier and a CRL number */
	AUTHORITY_KEYID *akid = (AUTHORITY_KEYID *)X509_CRL_get_ext_d2i(x,
			NID_authority_key_identifier, nullptr, nullptr);
	QVERIFY(akid && akid->keyid);
	QCOMPARE(ASN1_OCTET_STRING_cmp(akid->keyid,
			X509_get0_subject_key_id(ca->getCert())), 0);
	AUTHORITY_KEYID_free(akid);
	ASN1_INTEGER *num = (ASN1_INTEGER *)X509_CRL_get_ext_d2i(x,
			NID_crl_number, nullptr, nullptr);
	QVERIFY(num);
	int64_t crlNumber = 0;
	QVERIFY(ASN1_INTEGER_get_int64(&crlNumber, num));
	QCOMPARE(crlNumber, (int64_t)1);
	ASN1_INTEGER_free(num);

	/* complete CRL only, never SHA-1 */
	QVERIFY(X509_CRL_get_ext_by_NID(x, NID_delta_crl, -1) < 0);
	QVERIFY(X509_CRL_get_ext_by_NID(x, NID_issuing_distribution_point, -1) < 0);
	QVERIFY(X509_CRL_get_ext_by_NID(x, NID_freshest_crl, -1) < 0);
	QCOMPARE(X509_CRL_get_signature_nid(x), NID_ecdsa_with_SHA256);
	X509_CRL_free(x);

	/* the DER size is reported */
	QCOMPARE(AuditLog::entries().last().params["der_size"].toLongLong(),
		(qint64)ba.size());

	/* A CA without subject key identifier (the dialog's default):
	 * the key identifier is the SHA-1 hash of its public key */
	pki_x509 *noSki = rootCa("No SKI CA", nullptr, false);
	QVERIFY(noSki);
	QVERIFY(!X509_get0_subject_key_id(noSki->getCert()));
	c = crl(noSki);
	QVERIFY(c);
	QVERIFY(!crlText(c, noSki).isEmpty());
	ba = c->i2d();
	p = (const unsigned char *)ba.constData();
	x = d2i_X509_CRL(nullptr, &p, ba.size());
	QVERIFY(x);
	akid = (AUTHORITY_KEYID *)X509_CRL_get_ext_d2i(x,
			NID_authority_key_identifier, nullptr, nullptr);
	QVERIFY(akid && akid->keyid && akid->issuer && akid->serial);
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned len = 0;
	QVERIFY(X509_pubkey_digest(noSki->getCert(), EVP_sha1(), md, &len));
	QCOMPARE(QByteArray((const char *)ASN1_STRING_get0_data(akid->keyid),
			ASN1_STRING_get_length(akid->keyid)),
		QByteArray((const char *)md, len));
	AUTHORITY_KEYID_free(akid);
	X509_CRL_free(x);
#endif
}

/* nextUpdate comes from the CRL days of the CA, default P7D */
void test_service_revocation::crlValidityFromCa()
{
	pki_x509 *ca = rootCa("Validity CA");
	QVERIFY(ca);
	QCOMPARE(ca->getCrlDays(), 7);
	pki_crl *c = crl(ca);
	QVERIFY(c);
	QCOMPARE(c->getLastUpdate().secsTo(c->getNextUpdate()),
		7LL * SECS_PER_DAY);
	QCOMPARE(AuditLog::entries().last().params["next_update"].toString(),
		AuditLog::rfc3339(c->getNextUpdate()));

	/* Another CA with 3 days configured */
	pki_x509 *other = rootCa("Short CRL CA");
	QVERIFY(other);
	other->setCrlDays(3);
	certs()->updateCaProperties(other);
	QVariant otherId = other->getSqlItemId(), caId = ca->getSqlItemId();
	reopenDatabase();
	other = Store.lookupPki<pki_x509>(otherId);
	ca = Store.lookupPki<pki_x509>(caId);
	QVERIFY(other && ca);
	QCOMPARE(other->getCrlDays(), 3);
	QCOMPARE(ca->getCrlDays(), 7);
	c = crl(other);
	QVERIFY(c);
	QCOMPARE(c->getLastUpdate().secsTo(c->getNextUpdate()),
		3LL * SECS_PER_DAY);
}

void test_service_revocation::rejected_data()
{
	QTest::addColumn<QString>("variant");
	QTest::addColumn<QString>("action");
	QTest::addColumn<QString>("code");

	QTest::newRow("revoke twice") << "twice"
		<< "certificate.revoke" << "already_revoked";
	QTest::newRow("revoke a root") << "root"
		<< "certificate.revoke" << "self_signed";
	QTest::newRow("unknown reason") << "reason"
		<< "certificate.revoke" << "invalid_reason";
	QTest::newRow("no certificate") << "nocert"
		<< "certificate.revoke" << "missing_certificate";
	QTest::newRow("unrevoke a valid certificate") << "notrevoked"
		<< "certificate.unrevoke" << "not_revoked";
	QTest::newRow("CRL with SHA-1") << "sha1"
		<< "crl.generate" << "signature_hash_not_allowed";
	QTest::newRow("CRL number not increasing") << "crlnumber"
		<< "crl.generate" << "crl_number_not_increasing";
	QTest::newRow("CRL of an end entity") << "notca"
		<< "crl.generate" << "issuer_not_ca";
	QTest::newRow("CRL without CA key") << "nokey"
		<< "crl.generate" << "no_private_signing_key";
	QTest::newRow("revocation list with a serial twice") << "duplicate"
		<< "ca.set_revocations" << "duplicate_serial";
}

void test_service_revocation::rejected()
{
	QFETCH(QString, variant);
	QFETCH(QString, action);
	QFETCH(QString, code);

	pki_key *caKey = newKey("ca key");
	pki_x509 *ca = rootCa("Reject CA", caKey);
	pki_x509 *ee = endEntity("device", ca);
	QVERIFY(ca && ee);
	certs()->revoke(ctx, endEntity("revoked", ca), reason("Superseded"));
	QVERIFY(crl(ca));

	if (variant == "twice")
		certs()->revoke(ctx, ee, reason("Key Compromise"));
	if (variant == "nokey") {
		db_key *keys = Database.model<db_key>();
		keys->deleteItems(ctx, { caKey });
		QVERIFY(!ca->getRefKey());
	}
	qint64 rows = revocationRows();
	int crlCount = Store.getAll<pki_crl>().size();
	int entries = AuditLog::entries().size();
	crljob job(variant == "notca" ? ee : ca);

	try {
		if (variant == "twice")
			certs()->revoke(ctx, ee, reason("Superseded"));
		else if (variant == "root")
			certs()->revoke(ctx, ca, reason("Superseded"));
		else if (variant == "reason")
			certs()->revoke(ctx, ee, reason("no such reason"));
		else if (variant == "nocert")
			certs()->revoke(ctx, nullptr, reason("Superseded"));
		else if (variant == "notrevoked")
			certs()->unrevoke(ctx, ee);
		else if (variant == "duplicate") {
			x509revList list;
			x509rev rev = reason("Superseded");
			rev.setSerial(a1int("0A0B0C"));
			list << rev << rev;
			certs()->setRevocations(ctx, ca, list);
		} else {
			if (variant == "sha1")
				job.hashAlgo = digest(NID_sha1);
			if (variant == "crlnumber")
				job.crlNumber = ca->getCrlNumber();
			crls()->newCrl(ctx, job);
		}
		QFAIL("the request was accepted");
	} catch (serviceError &err) {
		QCOMPARE(err.code, code);
	}
	QCOMPARE(AuditLog::entries().size(), entries + 1);
	lastEntry(action, "failure", code);
	QCOMPARE(revocationRows(), rows);
	QCOMPARE(Store.getAll<pki_crl>().size(), crlCount);
	QCOMPARE(ca->getCrlNumber().toDec(), QString("1"));
	AuditVerifyResult v = AuditLog::verify();
	QVERIFY2(v.ok(), v.toJson().constData());
}

/* BTD-188: the issuer of a CRL passes the checks of IssuanceChecks
 * before anything is written: cRLSign when it has key usage (none: a
 * warning, BTD-55), valid now, its own key; no CRL row, no new CRL
 * number, one failure entry */
void test_service_revocation::crlIssuerChecks_data()
{
	QTest::addColumn<QString>("ku");          // "-": no key usage
	QTest::addColumn<int>("fromDays");
	QTest::addColumn<int>("toDays");
	QTest::addColumn<QString>("code");
	QTest::newRow("keyCertSign only") << "keyCertSign" << -30 << 3650
		<< "issuer_no_crlsign";
	QTest::newRow("expired") << "keyCertSign,cRLSign" << -30 << -1
		<< "issuer_expired";
	QTest::newRow("not yet valid") << "keyCertSign,cRLSign" << 2 << 3650
		<< "issuer_not_yet_valid";
	QTest::newRow("no key usage") << "-" << -30 << 3650 << "";
	QTest::newRow("cRLSign") << "keyCertSign,cRLSign" << -30 << 3650 << "";
}

void test_service_revocation::crlIssuerChecks()
{
	QFETCH(QString, ku);
	QFETCH(int, fromDays);
	QFETCH(int, toDays);
	QFETCH(QString, code);
	QDateTime now = QDateTime::currentDateTimeUtc();
	IssuanceSpec spec;
	spec.name = "CRL issuer";
	spec.subject.addEntryByNid(NID_commonName, spec.name);
	spec.key = newKey("CRL issuer key");
	spec.notBefore = a1time(now.addDays(fromDays));
	spec.notAfter = a1time(now.addDays(toDays));
	spec.hashAlgo = digest(NID_sha256);
	spec.extensions.basicCA = ExtensionSpec::bc_ca;
	spec.extensions.basicCritical = true;
	spec.extensions.subjectKeyId = true;
	if (ku != "-")
		spec.extensions.keyUsage = ku.split(",");
	pki_x509 *ca = certs()->newCert(ctx, spec);
	QVERIFY(ca);

	int crlCount = Store.getAll<pki_crl>().size();
	QString number = ca->getCrlNumber().toDec();
	int entries = AuditLog::entries().size();
	QString got;
	try {
		crls()->newCrl(ctx, crljob(ca));
	} catch (serviceError &err) {
		got = err.code;
	}
	QCOMPARE(got, code);
	QCOMPARE(AuditLog::entries().size(), entries + 1);
	if (!code.isEmpty()) {
		lastEntry("crl.generate", "failure", code);
		QCOMPARE(Store.getAll<pki_crl>().size(), crlCount);
		QCOMPARE(ca->getCrlNumber().toDec(), number);
		return;
	}
	QCOMPARE(Store.getAll<pki_crl>().size(), crlCount + 1);
	QCOMPARE(AuditLog::entries().last().params.value("warning").toString()
		.contains("issuer_without_key_usage"), ku == "-");
}

/* One rule, one code: the same issuer problem refuses a certificate and
 * a CRL with the same code */
void test_service_revocation::sameCodeForCertificateAndCrl_data()
{
	QTest::addColumn<QString>("rule");
	QTest::addColumn<QString>("code");
	QTest::newRow("insecure hash") << "sha1" << "signature_hash_not_allowed";
	QTest::newRow("issuer is no CA") << "notca" << "issuer_not_ca";
	QTest::newRow("expired issuer") << "expired" << "issuer_expired";
}

void test_service_revocation::sameCodeForCertificateAndCrl()
{
	QFETCH(QString, rule);
	QFETCH(QString, code);
	QDateTime now = QDateTime::currentDateTimeUtc();
	pki_x509 *ca = rule == "expired" ?
		issue("Old CA", newKey("old key"), nullptr, now.addDays(-30),
			now.addDays(-1)) :
		rootCa("Rule CA");
	QVERIFY(ca);
	pki_x509 *issuer = rule == "notca" ? endEntity("not a CA", ca) : ca;
	QVERIFY(issuer);

	IssuanceSpec spec;
	spec.name = "leaf";
	spec.subject.addEntryByNid(NID_commonName, "leaf");
	spec.key = newKey("leaf key");
	spec.signer = issuer;
	spec.notBefore = a1time(now.addDays(-40));
	spec.notAfter = a1time(now.addDays(30));
	spec.hashAlgo = digest(rule == "sha1" ? NID_sha1 : NID_sha256);
	spec.extensions.basicCA = ExtensionSpec::bc_not_ca;
	QString certCode, crlCode;
	try {
		certs()->newCert(ctx, spec);
	} catch (serviceError &err) {
		certCode = err.code;
	}
	crljob job(issuer);
	if (rule == "sha1")
		job.hashAlgo = digest(NID_sha1);
	try {
		crls()->newCrl(ctx, job);
	} catch (serviceError &err) {
		crlCode = err.code;
	}
	QCOMPARE(certCode, code);
	QCOMPARE(crlCode, code);
}

/* RFC 5280 3.3: listed once after notAfter, then dropped */
void test_service_revocation::expiredEntryLeavesCrl()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	pki_x509 *ca = rootCa("Expiry CA");
	pki_x509 *expired = endEntity("expired", ca, -1);
	pki_x509 *valid = endEntity("valid", ca);
	QVERIFY(ca && expired && valid);
	certs()->revoke(ctx, expired, reason("Superseded"));
	certs()->revoke(ctx, valid, reason("Key Compromise"));
	QString gone = "Serial Number: " + expired->getSerial().toHex();
	QString stays = "Serial Number: " + valid->getSerial().toHex();

	/* issued before the certificate expired: lists both */
	crljob job(ca);
	job.lastUpdate = a1time(QDateTime::currentDateTimeUtc().addDays(-2));
	job.nextUpdate = job.lastUpdate.addDays(7);
	pki_crl *before = crls()->newCrl(ctx, job);
	QString text = crlText(before, ca);
	QVERIFY2(text.contains(gone) && text.contains(stays), CCHAR(text));

	/* the first CRL after notAfter still lists it */
	text = crlText(crl(ca), ca);
	QVERIFY2(text.contains(gone) && text.contains(stays), CCHAR(text));

	/* the next one does not; the revocation itself stays */
	pki_crl *after = crl(ca);
	text = crlText(after, ca);
	QVERIFY2(!text.contains(gone) && text.contains(stays), CCHAR(text));
	QCOMPARE(after->numRev(), 1);
	QCOMPARE(AuditLog::entries().last().params["count"].toLongLong(), 1);
	QVERIFY(expired->isRevoked());
	QCOMPARE(revocationRows(), 2);
	QVERIFY(AuditLog::verify().ok());
#endif
}

/* The Manage revocations dialog: serials without certificate, edit and
 * removal, each change audited so that verify finds no unaudited row */
void test_service_revocation::manageRevocations()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	pki_x509 *ca = rootCa("Manage CA");
	pki_x509 *ee = endEntity("device", ca);
	QVERIFY(ca && ee);
	int entries = AuditLog::entries().size();

	x509revList list;
	x509rev manual = reason("Superseded");
	manual.setSerial(a1int("0123456789ABCDEF"));
	manual.setDate(a1time());
	x509rev byCert = reason("Key Compromise");
	byCert.setSerial(ee->getSerial());
	byCert.setDate(a1time());
	list << manual << byCert;
	certs()->setRevocations(ctx, ca, list);
	QCOMPARE(AuditLog::entries().size(), entries + 2);
	QVERIFY(ee->isRevoked());
	QCOMPARE(revocationRows(), 2);

	pki_crl *c = crl(ca);
	QString text = crlText(c, ca);
	QVERIFY2(text.contains("Serial Number: 0123456789ABCDEF"), CCHAR(text));
	QVERIFY2(text.contains("Superseded"), CCHAR(text));
	entries = AuditLog::entries().size();

	/* Edit an entry that is in a CRL: reason changes, date and CRL
	 * number stay; the unchanged entry writes nothing */
	list = ca->getRevList();
	int i = list.indexOf(byCert);
	QVERIFY(i != -1);
	a1time published = list[i].getDate();
	x509rev edited = reason("Affiliation Changed");
	edited.setSerial(ee->getSerial());
	edited.setDate(a1time(published.addSecs(3600)));
	list[i] = edited;
	certs()->setRevocations(ctx, ca, list);
	QCOMPARE(AuditLog::entries().size(), entries + 1);
	AuditEntry e = AuditLog::entries().last();
	QCOMPARE(e.action, QString("certificate.revoke"));
	QCOMPARE(e.objectId, ee->getSqlItemId().toString());
	QCOMPARE(e.params["reason_bit"].toLongLong(), 3);
	QCOMPARE(e.params["crl_number"].toLongLong(), 1);
	x509revList now = ca->getRevList();
	x509rev stored = now[now.indexOf(byCert)];
	QCOMPARE(stored.getReason(), QString("Affiliation Changed"));
	QCOMPARE(stored.getDate(), published);
	QCOMPARE(stored.getCrlNo(), 1);
	QCOMPARE(ee->getRevocation().getReason(),
		QString("Affiliation Changed"));

	/* Remove the manual entry */
	list.removeAll(manual);
	certs()->setRevocations(ctx, ca, list);
	QCOMPARE(AuditLog::entries().size(), entries + 2);
	e = AuditLog::entries().last();
	QCOMPARE(e.action, QString("certificate.unrevoke"));
	QCOMPARE(e.params["serial"].toString(), QString("0123456789ABCDEF"));
	QCOMPARE(revocationRows(), 1);

	text = crlText(crl(ca), ca);
	QVERIFY2(!text.contains("0123456789ABCDEF"), CCHAR(text));
	QVERIFY2(text.contains("Affiliation Changed"), CCHAR(text));

	AuditVerifyResult v = AuditLog::verify();
	QVERIFY2(v.ok(), v.toJson().constData());
	QCOMPARE(v.unauditedRevocations, 0);
#endif
}

/* certstrap rule 8: hex and decimal notation, unknown serials */
void test_service_revocation::certBySerial()
{
	pki_x509 *ca = rootCa("Serial CA");
	pki_x509 *ee = endEntity("device", ca);
	QVERIFY(ca && ee);
	QString hex = ee->getSerial().toHex();
	QString colons;
	for (int i = 0; i < hex.size(); i += 2)
		colons += (i ? ":" : "") + hex.mid(i, 2).toLower();

	QCOMPARE(certs()->certBySerial(ca, hex), ee);
	QCOMPARE(certs()->certBySerial(ca, "0x" + hex.toLower()), ee);
	QCOMPARE(certs()->certBySerial(ca, colons), ee);
	QCOMPARE(certs()->certBySerial(ca, " dec:" + ee->getSerial().toDec()),
		ee);

	/* Two certificates whose serials read the same digits as hex and
	 * as decimal: digits only are hex, as XCA shows serials; decimal
	 * needs "dec:" (review of xca#62: the unintended reading was
	 * taken silently when only it existed) */
	pki_x509 *a = new pki_x509(ee), *b = new pki_x509(ee);
	pki_key *caKey = ca->getRefKey();
	a->setSerial(a1int().setHex("1234"));
	b->setSerial(a1int().setDec("1234"));
	for (pki_x509 *c : { a, b }) {
		c->setIntName(c->getSerial().toHex());
		c->sign(caKey, digest(NID_sha256));
		QVERIFY(certs()->insert(c));
	}
	QCOMPARE(certs()->certBySerial(ca, "0x1234"), a);
	QCOMPARE(certs()->certBySerial(ca, "1234"), a);
	QCOMPARE(certs()->certBySerial(ca, "04D2"), b);
	QCOMPARE(certs()->certBySerial(ca, "dec:1234"), b);
	QCOMPARE(certs()->certBySerial(ca, "DEC:1234"), b);

	/* only the decimal reading exists: digits only do not find it */
	pki_x509 *d = new pki_x509(ee);
	d->setSerial(a1int().setDec("5678"));
	d->setIntName("dec-only");
	d->sign(caKey, digest(NID_sha256));
	QVERIFY(certs()->insert(d));
	QCOMPARE(certs()->certBySerial(ca, "dec:5678"), d);

	const QList<QPair<QString, QString> > bad {
		{ "5678", "unknown_serial" },
		{ "dec:12AB", "invalid_serial" },
		{ "dec:", "invalid_serial" },
		{ "dec:0x10", "invalid_serial" },
		{ "0x" + hex + "00", "unknown_serial" },
		{ "4711", "unknown_serial" },
		{ "12G4", "invalid_serial" },
		{ "", "invalid_serial" },
		{ "-1", "invalid_serial" },
	};
	for (const auto &t : bad) {
		try {
			certs()->certBySerial(ca, t.first);
			QFAIL(CCHAR("accepted " + t.first));
		} catch (serviceError &err) {
			QCOMPARE(err.code, t.second);
		}
	}
}

/* certstrap rule 8: revoke and CRL with a password-protected CA key; the
 * key password comes from the headless source as in the CLI */
void test_service_revocation::passwordProtectedCaKey()
{
#ifndef OPENSSL_PROGRAM
	QSKIP("openssl program not found");
#else
	PwDialogHeadless *h = new PwDialogHeadless();
	pwdialog->delegateTo(h);
	h->setSource(pass_info::KeyPassword, "pass:ca-key-secret");
	pki_evp *key = dynamic_cast<pki_evp *>(newKey("protected key"));
	QVERIFY(key);
	key->setOwnPass(pki_key::ptPrivate);
	QCOMPARE(key->getOwnPass(), pki_key::ptPrivate);

	pki_x509 *ca = rootCa("Protected CA", key);
	pki_x509 *ee = endEntity("device", ca);
	QVERIFY(ca && ee);
	certs()->revoke(ctx, ee, reason("Key Compromise"));
	pki_crl *c = crl(ca);
	QVERIFY(c);
	QVERIFY(crlText(c, ca).contains(ee->getSerial().toHex()));

	/* without the key password nothing is generated */
	h->clearSources();
	int crlCount = Store.getAll<pki_crl>().size();
	try {
		crls()->newCrl(ctx, crljob(ca));
		QFAIL("newCrl without key password");
	} catch (secretError &) {
	}
	QCOMPARE(Store.getAll<pki_crl>().size(), crlCount);
	lastEntry("crl.generate", "failure", "internal_error");
	QCOMPARE(ca->getCrlNumber().toDec(), QString("1"));
	QVERIFY(AuditLog::verify().ok());
#endif
}

/* BTD-170: "no reasonCode", an explicit unspecified and an unknown code
 * are three states. No reason is reported as none (JSON null), an explicit
 * 0 read from a CRL as unspecified, an unknown code as its number; XCA's
 * own "Unspecified" writes no extension (RFC 5280 5.3.1). An explicit 0
 * becomes "no reason" when it is a revocation of the CA; an unknown code
 * is kept and written again. */
void test_service_revocation::reasonStates()
{
	/* read from an entry */
	a1int sn("0A0B0C");
	QCOMPARE(revoked(sn, -1).getReason(), QString());
	QCOMPARE(encodedReason(revoked(sn, -1)), -1);
	QCOMPARE(revoked(sn, 0).getReason(), QString("Unspecified"));
	QCOMPARE(encodedReason(revoked(sn, 0)), 0);
	QCOMPARE(revoked(sn, 7).getReasonBit(), 7);
	QCOMPARE(revoked(sn, 7).getReason(), QString("7"));
	QCOMPARE(encodedReason(revoked(sn, 7)), 7);
	QCOMPARE(revoked(sn, 1).getReason(), QString("Key Compromise"));
	QCOMPARE(encodedReason(revoked(sn, 1)), 1);

	/* XCA's own revocation with "Unspecified": no reason anywhere */
	pki_x509 *ca = rootCa("Reason CA");
	pki_x509 *plain = endEntity("no reason", ca);
	pki_x509 *zero = endEntity("explicit zero", ca);
	pki_x509 *seven = endEntity("code seven", ca);
	QVERIFY(ca && plain && zero && seven);
	certs()->revoke(ctx, plain, reason("Unspecified"));
	QJsonObject doc = JsonReport::certificate(plain);
	QVERIFY2(doc["revocation"].toObject()["reason"].isNull(),
		JsonReport::line(doc).constData());

	/* imported: explicit 0 becomes "no reason", 7 is kept */
	x509revList list = ca->getRevList();
	list << revoked(zero->getSerial(), 0) << revoked(seven->getSerial(), 7);
	certs()->setRevocations(ctx, ca, list);
	QVERIFY(JsonReport::certificate(zero)["revocation"].toObject()
		["reason"].isNull());
	QCOMPARE(JsonReport::certificate(seven)["revocation"].toObject()
		["reason"].toInt(), 7);

	pki_crl *c = crl(ca);
	QVERIFY(c);
	QByteArray der = c->i2d();
	const unsigned char *p = (const unsigned char *)der.constData();
	X509_CRL *x = d2i_X509_CRL(nullptr, &p, der.size());
	QVERIFY(x);
	QMap<QString, int> codes;
	STACK_OF(X509_REVOKED) *st = X509_CRL_get_REVOKED(x);
	for (int i = 0; i < sk_X509_REVOKED_num(st); i++) {
		X509_REVOKED *r = sk_X509_REVOKED_value(st, i);
		x509rev rev(r);
		codes[rev.getSerial().toHex()] = encodedReason(rev);
	}
	X509_CRL_free(x);
	QCOMPARE(codes.value(plain->getSerial().toHex(), -2), -1);
	QCOMPARE(codes.value(zero->getSerial().toHex(), -2), -1);
	QCOMPARE(codes.value(seven->getSerial().toHex(), -2), 7);
	AuditVerifyResult v = AuditLog::verify();
	QVERIFY2(v.ok(), v.toJson().constData());
}

XCA_SERVICE_TEST_MAIN(test_service_revocation)
#include "test_service_revocation.moc"
