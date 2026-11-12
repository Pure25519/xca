/* vi: set sw=4 ts=4:
 *
 * The key types of a profile (BTD-237): key_types holds only the key
 * types of the bootstrap vocabulary (lib/key_types.cpp), each with the
 * key usage of its family (rsa, ec, eddsa, ml-dsa, slh-dsa), and a
 * profile issues for every family and signs with a digest-less issuer.
 */

#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include <openssl/x509v3.h>

#include "lib/audit.h"
#include "lib/db_key.h"
#include "lib/db_x509.h"
#include "lib/exception.h"
#include "lib/pki_x509.h"
#include "lib/profile.h"

#include "ServiceTestCase.h"

class test_service_profile_key_types : public ServiceTestCase
{
	Q_OBJECT

	ServiceContext ctx{ ServiceContext::cli, "os:service-test" };

	static QJsonObject leafProfile(const QJsonArray &types);
	pki_x509 *issuingCa(const QString &keyJob);

  private slots:
	void unknownKeyType_data();
	void unknownKeyType();
	void everyKeyTypeLoads();
	void familyNeedsKeyUsage_data();
	void familyNeedsKeyUsage();
	void signatureOnlyBits_data();
	void signatureOnlyBits();
	void issuesEveryFamily_data();
	void issuesEveryFamily();
};

/* The 26 key types of the bootstrap vocabulary */
static const QStringList allTypes {
	"rsa-2048", "rsa-3072", "rsa-4096",
	"ec-p256", "ec-p384", "ec-p521",
	"ec-brainpoolp256r1", "ec-brainpoolp384r1", "ec-brainpoolp512r1",
	"ed25519", "ed448",
	"ml-dsa-44", "ml-dsa-65", "ml-dsa-87",
	"slh-dsa-sha2-128s", "slh-dsa-sha2-128f",
	"slh-dsa-sha2-192s", "slh-dsa-sha2-192f",
	"slh-dsa-sha2-256s", "slh-dsa-sha2-256f",
	"slh-dsa-shake-128s", "slh-dsa-shake-128f",
	"slh-dsa-shake-192s", "slh-dsa-shake-192f",
	"slh-dsa-shake-256s", "slh-dsa-shake-256f",
};

/* The generic TLS client profile with a server-side key, the given key
 * types and digitalSignature for every key family */
QJsonObject test_service_profile_key_types::leafProfile(const QJsonArray &types)
{
	QFile f(SERVICE_TEST_DATA "/profiles/generic/xca-tls-client.json");
	if (!f.open(QIODevice::ReadOnly))
		return QJsonObject();
	QJsonObject doc = QJsonDocument::fromJson(f.readAll()).object();
	doc["key_source"] = "server";
	doc["key_types"] = types;
	QJsonObject ds { { "bits", QJsonArray{ "digitalSignature" } },
			 { "critical", false } };
	doc["ku_by_key_type"] = QJsonObject{ { "rsa", ds }, { "ec", ds },
		{ "eddsa", ds }, { "ml-dsa", ds }, { "slh-dsa", ds } };
	return doc;
}

pki_x509 *test_service_profile_key_types::issuingCa(const QString &keyJob)
{
	IssuanceSpec s;
	s.name = "Issuing CA " + keyJob;
	x509name n;
	n.addEntryByNid(NID_commonName, s.name);
	s.subject = n;
	s.key = Database.model<db_key>()->newKey(keyjob(keyJob), s.name);
	s.notBefore = a1time();
	s.notAfter = a1time(QDateTime::currentDateTimeUtc().addDays(1000));
	s.hashAlgo = digest(NID_sha256);
	s.extensions.basicCA = ExtensionSpec::bc_ca;
	s.extensions.basicCritical = true;
	s.extensions.subjectKeyId = true;
	s.extensions.keyUsage << "keyCertSign" << "cRLSign";
	s.extensions.keyUsageCritical = true;
	return Database.model<db_x509>()->newCert(ctx, s);
}

/* An unknown value is refused with the JSON pointer of the value */
void test_service_profile_key_types::unknownKeyType_data()
{
	QTest::addColumn<QJsonArray>("types");
	QTest::addColumn<QString>("pointer");
	QTest::newRow("rsa-1024") << QJsonArray{ "rsa-1024", "ec-p256" }
		<< "/key_types/0";
	QTest::newRow("ml-dsa-99") << QJsonArray{ "rsa-2048", "ec-p256",
		"ml-dsa-99" } << "/key_types/2";
	QTest::newRow("upper case") << QJsonArray{ "ML-DSA-65" }
		<< "/key_types/0";
	QTest::newRow("no string") << QJsonArray{ "ec-p256", 256 }
		<< "/key_types/1";
}

void test_service_profile_key_types::unknownKeyType()
{
	QFETCH(QJsonArray, types);
	QFETCH(QString, pointer);
	try {
		Profile::fromJson(leafProfile(types));
		QFAIL("accepted");
	} catch (serviceError &err) {
		QCOMPARE(err.code, QString("invalid_profile"));
		QVERIFY2(err.getString().contains(pointer),
			CCHAR(err.getString()));
	}
}

void test_service_profile_key_types::everyKeyTypeLoads()
{
	QCOMPARE(Profile::fromJson(leafProfile(
		QJsonArray::fromStringList(allTypes))).id,
		QString("xca-tls-client"));
}

/* A family in key_types needs its key usage, as the schema requires */
void test_service_profile_key_types::familyNeedsKeyUsage_data()
{
	QTest::addColumn<QString>("type");
	QTest::addColumn<QString>("family");
	QTest::newRow("ed448") << "ed448" << "eddsa";
	QTest::newRow("ml-dsa-65") << "ml-dsa-65" << "ml-dsa";
	QTest::newRow("slh-dsa-shake-256f") << "slh-dsa-shake-256f" << "slh-dsa";
	QTest::newRow("ec-brainpoolp384r1") << "ec-brainpoolp384r1" << "ec";
}

void test_service_profile_key_types::familyNeedsKeyUsage()
{
	QFETCH(QString, type);
	QFETCH(QString, family);
	QJsonObject doc = leafProfile(QJsonArray{ "rsa-2048", type });
	QJsonObject ku = doc["ku_by_key_type"].toObject();
	ku.remove(family);
	doc["ku_by_key_type"] = ku;
	try {
		Profile::fromJson(doc);
		QFAIL("accepted");
	} catch (serviceError &err) {
		QCOMPARE(err.code, QString("invalid_profile"));
		QVERIFY2(err.getString().contains("ku_by_key_type"),
			CCHAR(err.getString()));
	}
}

/* EdDSA, ML-DSA and SLH-DSA keys only sign: no encryption or key
 * agreement bit, also in the family generic */
void test_service_profile_key_types::signatureOnlyBits_data()
{
	QTest::addColumn<QString>("family");
	QTest::addColumn<QString>("bit");
	for (QString f : { "eddsa", "ml-dsa", "slh-dsa" })
		for (QString b : { "keyEncipherment", "dataEncipherment",
				   "keyAgreement" })
			QTest::newRow(CCHAR(f + " " + b)) << f << b;
}

void test_service_profile_key_types::signatureOnlyBits()
{
	QFETCH(QString, family);
	QFETCH(QString, bit);
	QJsonObject doc = leafProfile(QJsonArray{ "ed25519", "ml-dsa-44",
		"slh-dsa-sha2-128f" });
	QJsonObject ku = doc["ku_by_key_type"].toObject();
	ku[family] = QJsonObject{ { "bits", QJsonArray{ "digitalSignature", bit } },
				  { "critical", false } };
	doc["ku_by_key_type"] = ku;
	try {
		Profile::fromJson(doc);
		QFAIL("accepted");
	} catch (serviceError &err) {
		QCOMPARE(err.code, QString("invalid_profile"));
		QVERIFY2(err.getString().contains("ku_by_key_type"),
			CCHAR(err.getString()));
	}
}

/* A profile issues for keys of every family, signed by digest-less CAs
 * too: their signature needs no hash of the profile (BTD-164) */
void test_service_profile_key_types::issuesEveryFamily_data()
{
	QTest::addColumn<QString>("caJob");
	QTest::addColumn<QString>("leafJob");
	QTest::addColumn<QString>("type");
	QTest::newRow("ML-DSA-65 CA, ML-DSA-65 key")
		<< "ML-DSA-65" << "ML-DSA-65" << "ml-dsa-65";
	QTest::newRow("Ed25519 CA, SLH-DSA key")
		<< "ED25519" << "SLH-DSA-SHA2-128f" << "slh-dsa-sha2-128f";
	QTest::newRow("ML-DSA-87 CA, RSA key")
		<< "ML-DSA-87" << "RSA:2048" << "rsa-2048";
	QTest::newRow("P-256 CA, Brainpool key")
		<< "EC:prime256v1" << "EC:brainpoolP256r1" << "ec-brainpoolp256r1";
	QTest::newRow("P-256 CA, Ed448 key")
		<< "EC:prime256v1" << "ED448" << "ed448";
}

void test_service_profile_key_types::issuesEveryFamily()
{
	QFETCH(QString, caJob);
	QFETCH(QString, leafJob);
	QFETCH(QString, type);
	Profile p = Profile::fromJson(leafProfile(QJsonArray{ type }));
	pki_x509 *ca = issuingCa(caJob);
	pki_key *key = Database.model<db_key>()->newKey(keyjob(leafJob),
			"device key " + leafJob);
	QVERIFY(ca && key);
	QCOMPARE(Profile::keyType(key->getPubKey()), type);
	Registration reg;
	x509name n;
	n.addEntryByNid(NID_commonName, "device.example");
	reg.subject = n;
	pki_x509 *cert = nullptr;
	try {
		cert = Database.model<db_x509>()->newCert(ctx,
				p.apply(nullptr, key, reg, ca));
	} catch (errorEx &err) {
		QFAIL(CCHAR(err.getString()));
	}
	QVERIFY(cert);
	QCOMPARE(X509_get_key_usage(cert->getCert()),
		(uint32_t)KU_DIGITAL_SIGNATURE);
}

XCA_SERVICE_TEST_MAIN(test_service_profile_key_types)
#include "test_service_profile_key_types.moc"
