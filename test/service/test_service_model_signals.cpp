/* vi: set sw=4 ts=4:
 *
 * The model signals of the certificate list when a certificate is stored
 * (BTD-231): QAbstractItemModelTester checks every rowsInserted,
 * rowsMoved, dataChanged and layoutChanged of db_x509 against the model
 * as it is at that moment, in the tree and in the flat view. Stored are
 * a leaf under its CA, a newer CA certificate with the same name and key
 * (it takes over the children of the older one) and a leaf found under
 * the root before its CA; after each store the date timer runs, which
 * emits dataChanged for every item younger than two minutes. An index
 * outside the model makes the views read beyond their mapping and the
 * GUI stop answering (BTD-227).
 */

#include <QAbstractItemModelTester>

#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/db_key.h"
#include "lib/db_x509.h"
#include "lib/exception.h"
#include "lib/issuance.h"
#include "lib/pki_x509.h"

#include "ServiceTestCase.h"

class test_service_model_signals : public ServiceTestCase
{
	Q_OBJECT

	ServiceContext ctx{ ServiceContext::cli, "os:service-test" };

	static db_x509 *certs()
	{
		return Database.model<db_x509>();
	}
	pki_x509 *issue(const QString &cn, pki_key *key, pki_x509 *signer,
			int days);
	void storeAndTick(bool tree);

  private slots:
	void insertPath_data();
	void insertPath();
};

pki_x509 *test_service_model_signals::issue(const QString &cn, pki_key *key,
		pki_x509 *signer, int days)
{
	IssuanceSpec spec;
	spec.name = cn;
	spec.subject.addEntryByNid(NID_commonName, cn);
	spec.key = key;
	spec.signer = signer;
	spec.notBefore = a1time(QDateTime::currentDateTimeUtc().addDays(-1));
	spec.notAfter = a1time(QDateTime::currentDateTimeUtc().addDays(days));
	spec.hashAlgo = digest(NID_sha256);
	spec.extensions.basicCA = signer ? ExtensionSpec::bc_not_ca :
					   ExtensionSpec::bc_ca;
	spec.extensions.subjectKeyId = true;
	spec.extensions.authorityKeyId = true;
	if (signer)
		spec.extensions.keyUsage << "digitalSignature";
	else
		spec.extensions.keyUsage << "keyCertSign" << "cRLSign";
	try {
		return certs()->newCert(ctx, spec);
	} catch (errorEx &err) {
		qWarning() << "newCert failed:" << err.getString();
		return nullptr;
	}
}

void test_service_model_signals::insertPath_data()
{
	QTest::addColumn<bool>("tree");
	QTest::newRow("tree view") << true;
	QTest::newRow("flat view") << false;
}

/* AC 1: every signal of the insert path names existing rows and cells
 * with the right parent */
void test_service_model_signals::insertPath()
{
	QFETCH(bool, tree);
	db_x509 *model = certs();
	if (model->treeViewMode() != tree)
		model->changeView();
	QAbstractItemModelTester tester(model,
		QAbstractItemModelTester::FailureReportingMode::QtTest);
	db_key *keys = Database.model<db_key>();
	pki_key *caKey = keys->newKey(keyjob("EC:prime256v1"), "ca key");

	pki_x509 *ca = issue("Signal CA", caKey, nullptr, 365);
	QVERIFY(ca);
	model->timerMaintenance();
	pki_x509 *a = issue("a.example", keys->newKey(keyjob("EC:prime256v1"),
				"a key"), ca, 90);
	QVERIFY(a);
	QCOMPARE(a->getSigner(), ca);
	model->timerMaintenance();
	pki_x509 *b = issue("b.example", keys->newKey(keyjob("EC:prime256v1"),
				"b key"), ca, 90);
	QVERIFY(b);
	model->timerMaintenance();

	/* a newer CA certificate of the same name and key takes over the
	 * children of the older one: rows move between parents */
	pki_x509 *newer = issue("Signal CA", caKey, nullptr, 730);
	QVERIFY(newer);
	QCOMPARE(a->getSigner(), newer);
	QCOMPARE(b->getSigner(), newer);
	model->timerMaintenance();
	if (tree) {
		QCOMPARE(a->getParent(), (pki_base *)newer);
		QCOMPARE(model->rowCount(model->index(newer)), 2);
	}
	/* back to the other view, the tester keeps watching */
	model->changeView();
	model->timerMaintenance();
	model->changeView();
}

XCA_SERVICE_TEST_MAIN(test_service_model_signals)
#include "test_service_model_signals.moc"
