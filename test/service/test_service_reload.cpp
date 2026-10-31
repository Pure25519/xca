/* vi: set sw=4 ts=4:
 *
 * The reload of a model after another process wrote (BTD-238):
 * db_base::reloadContainer() refreshes the object of each row in place
 * instead of making a new one, so a pointer held across the reload stays
 * the object of its row. An object whose row is gone leaves the Store and
 * the model; it stays readable for whoever still holds it (freed when the
 * database closes), and the services refuse it with missing_object.
 */

#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/db_key.h"
#include "lib/db_x509.h"
#include "lib/exception.h"
#include "lib/issuance.h"
#include "lib/pki_x509.h"

#include "ServiceTestCase.h"

class test_service_reload : public ServiceTestCase
{
	Q_OBJECT

	ServiceContext ctx{ ServiceContext::cli, "os:service-test" };

	static db_x509 *certs()
	{
		return Database.model<db_x509>();
	}
	pki_x509 *issue(const QString &cn, pki_x509 *signer);
	static int modelRows(const QString &name);
	static void sql(const QString &statement);

  private slots:
	void sameObjectAfterReload();
	void changedRowRefreshed();
	void writeAfterReload();
	void deletedRowAfterReload();
};

pki_x509 *test_service_reload::issue(const QString &cn, pki_x509 *signer)
{
	IssuanceSpec spec;
	spec.name = cn;
	spec.subject.addEntryByNid(NID_commonName, cn);
	spec.key = Database.model<db_key>()->newKey(keyjob("EC:prime256v1"),
						cn + " key");
	spec.signer = signer;
	spec.notBefore = a1time(QDateTime::currentDateTimeUtc().addDays(-1));
	spec.notAfter = a1time(QDateTime::currentDateTimeUtc().addDays(
				signer ? 90 : 365));
	spec.hashAlgo = digest(NID_sha256);
	spec.extensions.basicCA = signer ? ExtensionSpec::bc_not_ca :
					   ExtensionSpec::bc_ca;
	if (!signer)
		spec.extensions.keyUsage << "keyCertSign" << "cRLSign";
	return certs()->newCert(ctx, spec);
}

/* the rows of the model (tree, all levels) whose object has this name */
int test_service_reload::modelRows(const QString &name)
{
	int n = 0;
	QList<QModelIndex> todo{ QModelIndex() };
	while (!todo.isEmpty()) {
		QModelIndex parent = todo.takeFirst();
		for (int r = 0; r < certs()->rowCount(parent); r++) {
			QModelIndex i = certs()->index(r, 0, parent);
			pki_base *p = db_base::fromIndex(i);
			if (p && p->getIntName() == name)
				n++;
			todo << i;
		}
	}
	return n;
}

/* as another process would write */
void test_service_reload::sql(const QString &statement)
{
	XSqlQuery q;
	QVERIFY2(q.exec(statement), qPrintable(statement));
}

void test_service_reload::sameObjectAfterReload()
{
	pki_x509 *ca = issue("Reload CA", nullptr);
	pki_x509 *leaf = issue("reload leaf", ca);
	QVERIFY(ca && leaf);
	QVariant idCa = ca->getSqlItemId(), idLeaf = leaf->getSqlItemId();

	certs()->reloadContainer({ x509 });
	QCOMPARE(Store.lookupPki<pki_x509>(idCa), ca);
	QCOMPARE(Store.lookupPki<pki_x509>(idLeaf), leaf);
	QCOMPARE(leaf->getSigner(), ca);
	QCOMPARE(leaf->getParent(), (pki_base *)ca);
	QCOMPARE(modelRows("reload leaf"), 1);
	QCOMPARE(certs()->allItemsCount(), 2);
}

/* another process renamed the certificate and revoked and unrevoked
 * nothing: the held object shows the stored name */
void test_service_reload::changedRowRefreshed()
{
	pki_x509 *ca = issue("Rename CA", nullptr);
	QVERIFY(ca);
	sql(QString("UPDATE items SET name='renamed elsewhere' WHERE id=%1")
		.arg(ca->getSqlItemId().toString()));
	certs()->reloadContainer({ x509 });
	QCOMPARE(Store.lookupPki<pki_x509>(ca->getSqlItemId()), ca);
	QCOMPARE(ca->getIntName(), QString("renamed elsewhere"));
	QCOMPARE(modelRows("renamed elsewhere"), 1);
}

/* a write on the held object after a reload lands on its row and in the
 * model */
void test_service_reload::writeAfterReload()
{
	pki_x509 *ca = issue("Write CA", nullptr);
	QVERIFY(ca);
	certs()->reloadContainer({ x509 });
	certs()->updateProperties(ctx, ca, "written after reload", "comment");
	XSqlQuery q(QString("SELECT name, comment FROM items WHERE id=%1")
		.arg(ca->getSqlItemId().toString()));
	QVERIFY(q.first());
	QCOMPARE(q.value(0).toString(), QString("written after reload"));
	QCOMPARE(q.value(1).toString(), QString("comment"));
	QCOMPARE(modelRows("written after reload"), 1);
}

/* another process deleted the row: the object leaves Store and model, the
 * holder can still read it, and the delete service refuses it with a
 * typed error and no success entry */
void test_service_reload::deletedRowAfterReload()
{
	pki_x509 *ca = issue("Gone CA", nullptr);
	pki_x509 *other = issue("Staying CA", nullptr);
	QVERIFY(ca && other);
	QString id = ca->getSqlItemId().toString();
	for (const char *t : { "certs", "x509super", "authority" })
		sql(QString("DELETE FROM %1 WHERE item=%2").arg(t).arg(id));
	sql(QString("DELETE FROM items WHERE id=%1").arg(id));

	certs()->reloadContainer({ x509 });
	QVERIFY(!Store.find(id.toULongLong()));
	QCOMPARE(modelRows("Gone CA"), 0);
	QCOMPARE(ca->getIntName(), QString("Gone CA"));
	QCOMPARE(Store.lookupPki<pki_x509>(other->getSqlItemId()), other);

	int before = AuditLog::entries().size();
	QString code = "<deleted>";
	try {
		certs()->deleteItems(ctx, { ca });
	} catch (serviceError &err) {
		code = err.code;
	}
	QCOMPARE(code, QString("missing_object"));
	QList<AuditEntry> added = AuditLog::entries().mid(before);
	QCOMPARE(added.size(), 1);
	QCOMPARE(added[0].result, QString("failure"));
	AuditVerifyResult v = AuditLog::verify();
	QVERIFY2(v.ok(), v.toJson().constData());
}

XCA_SERVICE_TEST_MAIN(test_service_reload)
#include "test_service_reload.moc"
