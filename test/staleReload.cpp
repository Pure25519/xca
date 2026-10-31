/* vi: set sw=4 ts=4:
 *
 * A database reload while a GUI handler holds an item (BTD-238). The
 * 1500 ms reload of database_model runs inside every nested event loop
 * when another process wrote. db_base::reloadContainer() made new objects
 * for every row and kept the old ones, so a pki_base* taken before the
 * loop was an orphan afterwards and the confirmed delete of the
 * certificate view failed with missing_object (BTD-87). The reload now
 * refreshes the object of each row in place: the held pointer stays the
 * object of its row.
 */

#include <QItemSelectionModel>

#include "widgets/MainWindow.h"
#include "widgets/CertTreeView.h"
#include "lib/XcaWarningCore.h"
#include "lib/audit.h"
#include "lib/db_key.h"
#include "lib/db_x509.h"
#include "lib/issuance.h"
#include "lib/pki_x509.h"

#include "main.h"

/* answers every question with yes; the first okcancel reloads the
 * certificates first, as the reload timer would during the dialog */
class reloadInQuestion : public xcaWarningCore
{
  public:
	int reloads{};
	bool okcancel(const QString &, const QString &) override
	{
		Database.model<db_x509>()->reloadContainer({ x509 });
		reloads++;
		return true;
	}
	bool yesno(const QString &, const QString &) override
	{
		return true;
	}
};

static pki_x509 *srCert(const QString &cn)
{
	ServiceContext ctx(ServiceContext::cli, "os:test");
	IssuanceSpec spec;
	spec.name = cn;
	spec.subject.addEntryByNid(NID_commonName, cn);
	spec.key = Database.model<db_key>()->newKey(keyjob("EC:prime256v1"),
						cn + " key");
	spec.notBefore = a1time(QDateTime::currentDateTimeUtc().addDays(-1));
	spec.notAfter = a1time(QDateTime::currentDateTimeUtc().addYears(1));
	spec.hashAlgo = digest(NID_sha256);
	spec.extensions.basicCA = ExtensionSpec::bc_ca;
	spec.extensions.keyUsage << "keyCertSign" << "cRLSign";
	return Database.model<db_x509>()->newCert(ctx, spec);
}

/* the rows of the model whose object has this name */
static int modelRows(db_x509 *certs, const QString &name)
{
	int n = 0;
	for (int r = 0; r < certs->rowCount(QModelIndex()); r++) {
		pki_base *p = db_base::fromIndex(certs->index(r, 0,
						QModelIndex()));
		if (p && p->getIntName() == name)
			n++;
	}
	return n;
}

void test_main::staleReloadInDelete()
{
	try {
		openDB();
		db_x509 *certs = Database.model<db_x509>();
		pki_x509 *a = srCert("stale A");
		pki_x509 *b = srCert("stale B");
		QVERIFY(a && b);
		QVariant idA = a->getSqlItemId(), idB = b->getSqlItemId();

		/* the reload keeps the object of each row */
		certs->reloadContainer({ x509 });
		QCOMPARE(Store.lookupPki<pki_x509>(idA), a);
		QCOMPARE(modelRows(certs, "stale A"), 1);
		QCOMPARE(db_base::fromIndex(certs->index(a)), (pki_base *)a);

		/* the GUI delete with a reload inside its confirmation */
		QTRY_VERIFY_WITH_TIMEOUT(mainwin->certView->getProxyIndex(
				certs->index(a)).isValid(), 2000);
		mainwin->certView->selectionModel()->select(
			mainwin->certView->getProxyIndex(certs->index(a)),
			QItemSelectionModel::ClearAndSelect |
			QItemSelectionModel::Rows);
		reloadInQuestion *w = new reloadInQuestion();
		xcaWarning::setGui(w);
		int before = AuditLog::entries().size();
		mainwin->certView->deleteItems();
		int reloads = w->reloads;
		xcaWarning::setGui(new xcaWarningCore());
		QCOMPARE(reloads, 1);
		QList<AuditEntry> added = AuditLog::entries().mid(before);
		QCOMPARE(added.size(), 1);
		QCOMPARE(added[0].action, QString("object.delete"));
		QCOMPARE(added[0].result, QString("success"));
		QVERIFY(!Store.find(idA.toULongLong()));
		QCOMPARE(modelRows(certs, "stale A"), 0);
		QCOMPARE(Store.lookupPki<pki_x509>(idB), b);
	} catch (errorEx &err) {
		QVERIFY2(false, CCHAR(err.getString()));
	}
}

/* BTD-239: right after a reload the view's proxy shows every row of the
 * model, without waiting for the throttled invalidate of XcaTreeView */
void test_main::reloadProxyRows()
{
	try {
		openDB();
		db_x509 *certs = Database.model<db_x509>();
		QVERIFY(srCert("proxy A") && srCert("proxy B"));
		QAbstractItemModel *proxy = mainwin->certView->model();
		QTRY_COMPARE_WITH_TIMEOUT(proxy->rowCount(),
			certs->rowCount(QModelIndex()), 2000);
		int rows = certs->rowCount(QModelIndex());
		QVERIFY(rows >= 2);

		certs->reloadContainer({ x509 });
		QCOMPARE(certs->rowCount(QModelIndex()), rows);
		QCOMPARE(proxy->rowCount(), rows);
	} catch (errorEx &err) {
		QVERIFY2(false, CCHAR(err.getString()));
	}
}
