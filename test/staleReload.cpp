/* vi: set sw=4 ts=4:
 *
 * BTD-87 (investigation): what a GUI handler holds across a nested event
 * loop when the 1500 ms reload of database_model runs inside it. The
 * reload (db_base::reloadContainer) makes new objects for every row and
 * keeps the old ones, so a pki_base* taken before the loop is no longer
 * the object of the model and of the Store afterwards. The delete of the
 * certificate view asks for confirmation in such a loop; the reload is
 * run in the answer, as another process changing the database would
 * trigger it. These cases record the behaviour of bxc-main; they are the
 * evidence of the investigation, not a fix.
 */

#include <QItemSelectionModel>
#include <QSortFilterProxyModel>

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

		/* (1) a reload makes new objects; the old one is orphaned */
		certs->reloadContainer({ x509 });
		pki_x509 *a2 = Store.lookupPki<pki_x509>(idA);
		qInfo() << "BTD-87 reload: same object after reload:"
			<< (a2 == a);
		QVERIFY2(a2 != a, "reloadContainer reuses objects now: "
			"update the BTD-87 findings");
		QCOMPARE(modelRows(certs, "stale A"), 1);
		QCOMPARE(db_base::fromIndex(certs->index(a2)), (pki_base *)a2);
		/* the reload adds its rows after endResetModel() without
		 * rowsInserted: the view shows none until the throttle timer
		 * of XcaTreeView (200 ms) invalidates its proxy */
		int shown = mainwin->certView->model()->rowCount();
		qInfo() << "BTD-87 rows shown right after the reload:" << shown
			<< "of" << certs->rowCount(QModelIndex());
		QTest::qWait(300);
		QCOMPARE(mainwin->certView->model()->rowCount(),
			certs->rowCount(QModelIndex()));

		/* (2) the GUI delete with a reload inside its confirmation */
		mainwin->certView->selectionModel()->select(
			mainwin->certView->getProxyIndex(certs->index(a2)),
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
		QStringList actions;
		for (const AuditEntry &e : added)
			actions << e.action + ":" + e.result + ":" + e.errorCode;
		pki_x509 *a3 = Store.lookupPki<pki_x509>(idA);
		int rowsA = modelRows(certs, "stale A");
		qInfo() << "BTD-87 delete with reload in the confirmation:"
			<< "audit" << actions
			<< "| Store has id A:" << (a3 != nullptr)
			<< "| model rows named 'stale A':" << rowsA
			<< "| B untouched:" << (Store.lookupPki<pki_x509>(idB) != nullptr);
		/* bxc-main: the confirmed delete is refused, because the held
		 * object is no longer the stored one; nothing is deleted, no
		 * other object is touched (no wrong-object delete) */
		QCOMPARE(added.size(), 1);
		QCOMPARE(added[0].action, QString("object.delete"));
		QCOMPARE(added[0].result, QString("failure"));
		QVERIFY(a3);
		QCOMPARE(rowsA, 1);
		QVERIFY(Store.lookupPki<pki_x509>(idB));
	} catch (errorEx &err) {
		QVERIFY2(false, CCHAR(err.getString()));
	}
}
