/* vi: set sw=4 ts=4:
 *
 * The invalidity date of the revocation dialog (BTD-206): only with the
 * box "Invalid since" ticked; a date after the revocation is refused by
 * db_x509::revoke() with invalid_invalidity_date, shown as an error, and
 * revokes nothing.
 */

#include "widgets/MainWindow.h"
#include "widgets/CertTreeView.h"
#include "ui_Revoke.h"
#include "widgets/RevocationList.h"
#include "lib/XcaWarningCore.h"
#include "lib/audit.h"
#include "lib/db_key.h"
#include "lib/db_x509.h"
#include "lib/issuance.h"
#include "lib/pki_x509.h"

#include "main.h"

static QStringList revokeErrors;

/* testxca answers like the command line; this one keeps the errors */
class revokeWarnings : public xcaWarningCore
{
  public:
	void error(const QString &msg) override
	{
		revokeErrors << msg;
	}
};

static pki_x509 *riIssue(const QString &cn, pki_x509 *signer)
{
	ServiceContext ctx(ServiceContext::cli, "os:test");
	IssuanceSpec spec;
	spec.name = cn;
	spec.subject.addEntryByNid(NID_commonName, cn);
	spec.key = Database.model<db_key>()->newKey(keyjob("EC:prime256v1"),
			cn + " key");
	spec.signer = signer;
	spec.notBefore = a1time(QDateTime::currentDateTimeUtc().addDays(-1));
	spec.notAfter = a1time(QDateTime::currentDateTimeUtc().addDays(
				signer ? 90 : 730));
	spec.hashAlgo = digest(NID_sha256);
	if (signer) {
		spec.extensions.basicCA = ExtensionSpec::bc_not_ca;
		spec.extensions.keyUsage << "digitalSignature";
	} else {
		spec.extensions.basicCA = ExtensionSpec::bc_ca;
		spec.extensions.keyUsage << "keyCertSign" << "cRLSign";
	}
	return Database.model<db_x509>()->newCert(ctx, spec);
}

/* the revoke action of the certificate view on cert, with the dialog
 * answered by fill */
static void revokeInView(pki_x509 *cert, void (*fill)(Revocation *))
{
	CertTreeView *v = mainwin->certView;
	QModelIndex idx = v->getProxyIndex(
			Database.model<db_x509>()->index(cert));
	v->selectionModel()->setCurrentIndex(idx,
		QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
	whenShown<Revocation>("Revoke", fill);
	v->revoke();
}

static a1time pastDate;

static void ahead(Revocation *dlg)
{
	dlg->invalidSince->setChecked(true);
	dlg->invalid->setDate(a1time(
			QDateTime::currentDateTimeUtc().addDays(1)));
	dlg->buttonBox->button(QDialogButtonBox::Ok)->click();
}

static void past(Revocation *dlg)
{
	QVERIFY(!dlg->invalid->isEnabled());
	dlg->invalidSince->setChecked(true);
	QVERIFY(dlg->invalid->isEnabled());
	dlg->invalid->setDate(pastDate);
	dlg->buttonBox->button(QDialogButtonBox::Ok)->click();
}

void test_main::revokeInvalidityDate()
{
	try {
		openDB();
		pki_x509 *ca = riIssue("Invalidity GUI CA", nullptr);
		QVERIFY(ca);
		pki_x509 *refused = riIssue("ahead.example", ca);
		pki_x509 *kept = riIssue("past.example", ca);
		QVERIFY(refused && kept);

		revokeErrors.clear();
		xcaWarning::setGui(new revokeWarnings());
		int entries = AuditLog::entries().size();
		revokeInView(refused, ahead);
		xcaWarning::setGui(new xcaWarningCore());
		QCOMPARE(revokeErrors.size(), 1);
		QVERIFY2(revokeErrors[0].contains("after the revocation date"),
			CCHAR(revokeErrors[0]));
		QVERIFY(!refused->isRevoked());
		QCOMPARE(AuditLog::entries().size(), entries + 1);
		AuditEntry e = AuditLog::entries().last();
		QCOMPARE(e.action, QString("certificate.revoke"));
		QCOMPARE(e.result, QString("failure"));
		QCOMPARE(e.errorCode, QString("invalid_invalidity_date"));

		pastDate = a1time("20261001120000Z");
		revokeInView(kept, past);
		QVERIFY(kept->isRevoked());
		QCOMPARE(kept->getRevocation().getInvalDate().toPlainUTC(),
			pastDate.toPlainUTC());
		QVERIFY(AuditLog::verify().ok());
	} catch (errorEx &err) {
		QVERIFY2(false, CCHAR(err.getString()));
	}
}
