/* vi: set sw=4 ts=4:
 *
 * The renewal dialog through the renew service function (BTD-56): every
 * renewal writes an audit entry certificate.renew (success or failure)
 * with the channel gui; the selected certificates are renewed in one
 * transaction, and the old ones are revoked and replaced only after all
 * renewals succeeded; a renewal under an issuer that fails a check is
 * refused with the typed error of an issuance. Before, the dialog signed
 * outside the service: no audit, no checks, the renewals before a failing
 * one stayed stored.
 */

#include <QCheckBox>
#include <QDialogButtonBox>
#include <QPushButton>

#include "widgets/MainWindow.h"
#include "widgets/CertExtend.h"
#include "widgets/CertTreeView.h"
#include "widgets/RevocationList.h"
#include "ui_CertExtend.h"
#include "ui_Revoke.h"
#include "lib/XcaWarningCore.h"
#include "lib/audit.h"
#include "lib/db_key.h"
#include "lib/db_x509.h"
#include "lib/issuance.h"
#include "lib/pki_x509.h"

#include "main.h"

static QStringList rsErrors;

/* testxca answers like the command line; this one keeps the errors */
class renewalServiceErrors : public xcaWarningCore
{
  public:
	void error(const QString &msg) override
	{
		rsErrors << msg;
	}
};

static pki_x509 *rsIssue(const QString &cn, pki_x509 *ca)
{
	ServiceContext ctx(ServiceContext::cli, "os:test");
	IssuanceSpec spec;
	spec.name = cn;
	spec.subject.addEntryByNid(NID_commonName, cn);
	spec.key = Database.model<db_key>()->newKey(keyjob("EC:prime256v1"),
						cn + " key");
	spec.signer = ca;
	spec.notBefore = a1time(QDateTime::currentDateTimeUtc().addDays(-1));
	spec.notAfter = a1time(QDateTime::currentDateTimeUtc().addYears(
				ca ? 1 : 5));
	spec.hashAlgo = digest(NID_sha256);
	spec.extensions.basicCA = ca ? ExtensionSpec::bc_not_ca :
					ExtensionSpec::bc_ca;
	spec.extensions.subjectKeyId = true;
	if (ca)
		spec.extensions.keyUsage << "digitalSignature";
	else
		spec.extensions.keyUsage << "keyCertSign" << "cRLSign";
	return Database.model<db_x509>()->newCert(ctx, spec);
}

/* Revoke and replace the old certificates, as the dialog offers */
static void renewRevokeReplace(CertExtend *dlg)
{
	dlg->revoke->setCheckState(Qt::Checked);
	dlg->replace->setCheckState(Qt::Checked);
	whenShown<Revocation>("Revoke", [](Revocation *rev) {
		rev->buttonBox->button(QDialogButtonBox::Ok)->click();
	});
	dlg->buttonBox->button(QDialogButtonBox::Ok)->click();
}

static void renewOnly(CertExtend *dlg)
{
	dlg->revoke->setCheckState(Qt::Unchecked);
	dlg->replace->setCheckState(Qt::Unchecked);
	dlg->buttonBox->button(QDialogButtonBox::Ok)->click();
}

void test_main::renewalThroughService()
{
	try {
		openDB();
		db_x509 *certs = Database.model<db_x509>();
		pki_x509 *ca = rsIssue("Service Renew CA", nullptr);
		pki_x509 *a = rsIssue("renew-a.example", ca);
		pki_x509 *b = rsIssue("renew-b.example", ca);
		QVERIFY(ca && a && b);
		a1int serialA = a->getSerial(), serialB = b->getSerial();
		int before = AuditLog::entries().size();

		/* both selected, renewed, then revoked and replaced */
		whenShown<CertExtend>("CertExtend", renewRevokeReplace);
		mainwin->certView->renewal({ certs->index(a), certs->index(b) });
		QList<AuditEntry> added = AuditLog::entries().mid(before);
		QStringList actions;
		for (const AuditEntry &e : added)
			actions << e.action + ":" + e.result;
		/* renewals first, then revocations, then the deletions */
		QCOMPARE(actions.mid(0, 4), (QStringList{
			"certificate.renew:success", "certificate.renew:success",
			"certificate.revoke:success", "certificate.revoke:success" }));
		QVERIFY2(actions.size() > 4, CCHAR(actions.join(" ")));
		for (const QString &a : actions.mid(4))
			QCOMPARE(a, QString("object.delete:success"));
		QCOMPARE(added[0].channel, QString("gui"));
		QCOMPARE(added[0].params["predecessor_serial"].toString(),
			serialA.toHex());
		QCOMPARE(added[1].params["predecessor_serial"].toString(),
			serialB.toHex());
		QList<pki_x509 *> left;
		for (pki_x509 *c : Store.getAll<pki_x509>())
			if (c->getIntName().startsWith("renew-"))
				left << c;
		QCOMPARE(left.size(), 2);
		for (pki_x509 *c : left) {
			QVERIFY(c->getSerial() != serialA && c->getSerial() != serialB);
			QCOMPARE(c->getSigner(), ca);
		}
		QVERIFY(AuditLog::verify().ok());
	} catch (errorEx &err) {
		QVERIFY2(false, CCHAR(err.getString()));
	}
}

/* AC 4 and 5: the second selected certificate's issuer no longer has
 * the private key of its certificate (issuer_key_mismatch): nothing is
 * renewed, revoked or deleted, the error names the code's reason and
 * one failure entry certificate.renew is kept */
void test_main::renewalAllOrNothing()
{
	try {
		openDB();
		db_x509 *certs = Database.model<db_x509>();
		pki_x509 *ca = rsIssue("Good Renew CA", nullptr);
		pki_x509 *other = rsIssue("Broken Renew CA", nullptr);
		QVERIFY(ca && other);
		pki_x509 *a = rsIssue("keep-a.example", ca);
		pki_x509 *b = rsIssue("keep-b.example", other);
		QVERIFY(a && b);
		other->setRefKey(Database.model<db_key>()->newKey(
				keyjob("EC:prime256v1"), "stray key"));
		int stored = Store.getAll<pki_x509>().size();
		int before = AuditLog::entries().size();

		rsErrors.clear();
		xcaWarning::setGui(new renewalServiceErrors());
		whenShown<CertExtend>("CertExtend", renewRevokeReplace);
		mainwin->certView->renewal({ certs->index(a), certs->index(b) });
		xcaWarning::setGui(new xcaWarningCore());

		QCOMPARE(rsErrors.size(), 1);
		QVERIFY2(rsErrors[0].contains("does not belong to"),
			CCHAR(rsErrors[0]));
		QCOMPARE(Store.getAll<pki_x509>().size(), stored);
		QVERIFY(!a->isRevoked() && !b->isRevoked());
		QList<AuditEntry> added = AuditLog::entries().mid(before);
		QCOMPARE(added.size(), 1);
		QCOMPARE(added[0].action, QString("certificate.renew"));
		QCOMPARE(added[0].result, QString("failure"));
		QCOMPARE(added[0].errorCode, QString("issuer_key_mismatch"));
		QCOMPARE(added[0].channel, QString("gui"));

		/* alone, the good one renews */
		whenShown<CertExtend>("CertExtend", renewOnly);
		mainwin->certView->renewal({ certs->index(a) });
		QCOMPARE(Store.getAll<pki_x509>().size(), stored + 1);
		QCOMPARE(AuditLog::entries().last().action,
			QString("certificate.renew"));
		QCOMPARE(AuditLog::entries().last().result, QString("success"));
	} catch (errorEx &err) {
		QVERIFY2(false, CCHAR(err.getString()));
	}
}
