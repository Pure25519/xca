/* vi: set sw=4 ts=4:
 *
 * The audit log check of the GUI (BTD-103, PLAN.md 6.3): Extra > Verify
 * audit log shows the report of AuditLog::verify(), the same as
 * xca --audit-verify, for an intact and for a manipulated chain, and
 * offers the adoption of BTD-110 for an unsigned log without key. The
 * test finds everything by objectName, as the GUI harness does.
 */

#include <QAbstractButton>
#include <QAction>
#include <QDialog>
#include <QLabel>
#include <QLineEdit>
#include <QSqlQuery>

#include "widgets/MainWindow.h"
#include "widgets/XcaWarning.h"
#include "lib/XcaWarningCore.h"
#include "lib/audit.h"
#include "lib/db_key.h"
#include "lib/pki_evp.h"
#include "lib/settings.h"

#include "main.h"

static QDialog *openAuditVerify(MainWindow *mainwin)
{
	QAction *a = mainwin->findChild<QAction *>("act_extra_verifyAudit");
	if (!a)
		return nullptr;
	a->trigger();
	return test_main::findWindow<QDialog>("dlg_auditVerify");
}

static QString value(QDialog *dlg, const QString &name)
{
	QLabel *l = dlg->findChild<QLabel *>("dlg_auditVerify_" + name);
	return l ? l->text() : QString("<no %1>").arg(name);
}

static void press(QDialog *dlg, const QString &name)
{
	QAbstractButton *b = dlg->findChild<QAbstractButton *>(name);
	QVERIFY2(b, CCHAR(name));
	b->click();
}

void test_main::auditVerifyIntactAndBroken()
{
	try {
		openDB();
		ServiceContext ctx(ServiceContext::cli, "os:test");
		db_key *keys = Database.model<db_key>();
		keys->newKey(keyjob("EC:prime256v1"), "audit view key 1");
		keys->newKey(keyjob("EC:prime256v1"), "audit view key 2");
		AuditLog::checkpoint(ctx);
		keys->newKey(keyjob("EC:prime256v1"), "audit view key 3");

		QDialog *dlg = openAuditVerify(mainwin);
		QVERIFY2(dlg, "Extra > Verify audit log missing");
		AuditVerifyResult r = AuditLog::verify();
		QVERIFY(r.ok());
		QCOMPARE(value(dlg, "ok"), QString("OK"));
		QCOMPARE(value(dlg, "entries"), QString::number(r.entries));
		QCOMPARE(value(dlg, "checkpoints"), QString::number(r.checkpoints));
		QCOMPARE(value(dlg, "lastCheckpointSeq"),
			QString::number(r.lastCheckpointSeq));
		QCOMPARE(value(dlg, "unanchoredEntries"),
			QString::number(r.unanchoredEntries));
		QCOMPARE(value(dlg, "auditKeys"), r.auditKeys.join("\n"));
		QVERIFY(!dlg->findChild<QAbstractButton *>("btn_adopt")
			->isVisible());

		/* The newest entry changed behind XCA's back */
		QSqlQuery q;
		QVERIFY(q.exec("SELECT actor FROM audit_log WHERE "
			"seq=(SELECT MAX(seq) FROM audit_log)") && q.next());
		QString actor = q.value(0).toString();
		QVERIFY(q.exec("UPDATE audit_log SET actor='os:mallory' WHERE "
			"seq=(SELECT MAX(seq) FROM audit_log)"));
		press(dlg, "btn_verify");
		r = AuditLog::verify();
		QVERIFY(!r.ok());
		QCOMPARE(value(dlg, "ok"), QString("Failed"));
		QCOMPARE(value(dlg, "reason"), QString("hash"));
		QCOMPARE(value(dlg, "firstBrokenSeq"),
			QString::number(r.firstBrokenSeq));

		/* Repaired, but a pinned key that is not the log's (BTD-101) */
		q.prepare("UPDATE audit_log SET actor=? WHERE "
			"seq=(SELECT MAX(seq) FROM audit_log)");
		q.addBindValue(actor);
		QVERIFY(q.exec());
		QLineEdit *pin = dlg->findChild<QLineEdit *>(
					"dlg_auditVerify_pinKeys");
		QVERIFY(pin);
		pin->setText(QString(64, '0'));
		press(dlg, "btn_verify");
		QCOMPARE(value(dlg, "reason"), QString("untrusted_key"));
		press(dlg, "btn_close");
	} catch (errorEx &err) {
		QVERIFY2(false, CCHAR(err.getString()));
	}
}

/* Answers the adoption question with "yes" and notes its id and text:
 * testxca runs with the headless xcaWarningCore */
static QString adoptQuestion, adoptId;
class adoptWarnings : public xcaWarningCore
{
  public:
	bool yesno(const QString &id, const QString &msg) override
	{
		adoptId = id;
		adoptQuestion = msg;
		return true;
	}
};

void test_main::auditVerifyAdopt()
{
	try {
		openDB();
		/* A log written without the password for longer than the
		 * interval allows: no key, checkpoint_missing */
		Settings["audit_checkpoint_interval"] = 1;
		Passwd pass = pki_evp::passwd;
		pki_evp::passwd.cleanse();
		ServiceContext ctx(ServiceContext::cli, "os:test");
		for (int i = 0; i < 4; i++)
			AuditLog::append(ctx, "key.generate", "key",
					QString::number(i + 100));
		pki_evp::passwd = pass;

		QDialog *dlg = openAuditVerify(mainwin);
		QVERIFY2(dlg, "Extra > Verify audit log missing");
		QCOMPARE(value(dlg, "reason"), QString("checkpoint_missing"));
		QAbstractButton *adopt =
			dlg->findChild<QAbstractButton *>("btn_adopt");
		QVERIFY(adopt && adopt->isVisible());
		int unanchored = AuditLog::verify().unanchoredEntries;

		adoptQuestion.clear();
		xcaWarning::setGui(new adoptWarnings());
		adopt->click();
		xcaWarning::setGui(new xcaWarningCore());
		QCOMPARE(adoptId, QString("audit.adopt"));
		QVERIFY2(adoptQuestion.contains(QString::number(unanchored)),
			CCHAR(adoptQuestion));
		AuditVerifyResult r = AuditLog::verify();
		QVERIFY2(r.ok(), r.toJson().constData());
		QCOMPARE(value(dlg, "ok"), QString("OK"));
		QCOMPARE(value(dlg, "adoptedEntries"),
			QString::number(r.adoptedEntries));
		QVERIFY(r.adoptedEntries > 0);
		QVERIFY(!adopt->isVisible());
		press(dlg, "btn_close");
	} catch (errorEx &err) {
		QVERIFY2(false, CCHAR(err.getString()));
	}
}
