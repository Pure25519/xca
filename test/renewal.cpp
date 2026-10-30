/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2024 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QTest>
#include <QThread>
#include <QDialog>
#include <QCheckBox>

#include "widgets/MainWindow.h"
#include "ui_MainWindow.h"
#include "widgets/ImportMulti.h"
#include "ui_ImportMulti.h"
#include "widgets/CertExtend.h"
#include "lib/audit.h"
#include "ui_CertExtend.h"
#include "widgets/RevocationList.h"
#include "ui_RevocationList.h"
#include "ui_Revoke.h"

#include "lib/pki_multi.h"

#include "widgets/XcaWarning.h"
#include "lib/db_key.h"
#include "lib/issuance.h"
#include <QMessageBox>
#include "lib/XcaWarningCore.h"
#include "main.h"

#define ZERO_SECS "yyyyMMddHHmm'00Z'"
a1time not_after = a1time::now(3*356*24*60*60);

void revoke_and_renew()
{
	CertExtend *dlg = test_main::findWindow<CertExtend>("CertExtend");
	if (!dlg)
		return;
	dlg->replace->setCheckState(Qt::Checked);
	dlg->revoke->setCheckState(Qt::Checked);
	dlg->notAfter->setDate(not_after);
	dlg->buttonBox->button(QDialogButtonBox::Ok)->click();
	Revocation *rev = test_main::findWindow<Revocation>("Revoke");
	rev->buttonBox->button(QDialogButtonBox::Ok)->click();
}

void renew()
{
	CertExtend *dlg = test_main::findWindow<CertExtend>("CertExtend");
	if (!dlg)
		return;
	dlg->validNumber->setText("1");
	dlg->validRange->setCurrentIndex(1);
	dlg->applyTime->click();
	not_after = dlg->notAfter->getDate();
	dlg->replace->setCheckState(Qt::Unchecked);
	dlg->revoke->setCheckState(Qt::Unchecked);
	dlg->buttonBox->button(QDialogButtonBox::Ok)->click();
}

void renew_del_keep_serial()
{
	CertExtend *dlg = test_main::findWindow<CertExtend>("CertExtend");
	if (!dlg)
		return;
	dlg->replace->setCheckState(Qt::Checked);
	dlg->revoke->setCheckState(Qt::Unchecked);
	dlg->noWellDefinedExpDate->setCheckState(Qt::Checked);
	dlg->keepSerial->setCheckState(Qt::Checked);
	dlg->buttonBox->button(QDialogButtonBox::Ok)->click();
}

QList<pki_x509*> getcerts(const QString &name)
{
	QList<pki_x509*> l;
	foreach(pki_x509 *pki, Store.getAll<pki_x509>()) {
        if (pki->getIntName() == name)
			l << pki;
	}
	return l;
}

static QStringList renewErrors;

/* testxca answers like the command line (xcaWarningCore); this one also
 * keeps the error messages the renewal reports */
class renewalErrors : public xcaWarningCore
{
  public:
	void error(const QString &msg) override
	{
		renewErrors << msg;
	}
};

/* Accepts the renewal dialog as it is */
static void renewAsIs()
{
	CertExtend *dlg = test_main::findWindow<CertExtend>("CertExtend");
	if (!dlg)
		return;
	dlg->replace->setCheckState(Qt::Unchecked);
	dlg->revoke->setCheckState(Qt::Unchecked);
	dlg->buttonBox->button(QDialogButtonBox::Ok)->click();
}

/* BTD-181: the renewal signs with the issuer's key and the digest of the
 * old certificate; when that signature fails (an RSA-512 CA key with
 * SHA-512), the dialog shows the error and stores nothing, never a
 * certificate with an empty DER (BTD-171) */
void test_main::renewalSigningFails()
{
	try {
		openDB();
		ServiceContext ctx(ServiceContext::cli, "os:test");
		db_key *keys = Database.model<db_key>();
		db_x509 *certs = Database.model<db_x509>();
		pki_key *caKey = keys->newKey(keyjob("RSA:2048"), "CA");
		/* XCA asks before it makes a key that small */
		xcaWarningCore::setConfirmations(false, { "key.size" });
		pki_key *small = keys->newKey(keyjob("RSA:512"), "small");
		xcaWarningCore::setConfirmations(false, {});
		pki_key *eeKey = keys->newKey(keyjob("EC:prime256v1"), "EE");
		QVERIFY(caKey && small && eeKey);
		x509name n;
		n.addEntryByNid(NID_commonName, "Renew CA");
		IssuanceSpec spec;
		spec.name = "Renew CA";
		spec.subject = n;
		spec.key = caKey;
		spec.notBefore = a1time(QDateTime::currentDateTimeUtc().addDays(-1));
		spec.notAfter = a1time(QDateTime::currentDateTimeUtc().addYears(2));
		spec.hashAlgo = digest(NID_sha256);
		spec.extensions.basicCA = ExtensionSpec::bc_ca;
		spec.extensions.keyUsage << "keyCertSign" << "cRLSign";
		pki_x509 *ca = certs->newCert(ctx, spec);
		QVERIFY(ca);
		x509name en;
		en.addEntryByNid(NID_commonName, "renew.example");
		IssuanceSpec ee;
		ee.name = "renew leaf";
		ee.subject = en;
		ee.key = eeKey;
		ee.signer = ca;
		ee.notBefore = a1time();
		ee.notAfter = a1time(QDateTime::currentDateTimeUtc().addDays(30));
		ee.hashAlgo = digest(NID_sha512);
		ee.extensions.basicCA = ExtensionSpec::bc_not_ca;
		pki_x509 *leaf = certs->newCert(ctx, ee);
		QVERIFY(leaf);
		int before = Store.getAll<pki_x509>().size();

		/* the CA now signs with a key too small for SHA-512 */
		ca->setRefKey(small);
		renewErrors.clear();
		xcaWarning::setGui(new renewalErrors());
		QThread *job = QThread::create(renewAsIs);
		job->start();
		mainwin->certView->renewal({ certs->index(leaf) });
		job->wait();
		delete job;
		xcaWarning::setGui(new xcaWarningCore());

		QCOMPARE(renewErrors.size(), 1);
		QVERIFY2(renewErrors[0].contains("could not be signed"),
			CCHAR(renewErrors[0]));
		QCOMPARE(Store.getAll<pki_x509>().size(), before);
		QCOMPARE(getcerts("renew leaf").size(), 1);
	} catch (errorEx &err) {
		QVERIFY2(false, CCHAR(err.getString()));
	}
}

void test_main::revoke()
{
	try {

	ign_openssl_error();
	openDB();
	dbstatus();
	pki_multi *pem = new pki_multi();
	pem->fromPEMbyteArray(pemdata["Inter CA 1"].toUtf8(), QString());
	pem->fromPEMbyteArray(pemdata["Root CA"].toUtf8(), QString());
	pem->fromPEMbyteArray(pemdata["Root CA Key"].toUtf8(), QString());
	Database.insert(pem);
	dbstatus();

	QThread *job;
	QList<pki_x509*> l;
	db_x509 *certs = Database.model<db_x509>();
	pki_x509 *cert;
	a1int serial;

	// Revoke and renew
	cert = dynamic_cast<pki_x509*>(certs->getByName("Inter CA 1"));
	serial = cert->getSerial();
	job = QThread::create(revoke_and_renew);
	job->start();
	mainwin->certView->renewal({ certs->index(cert) });
	job->wait();

	delete job;
	dbstatus();
	l = getcerts("Inter CA 1");
	QCOMPARE(1, l.size());

	bool found = false;
	x509revList revs = dynamic_cast<pki_x509*>(certs->getByName("Root CA"))->getRevList();
	for (x509rev r : revs) {
		if (r.getSerial() == serial)
			found = true;
	}
	QVERIFY2(found, "Revoked serial not found");

	// renew
	job = QThread::create(renew);
	job->start();
	mainwin->certView->renewal({ certs->index(certs->getByName("Inter CA 1")) });
	job->wait();

	delete job;
	dbstatus();
	l = getcerts("Inter CA 1");
	QCOMPARE(2, l.size());
	// Delete one of the certs
	if (l.size() > 0)
		certs->deleteItems(ServiceContext::localUser(
				ServiceContext::cli), { l[0] });
	l = getcerts("Inter CA 1");
	QCOMPARE(1, l.size());

	// renew, keep serial
	cert = dynamic_cast<pki_x509*>(certs->getByName("Inter CA 1"));
	serial = cert->getSerial();

	job = QThread::create(renew_del_keep_serial);
	job->start();
	mainwin->certView->renewal({ certs->index(certs->getByName("Inter CA 1")) });
	job->wait();

	delete job;
	dbstatus();
	l = getcerts("Inter CA 1");
	QCOMPARE(1, l.size());
	not_after.setUndefined();
	if (l.size() > 0)
		QCOMPARE(l[0]->getNotAfter().toPlain(), not_after.toPlain());

	} catch (...) {
		QVERIFY2(false, "Exception thrown");
	}
}
