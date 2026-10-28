/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2010 - 2011 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "NewCrl.h"
#include "XcaDialog.h"
#include "validity.h"
#include "MainWindow.h"
#include "XcaWarning.h"
#include "lib/audit.h"
#include "lib/base.h"
#include "lib/database_model.h"
#include "lib/db_crl.h"
#include "lib/func.h"
#include <QLabel>
#include <QLineEdit>
#include <QComboBox>
#include <QCheckBox>
#include <QMessageBox>

NewCrl::NewCrl(const crljob &j, QWidget *w)
	: QWidget(w ? w : mainwin), task(j)
{
	pki_x509 *issuer = task.issuer;
	pki_key *key = issuer->getRefKey();

	setupUi(this);
	dateBox->setTitle(issuer->getIntName());
	validNumber->setText(QString::number(task.crlDays));
	validRange->setCurrentIndex(0);
	on_applyTime_clicked();
	nextUpdate->setEndDate(true);

	hashAlgo->setupHashes(key->possibleHashNids());
	hashAlgo->setCurrent(task.hashAlgo);

	crlNumber->setText(task.crlNumber.toDec());
	if (issuer->hasExtension(NID_subject_alt_name)) {
		subAltName->setEnabled(true);
		subAltName->setChecked(task.subAltName);
	} else {
		subAltName->setEnabled(false);
	}
	revocationReasons->setChecked(task.withReason);
	/* always part of a CRL (BTD-33) */
	authKeyId->setChecked(true);
	authKeyId->setEnabled(false);
	setCrlNumber->setChecked(true);
	setCrlNumber->setEnabled(false);
}

crljob NewCrl::getCrlJob() const
{
	crljob t = task;
	t.withReason = revocationReasons->isChecked();
	t.subAltName = subAltName->isChecked();
	t.lastUpdate = lastUpdate->getDate();
	t.nextUpdate = nextUpdate->getDate();
    t.hashAlgo = hashAlgo->current();
    t.crlNumber = crlNumber->text().toLong();
	return t;
}

void NewCrl::on_applyTime_clicked()
{
	nextUpdate->setDiff(lastUpdate, validNumber->text().toInt(),
					validRange->currentIndex());
}

NewCrl::~NewCrl()
{
	qDebug() << "NewCrl::~NewCrl() -- DELETED";
}

void NewCrl::newCrl(QWidget *parent, pki_x509 *issuer)
{
	crljob task(issuer);
	NewCrl *widget = new NewCrl(task);
	XcaDialog *dlg = new XcaDialog(parent, revocation, widget,
				tr("Create CRL"), QString(), "crlgenerate");
	if (dlg->exec()) {
		db_crl *db = Database.model<db_crl>();
		try {
			if (db)
				db->createSuccess(db->newCrl(
					ServiceContext::localUser(
						ServiceContext::gui),
					widget->getCrlJob()));
		} catch (errorEx &err) {
			XCA_ERROR(err);
		}
	}
	delete dlg;
}
