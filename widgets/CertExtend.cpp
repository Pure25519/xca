/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "CertExtend.h"
#include "CertTreeView.h"
#include "RevocationList.h"
#include "lib/audit.h"
#include "lib/base.h"
#include "lib/db_x509.h"
#include "lib/func.h"
#include "lib/issuance.h"
#include "lib/pki_x509.h"
#include "widgets/validity.h"
#include "widgets/XcaWarning.h"
#include <QLabel>
#include <QLineEdit>
#include <QComboBox>
#include <QCheckBox>
#include <QMessageBox>


CertExtend::CertExtend(QWidget *parent, pki_x509 *s)
	:QDialog(parent)
{
	setupUi(this);
	setWindowTitle(XCA_TITLE);
	image->setPixmap(QPixmap(":certImg"));
	validNumber->setText("1");
	validRange->setCurrentIndex(2);
	on_applyTime_clicked();
	signer = s;
	notAfter->setEndDate(true);
}

void CertExtend::on_applyTime_clicked()
{
	notAfter->setDiff(notBefore, validNumber->text().toInt(),
				     validRange->currentIndex());
}

void CertExtend::on_keepSerial_toggled(bool checked)
{
	if (checked) {
		old_revoke = revoke->isChecked();
		revoke->setEnabled(false);
		revoke->setChecked(false);

		old_replace = replace->isChecked();
		replace->setEnabled(false);
		replace->setChecked(true);
	} else {
		revoke->setEnabled(true);
		revoke->setChecked(old_revoke);

		replace->setEnabled(true);
		replace->setChecked(old_replace);
	}
}

void CertExtend::accept()
{
	if (signer && notBefore->getDate() < signer->getNotBefore()) {
		QString text = tr("The certificate will be earlier valid than the signer. This is probably not what you want.");
		xcaWarningBox msg(this, text);
		msg.addButton(QMessageBox::Ok, tr("Edit dates"));
		msg.addButton(QMessageBox::Close, tr("Abort rollout"));
		msg.addButton(QMessageBox::Apply, tr("Continue rollout"));
		msg.addButton(QMessageBox::Yes, tr("Adjust date and continue"));
		switch (msg.exec())
		{
			case QMessageBox::Ok:
			case QMessageBox::Cancel:
				return;
			case QMessageBox::Close:
				reject();
				return;
			case QMessageBox::Apply:
				break;
			case QMessageBox::Yes:
				notBefore->setDate(signer->getNotBefore());
		}
	}
	/* a signer with the undefined notAfter caps nothing (BTD-51) */
	bool capped = false;
	a1time cappedEnd = IssuanceSpec::cappedNotAfter(notAfter->getDate(),
							signer, &capped);
	if (capped && !noWellDefinedExpDate->isChecked()) {
		QString text = tr("The certificate will be longer valid than the signer. This is probably not what you want.");
		xcaWarningBox msg(this, text);
		msg.addButton(QMessageBox::Ok, tr("Edit dates"));
		msg.addButton(QMessageBox::Close, tr("Abort rollout"));
		msg.addButton(QMessageBox::Apply, tr("Continue rollout"));
		msg.addButton(QMessageBox::Yes, tr("Adjust date and continue"));
		switch (msg.exec())
		{
			case QMessageBox::Ok:
			case QMessageBox::Cancel:
				return;
			case QMessageBox::Close:
				reject();
				return;
			case QMessageBox::Apply:
				break;
			case QMessageBox::Yes:
				notAfter->setDate(cappedEnd);
		}
	}
	QDialog::accept();
}

/* GUI glue of the certificate renewal, moved from lib/db_x509.cpp
 * (BTD-33) and into the certificate view (BTD-36). All selected
 * certificates are renewed by db_x509::renew() in one transaction,
 * through the checks and the audit of every issuance (BTD-56); only
 * then are the old ones revoked (db_x509::revoke()) or deleted. */
void CertTreeView::renewal(QModelIndexList indexes)
{
	if (!basemodel)
		return;
	db_x509 *certs = this->certs();
	pki_x509 *oldcert = NULL, *signer = NULL;
	pki_key *signkey = NULL;
	CertExtend *dlg = NULL;
	x509rev r;
	bool doRevoke = false;
	bool doReplace = false;

	if (indexes.size() == 0)
		return;
	QModelIndex idx = indexes[0];

	try {
		oldcert = db_base::fromIndex<pki_x509>(idx);
		if (!oldcert || !(signer = oldcert->getSigner()) ||
				!(signkey = signer->getRefKey()) ||
				signkey->isPubKey())
			return;
		bool renew_myself = signer == oldcert;
		dlg = new CertExtend(NULL, renew_myself ? NULL : signer);
		dlg->revoke->setEnabled(!renew_myself);
		if (!dlg->exec()) {
			delete dlg;
			return;
		}
		if (dlg->revoke->isChecked() && !renew_myself) {
			Revocation *revoke = new Revocation(indexes);
			doRevoke = revoke->exec();
			r = revoke->getRevocation();
			delete revoke;
		}
		doReplace = dlg->replace->isChecked();
		QList<RenewalSpec> specs;
		foreach(idx, indexes) {
			oldcert = db_base::fromIndex<pki_x509>(idx);
			if (!oldcert)
				continue;
			RenewalSpec spec;
			spec.predecessor = oldcert;
			spec.notBefore = dlg->notBefore->getDate();
			if (dlg->noWellDefinedExpDate->isChecked())
				spec.notAfter.setUndefined();
			else
				spec.notAfter = dlg->notAfter->getDate();
			spec.hashAlgo = oldcert->getDigest();
			spec.keepSerial = dlg->keepSerial->isChecked();
			specs << spec;
		}
		ServiceContext ctx = ServiceContext::localUser(
					ServiceContext::gui);
		for (pki_x509 *newcert : certs->renew(ctx, specs))
			certs->createSuccess(newcert);
		if (doRevoke) {
			foreach(idx, indexes) {
				oldcert = db_base::fromIndex<pki_x509>(idx);
				if (oldcert && !oldcert->isRevoked())
					certs->revoke(ctx, oldcert, r);
			}
		}

		// delete old certificates if requested
		if (doReplace) {
			QList<pki_base *> old;
			foreach(idx, indexes) {
				if (db_base::fromIndex<pki_x509>(idx))
					old << db_base::fromIndex(idx);
			}
			certs->deleteItems(ctx, old);
		}
	}
	catch (errorEx &err) {
		XCA_ERROR(err);
	}
	delete dlg;
	emit certs->columnsContentChanged();
}
