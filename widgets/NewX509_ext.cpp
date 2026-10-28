/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "NewX509.h"
#include <QCheckBox>
#include <QComboBox>
#include <QRadioButton>
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>

#include "MainWindow.h"
#include "lib/x509v3ext.h"
#include "lib/pki_temp.h"
#include "lib/pki_x509req.h"
#include "lib/settings.h"
#include "lib/func.h"

ExtensionSpec NewX509::getExtensionSpec()
{
	static const QString keyusage[] = {
		"digitalSignature", "nonRepudiation", "keyEncipherment",
		"dataEncipherment", "keyAgreement", "keyCertSign",
		"cRLSign", "encipherOnly", "decipherOnly"
	};
	static const QString certTypeList[] = {
		"client", "server",  "email", "objsign",
		"sslCA",  "emailCA", "objCA" };
	ExtensionSpec e;
	int i, rows;

	switch (basicCA->currentIndex()) {
	case 1: e.basicCA = ExtensionSpec::bc_ca; break;
	case 2: e.basicCA = ExtensionSpec::bc_not_ca; break;
	default: e.basicCA = ExtensionSpec::bc_absent; break;
	}
	e.basicCritical = bcCritical->isChecked();
	e.pathLen = basicPath->text();
	e.subjectKeyId = subKey->isChecked();
	e.authorityKeyId = authKey->isChecked() && authKey->isEnabled();

	rows = keyUsage->count();
	for (i=0; i<rows; i++) {
		if (keyUsage->item(i)->isSelected())
			e.keyUsage << keyusage[i];
	}
	e.keyUsageCritical = kuCritical->isChecked();
	rows = ekeyUsage->count();
	for (i=0; i<rows; i++) {
		if (ekeyUsage->item(i)->isSelected())
			e.extKeyUsage << QString(OBJ_nid2sn(extkeyuse_nid[i]));
	}
	e.extKeyUsageCritical = ekuCritical->isChecked();

	e.nameConstraints = nameCons->text();
	e.subjectAltName = subAltName->text();
	e.issuerAltName = issAltName->text();
	e.crlDistPoints = crlDist->text();
	e.authInfoAccess = authInfAcc->text();
	e.ocspMustStaple = OCSPstaple->isChecked();

	e.advanced = nconf_data->isReadOnly() ? v3ext_backup :
					nconf_data->toPlainText();

	e.netscape = !Settings["disable_netscape"];
	rows = nsCertType->count();
	for (i=0; i<rows; i++) {
		if (nsCertType->item(i)->isSelected())
			e.nsCertType << certTypeList[i];
	}
	e.nsBaseUrl = nsBaseUrl->text();
	e.nsRevocationUrl = nsRevocationUrl->text();
	e.nsCARevocationUrl = nsCARevocationUrl->text();
	e.nsRenewalUrl = nsRenewalUrl->text();
	e.nsCaPolicyUrl = nsCaPolicyUrl->text();
	e.nsSslServerName = nsSslServerName->text();
	e.nsComment = nsComment->text();
	return e;
}

IssuanceSpec NewX509::getIssuanceSpec()
{
	IssuanceSpec spec;

	if (fromReqCB->isChecked()) {
		spec.request = getSelectedReq();
		if (!spec.request)
			return spec;
		spec.name = spec.request->getIntName();
	} else {
		spec.key = getSelectedKey();
		spec.name = description->text();
	}
	spec.subject = getX509name();
	if (foreignSignRB->isChecked())
		spec.signer = getSelectedSigner();
	spec.notBefore = notBefore->getDate();
	if (noWellDefinedExpDate->isChecked())
		spec.notAfter.setUndefined();
	else
		spec.notAfter = notAfter->getDate();
	spec.hashAlgo = hashAlgo->current();
	spec.extensions = getExtensionSpec();
	spec.copyRequestExtensions = fromReqCB->isChecked() &&
					copyReqExtCB->isChecked();
	spec.comment = comment->toPlainText();
	pki_temp *temp = currentTemplate();
	if (temp)
		spec.templateName = temp->getIntName();
	spec.source = getPkiSource();
	return spec;
}

/* The single extensions for the validation view and the check icons */
x509v3ext NewX509::getBasicConstraints()
{
	return getExtensionSpec().basicConstraintsExt(&ext_ctx);
}

x509v3ext NewX509::getSubKeyIdent()
{
	return getExtensionSpec().subjectKeyIdExt(&ext_ctx);
}

x509v3ext NewX509::getOCSPstaple()
{
	return getExtensionSpec().ocspMustStapleExt(&ext_ctx);
}

x509v3ext NewX509::getAuthKeyIdent()
{
	return getExtensionSpec().authorityKeyIdExt(&ext_ctx,
					selfSignRB->isChecked());
}

x509v3ext NewX509::getKeyUsage()
{
	return getExtensionSpec().keyUsageExt(&ext_ctx);
}

x509v3ext NewX509::getEkeyUsage()
{
	return getExtensionSpec().extKeyUsageExt(&ext_ctx);
}

x509v3ext NewX509::getNameConstraints()
{
	return getExtensionSpec().nameConstraintsExt(&ext_ctx);
}

x509v3ext NewX509::getSubAltName()
{
	return getExtensionSpec().subjectAltNameExt(&ext_ctx, pt == x509_req);
}

x509v3ext NewX509::getIssAltName()
{
	return getExtensionSpec().issuerAltNameExt(&ext_ctx, pt == x509_req);
}

x509v3ext NewX509::getCrlDist()
{
	return getExtensionSpec().crlDistPointsExt(&ext_ctx);
}

x509v3ext NewX509::getAuthInfAcc()
{
	return getExtensionSpec().authInfoAccessExt(&ext_ctx);
}

extList NewX509::getAdvanced()
{
	return getExtensionSpec().advancedExts(&ext_ctx);
}

extList NewX509::getGuiExt()
{
	return getExtensionSpec().standardExts(&ext_ctx,
				selfSignRB->isChecked(), pt == x509_req);
}

extList NewX509::getAllExt()
{
	return getExtensionSpec().build(&ext_ctx,
				selfSignRB->isChecked(), pt == x509_req);
}

extList NewX509::getNetscapeExt()
{
	return getExtensionSpec().netscapeExts(&ext_ctx);
}

void NewX509::initCtx(pki_x509 *subj, pki_x509 *iss, pki_x509req *req)
{
	X509 *s = NULL, *s1 = NULL;
	X509_REQ *r = NULL;

	if (subj) s1 = subj->getCert();
	if (iss) s = iss->getCert();
	if (req) r = req->getReq();

	X509V3_set_ctx(&ext_ctx, s, s1, r, NULL, 0);
}

extList NewX509::getExtDuplicates(const extList &el)
{
	int i, start, cnt, n1, n;
	x509v3ext e;
	extList el_dup;
	QString olist;

	cnt = el.size();
	for (start=0; start < cnt; start++) {
		n1 = el[start].nid();
		for (i = start+1; i<cnt; i++) {
			e = el[i];
			n = e.nid();
			if (n1 == n) {
				// DUPLICATE
				if (el_dup.idxByNid(n1) ==-1)
					el_dup << e;

			}
		}
	}
	return el_dup;
}
