/* vi: set sw=4 ts=4:
 *
 * Templates without the GUI (BTD-35), see template.h
 */

#include "template.h"
#include "oid.h"
#include "pki_temp.h"
#include "pki_x509super.h"
#include "request.h"
#include "settings.h"

#include <QRegularExpression>

const QStringList TemplateSpec::keyUsageNames {
	"digitalSignature", "nonRepudiation", "keyEncipherment",
	"dataEncipherment", "keyAgreement", "keyCertSign",
	"cRLSign", "encipherOnly", "decipherOnly"
};

const QStringList TemplateSpec::nsCertTypeNames {
	"client", "server",  "email", "objsign",
	"sslCA",  "emailCA", "objCA"
};

static QStringList fromMask(int mask, const QStringList &names)
{
	QStringList list;
	for (int i = 0; i < names.size(); i++) {
		if (mask & (1 << i))
			list << names[i];
	}
	return list;
}

static int toMask(const QStringList &list, const QStringList &names)
{
	int mask = 0;
	for (int i = 0; i < names.size(); i++) {
		if (list.contains(names[i]))
			mask |= 1 << i;
	}
	return mask;
}

/* The stored short names in the order of the dialog's list (eku.txt),
 * which is the order the dialog builds the extension in; names the
 * list does not know follow in their stored order */
static QStringList extKeyUsageList(const QString &stored)
{
	QStringList names, known, unknown;

	foreach(QString s, stored.split(QRegularExpression(",\\s*"),
					Qt::SkipEmptyParts))
		names << s.trimmed();
	foreach(int nid, extkeyuse_nid) {
		QString sn = OBJ_nid2sn(nid);
		if (names.contains(sn))
			known << sn;
	}
	foreach(QString sn, names) {
		if (!known.contains(sn) && !unknown.contains(sn))
			unknown << sn;
	}
	return known + unknown;
}

TemplateSpec TemplateSpec::fromTemplate(const pki_temp *temp)
{
	TemplateSpec t;
	ExtensionSpec &e = t.extensions;

	if (!temp)
		return t;

	t.name = temp->getIntName();
	t.comment = temp->getComment();
	t.subject = temp->getSubject();
	t.source = temp->pkiSource;

	switch (temp->getSettingInt("ca")) {
	case 1: e.basicCA = ExtensionSpec::bc_ca; break;
	case 2: e.basicCA = ExtensionSpec::bc_not_ca; break;
	default: e.basicCA = ExtensionSpec::bc_absent; break;
	}
	e.basicCritical = temp->getSettingInt("bcCritical");
	e.pathLen = temp->getSetting("basicPath");
	e.subjectKeyId = temp->getSettingInt("subKey");
	e.authorityKeyId = temp->getSettingInt("authKey");
	e.keyUsage = fromMask(temp->getSettingInt("keyUse"), keyUsageNames);
	e.keyUsageCritical = temp->getSettingInt("kuCritical");
	e.extKeyUsage = extKeyUsageList(temp->getSetting("eKeyUse"));
	e.extKeyUsageCritical = temp->getSettingInt("ekuCritical");
	e.nameConstraints = temp->getSetting("nameCons");
	e.subjectAltName = temp->getSetting("subAltName");
	e.issuerAltName = temp->getSetting("issAltName");
	e.crlDistPoints = temp->getSetting("crlDist");
	e.authInfoAccess = temp->getSetting("authInfAcc");
	e.ocspMustStaple = temp->getSettingInt("OCSPstaple");
	e.advanced = temp->getSetting("adv_ext");

	e.netscape = !Settings["disable_netscape"];
	e.nsCertType = fromMask(temp->getSettingInt("nsCertType"),
				nsCertTypeNames);
	e.nsBaseUrl = temp->getSetting("nsBaseUrl");
	e.nsRevocationUrl = temp->getSetting("nsRevocationUrl");
	e.nsCARevocationUrl = temp->getSetting("nsCARevocationUrl");
	e.nsRenewalUrl = temp->getSetting("nsRenewalUrl");
	e.nsCaPolicyUrl = temp->getSetting("nsCaPolicyUrl");
	e.nsSslServerName = temp->getSetting("nsSslServerName");
	e.nsComment = temp->getSetting("nsComment");

	t.validity = temp->getSettingInt("validN");
	switch (temp->getSettingInt("validM")) {
	case 1: t.unit = months; break;
	case 2: t.unit = years; break;
	default: t.unit = days; break;
	}
	t.midnight = temp->getSettingInt("validMidn");
	t.noWellDefinedExpDate = temp->getSettingInt("noWellDefinedExpDate");
	return t;
}

/* The values NewX509::toTemplate() always wrote */
void TemplateSpec::toTemplate(pki_temp *temp) const
{
	const ExtensionSpec &e = extensions;

	if (!temp)
		return;
	temp->setIntName(name);
	temp->setComment(comment);
	temp->setSubject(subject);

	temp->setSetting("ca", e.basicCA == ExtensionSpec::bc_ca ? 1 :
			e.basicCA == ExtensionSpec::bc_not_ca ? 2 : 0);
	temp->setSetting("bcCritical", e.basicCritical);
	/* as given: toInt() made 0 of every non-number (BTD-55) */
	temp->setSetting("basicPath", e.pathLen);
	temp->setSetting("subKey", e.subjectKeyId);
	temp->setSetting("authKey", e.authorityKeyId);
	temp->setSetting("keyUse", toMask(e.keyUsage, keyUsageNames));
	temp->setSetting("kuCritical", e.keyUsageCritical);
	temp->setSetting("eKeyUse", e.extKeyUsage.join(", "));
	temp->setSetting("ekuCritical", e.extKeyUsageCritical);
	temp->setSetting("nameCons", e.nameConstraints);
	temp->setSetting("subAltName", e.subjectAltName);
	temp->setSetting("issAltName", e.issuerAltName);
	temp->setSetting("crlDist", e.crlDistPoints);
	temp->setSetting("authInfAcc", e.authInfoAccess);
	temp->setSetting("OCSPstaple", e.ocspMustStaple);
	temp->setSetting("adv_ext", e.advanced);

	temp->setSetting("nsCertType", toMask(e.nsCertType, nsCertTypeNames));
	temp->setSetting("nsBaseUrl", e.nsBaseUrl);
	temp->setSetting("nsRevocationUrl", e.nsRevocationUrl);
	temp->setSetting("nsCARevocationUrl", e.nsCARevocationUrl);
	temp->setSetting("nsRenewalUrl", e.nsRenewalUrl);
	temp->setSetting("nsCaPolicyUrl", e.nsCaPolicyUrl);
	temp->setSetting("nsSslServerName", e.nsSslServerName);
	temp->setSetting("nsComment", e.nsComment);

	temp->setSetting("validN", validity);
	temp->setSetting("validM", (int)unit);
	temp->setSetting("validMidn", midnight);
	temp->setSetting("noWellDefinedExpDate", noWellDefinedExpDate);
}

TemplateSpec TemplateSpec::fromObject(pki_x509super *obj, extList *notPorted)
{
	pki_temp temp;
	extList el;

	if (obj) {
		temp.setIntName(obj->getIntName());
		el = temp.fromCert(obj);
	}
	if (notPorted)
		*notPorted = el;
	TemplateSpec t = fromTemplate(&temp);
	t.source = transformed;
	return t;
}

void TemplateSpec::validityFrom(const a1time &now, a1time *notBefore,
				a1time *notAfter) const
{
	QDateTime start = now.toUTC();

	if (midnight) {
		start.setTime(QTime(0, 0, 0));
	} else {
		QTime t = start.time();
		start.setTime(QTime(t.hour(), t.minute(), 0));
	}
	*notBefore = a1time(start);

	if (noWellDefinedExpDate) {
		notAfter->setUndefined();
		return;
	}
	QDateTime end = start;
	switch (unit) {
	case days: end = end.addDays(validity); break;
	case months: end = end.addMonths(validity); break;
	case years: end = end.addYears(validity); break;
	}
	if (midnight) {
		end = end.addDays(-1);
		end.setTime(QTime(23, 59, 59));
	}
	*notAfter = a1time(end);
}

void TemplateSpec::applyTo(IssuanceSpec &spec, const a1time &now) const
{
	spec.subject = subject;
	spec.extensions = extensions;
	validityFrom(now, &spec.notBefore, &spec.notAfter);
	spec.templateName = name;
}

void TemplateSpec::applyTo(RequestSpec &spec) const
{
	spec.subject = subject;
	spec.extensions = extensions;
	spec.templateName = name;
}

TemplateSpec TemplateSpec::fromIssuanceSpec(const IssuanceSpec &spec)
{
	TemplateSpec t;

	t.name = spec.templateName;
	t.subject = spec.subject;
	t.extensions = spec.extensions;
	if (spec.notAfter.isUndefined()) {
		t.noWellDefinedExpDate = true;
	} else {
		t.validity = spec.notBefore.daysTo(spec.notAfter);
		t.midnight = spec.notBefore.toPlain().endsWith("000000Z") &&
				spec.notAfter.toPlain().endsWith("235959Z");
		if (t.midnight)
			t.validity++;
	}
	t.unit = days;
	return t;
}
