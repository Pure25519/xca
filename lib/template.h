/* vi: set sw=4 ts=4:
 *
 * Templates without the GUI (BTD-35): the value object that
 * db_temp::newTemplate() and db_temp::updateTemplate() take, and its
 * conversion to and from an IssuanceSpec preset.
 *
 * A template is a preset of the New Certificate dialog: subject,
 * extensions and a validity period relative to the issuance date.
 * TemplateSpec holds the same values as typed members; pki_temp keeps
 * its stored form (the settings map of TMPL_VERSION). The dialog fills
 * and reads its widgets through TemplateSpec, so the mapping between
 * the stored settings and the extensions exists once, here.
 *
 * Migration (BTD-54): what a CSR adds per extension is stored in the
 * settings reqSan, reqKu, reqEku ("", "template", "request", "merge")
 * and ekuAllowed, ekuDefault (comma lists). A template stored before
 * has none of them; absent or empty means merge_legacy and no EKU
 * limit, which is exactly what XCA always did: with "copy extensions
 * from the request" a CSR extension is added when the template has
 * none of that kind, otherwise the template alone decides.
 */

#ifndef __TEMPLATE_H
#define __TEMPLATE_H

#include <QString>
#include <QStringList>

#include "asn1time.h"
#include "issuance.h"
#include "pki_base.h"
#include "x509name.h"

class pki_temp;
class pki_x509super;
class RequestSpec;

class TemplateSpec
{
  public:
	/* The units of the dialog's validity combo box, setting "validM" */
	enum validityUnit { days, months, years };

	QString name{};
	QString comment{};
	x509name subject{};
	ExtensionSpec extensions{};   // extensions.netscape is not stored:
	                              // the setting "disable_netscape" decides

	int validity{ 365 };
	enum validityUnit unit{ days };
	bool midnight{};              // from 00:00:00 to 23:59:59 UTC
	bool noWellDefinedExpDate{};  // notAfter 99991231235959Z

	enum pki_source source{ generated };

	/* The key usage names in the order of the stored bit mask
	 * (setting "keyUse") and of the dialog's list */
	static const QStringList keyUsageNames;
	/* The Netscape certificate types in the order of the stored bit
	 * mask (setting "nsCertType") and of the dialog's list */
	static const QStringList nsCertTypeNames;

	/* The values of a stored, predefined or read template */
	static TemplateSpec fromTemplate(const pki_temp *temp);
	/* Writes name, comment and all settings into temp */
	void toTemplate(pki_temp *temp) const;

	/* The template the "Transform > Template" action makes from a
	 * certificate or request; *notPorted receives the extensions the
	 * template cannot hold */
	static TemplateSpec fromObject(pki_x509super *obj,
					extList *notPorted = nullptr);

	/* The validity period applied to an issuance date, as the dialog's
	 * "Apply" does: notBefore is now without seconds or, with midnight,
	 * 00:00:00 UTC of today; notAfter adds the period (one day less and
	 * 23:59:59 UTC with midnight) or is undefined */
	void validityFrom(const a1time &now, a1time *notBefore,
				a1time *notAfter) const;

	/* Apply all: subject, extensions and validity into spec; spec's
	 * key, request, signer, hash and name stay. templateName is set
	 * to this template's name for the audit entry. */
	void applyTo(IssuanceSpec &spec, const a1time &now = a1time()) const;
	/* The request dialog: subject and extensions */
	void applyTo(RequestSpec &spec) const;
	/* A template from the values of an issuance: subject, extensions
	 * and the validity period in days (or undefined) */
	static TemplateSpec fromIssuanceSpec(const IssuanceSpec &spec);
};

#endif
