/* vi: set sw=4 ts=4:
 *
 * Certificate profiles of bxc-pki (BTD-54): a profile document of
 * schemas/profile.schema.json (BTD-64) turned into an IssuanceSpec.
 *
 * The profile decides; the CSR contributes its key, its subject and its
 * SAN only. KU by key type, a fixed EKU, basicConstraints (cA=FALSE for
 * opcua and tls; cA and pathLen as a generic profile of schema v1.1 says,
 * BTD-167), SKI and AKI come from the profile, and so do the CSR policy of BTD-65 and
 * the OPC UA chain rules of BTD-55. A profile is selected by its id (EST
 * label, CMP alias, registration), never by the content of a CSR.
 *
 * Validity: validity.default from now, notBefore backdated by
 * validity.backdate for device clocks. The backdating is a default, not
 * a requested date, so it ends at the issuer's notBefore: a CA made an
 * hour ago issues from its own start, never refused as
 * issuer_not_yet_valid (BTD-55; boss decision 2026-10-29).
 *
 * Profile::fromJson() takes the document from anywhere: a file
 * (fromFile()), or the profile store of BTD-167. apply() neither writes
 * to the database nor draws a serial.
 *
 * Migration of XCA templates (fromTemplate(), BTD-167): a template
 * becomes a generic profile of schema v1.1 with id "xca-" plus its name
 * in lower case (other characters as "-"). basicConstraints, pathLen,
 * key usage (the same bits for RSA and EC keys), EKU and their
 * criticality are taken over; "DNS:copycn" becomes san.dns_from_cn; the
 * validity period becomes validity.default and .max without backdating.
 * SKI and AKI are always present. The profile takes the subject and the
 * SAN of the CSR (the template only with "copy extensions"), any key
 * type of the schema, SHA-256 (SHA-384 for P-384 CAs), and keeps the
 * order of the extensions as XCA builds them. Netscape extensions are not
 * migrated (bxc-pki profiles/README.md); droppedFromTemplate() names
 * them for the migration result and the audit entry. Refused, with the field named
 * (template_not_migratable): a fixed subject, a fixed SAN, name
 * constraints, issuer alternative name, CRL distribution points, AIA,
 * OCSP must-staple, advanced extensions, no basicConstraints, no key
 * usage, no SKI or AKI, EKU limits of BTD-54, midnight validity and the
 * undefined expiry date.
 */

#ifndef __PROFILE_H
#define __PROFILE_H

#include <QJsonObject>
#include <QString>
#include <QStringList>

#include <openssl/evp.h>

#include "issuance.h"
#include "x509name.h"

class pki_key;
class pki_x509;
class pki_x509req;
class TemplateSpec;

/* What the registration of a device or user knows */
class Registration
{
  public:
	QString applicationUri{};   // san.uri source registration
	QString organization{};     // for add_missing_o
	QString userName{};         // cn_source user
	QString httpsHost{};        // cn_source https-host
	/* key_source server: no CSR, subject and SAN come from here (SAN as
	 * an OpenSSL configuration value, e.g. "DNS:plc10, IP:10.0.0.10") */
	x509name subject{};
	QString subjectAltName{};
};

class Profile
{
	QJsonObject doc{};

  public:
	QString id{};
	QString family{};           // opcua, tls or generic (schema v1.1)
	QString keySource{};        // csr or server

	/* Throws serviceError invalid_profile naming the field */
	static Profile fromJson(const QJsonObject &doc);
	static Profile fromFile(const QString &path);

	/* The generic profile (schema v1.1) of an XCA template; throws
	 * serviceError template_not_migratable naming the field. */
	static QJsonObject fromTemplate(const TemplateSpec &t,
			const QString &id = QString());
	/* What fromTemplate() leaves out because a profile has no place for
	 * it: the Netscape values the template holds (nsCertType,
	 * nsComment, ...), named in the migration result and its audit
	 * entry, never dropped silently */
	static QStringList droppedFromTemplate(const TemplateSpec &t);

	/* The key type as the profile names it: rsa-2048, ec-p256, ... */
	static QString keyType(const EVP_PKEY *pkey);

	/* request for key_source csr, key for key_source server; the
	 * signer is the issuing CA. Throws serviceError for anything the
	 * profile does not allow (key type, subject, SAN counts). */
	IssuanceSpec apply(pki_x509req *request, pki_key *key,
			const Registration &reg, pki_x509 *signer) const;
};

#endif
