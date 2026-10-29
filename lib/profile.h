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

	/* The key type as the profile names it: rsa-2048, ec-p256, ... */
	static QString keyType(const EVP_PKEY *pkey);

	/* request for key_source csr, key for key_source server; the
	 * signer is the issuing CA. Throws serviceError for anything the
	 * profile does not allow (key type, subject, SAN counts). */
	IssuanceSpec apply(pki_x509req *request, pki_key *key,
			const Registration &reg, pki_x509 *signer) const;
};

#endif
