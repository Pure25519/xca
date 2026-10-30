/* vi: set sw=4 ts=4:
 *
 * Name policies of bxc-pki (BTD-167): a document of
 * schemas/policy.schema.json checked against the certificate to be signed,
 * after the profile built it and before the serial and the signature
 * (IssuanceChecks::names()), so that GUI, CLI, REST, EST and CMP share it.
 *
 * Per name form (dNSName, iPAddress, URI, rfc822Name, subject DN
 * attribute): without allow rules every name passes the allow step, with
 * allow rules a name must match one (an empty list admits none); a name
 * matching a deny rule is refused in any case. A name is never rewritten
 * (EJBCA #803). DNS names are compared in lower case; a name without a dot
 * matches only a single-label rule (step-ca #2318). The syntax of the
 * names themselves (empty label, trailing dot, non-ASCII, invalid A-label)
 * is checked for every issuance, with or without a policy.
 *
 * Further rules: uniqueness with a status filter (EJBCA D#1084), a minimum
 * content (extensions present, DN attributes) and the strict issuer key
 * usage. Each violation is a serviceError naming the policy, the rule and
 * the value.
 */

#ifndef __POLICY_H
#define __POLICY_H

#include <QJsonObject>
#include <QList>
#include <QString>

class IssuanceSpec;
class pki_x509;

class Policy
{
	QJsonObject doc{};

  public:
	QString id{};

	/* Throws serviceError invalid_policy naming the field; the rest of
	 * the schema is checked by the schema test of bxc-pki */
	static Policy fromJson(const QJsonObject &doc);
	static Policy fromFile(const QString &path);
	QJsonObject document() const
	{
		return doc;
	}

	/* Throws serviceError policy_name_not_allowed, policy_name_denied,
	 * policy_no_extensions, policy_missing_dn_attribute,
	 * policy_issuer_key_usage or policy_not_unique */
	void check(const IssuanceSpec &spec, const pki_x509 *cert,
			const QList<const pki_x509 *> &chain) const;
};

#endif
