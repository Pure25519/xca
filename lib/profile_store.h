/* vi: set sw=4 ts=4:
 *
 * Profiles and name policies as stored, versioned, audited documents
 * (BTD-167), in the tables profiles and policies of bxc_schema 4.
 *
 * Every document has a name (its id), a version and the JSON text. An
 * import or create makes version 1, an update the next version; the
 * newest version that is not retired is the one issuance uses. A version
 * that issued a certificate is never deleted (profile_in_use); retire
 * takes a name out of use instead. Each change writes an audit entry
 * profile.* or policy.* with the channel and actor of the ServiceContext.
 * Documents are checked with Profile::fromJson() or Policy::fromJson()
 * before they are stored.
 *
 * A CA lists the profiles and policies it may use, a profile the
 * policies that apply to it (table assignments). issue() selects the
 * profile by its name, never by CSR content (BTD-64), checks the
 * assignment, applies the profile (BTD-54) with the policies of the CA
 * and of the profile, and records profile version and policies of the
 * certificate (table issued_profiles).
 *
 * Kinds are "profile" and "policy". Errors are serviceError:
 * invalid_profile, invalid_policy, invalid_kind, document_exists,
 * document_not_found, profile_in_use, profile_not_assigned,
 * profile_signature_mismatch, already_assigned, not_assigned.
 */

#ifndef __PROFILE_STORE_H
#define __PROFILE_STORE_H

#include <QJsonObject>
#include <QList>
#include <QString>
#include <QStringList>

class pki_key;
class pki_x509;
class pki_x509req;
class Registration;
class ServiceContext;

namespace ProfileStore
{
	class Document
	{
	  public:
		QString kind{};
		QString name{};
		int version{};
		QJsonObject document{};
		QString created{};
		bool retired{};
	};

	Document create(const ServiceContext &ctx, const QString &kind,
			const QJsonObject &document);
	Document importFile(const ServiceContext &ctx, const QString &kind,
			const QString &path);
	/* The next version of the document with the same id */
	Document update(const ServiceContext &ctx, const QString &kind,
			const QJsonObject &document);
	void retire(const ServiceContext &ctx, const QString &kind,
			const QString &name);
	void remove(const ServiceContext &ctx, const QString &kind,
			const QString &name, int version);

	/* The newest version of every name, retired ones included */
	QList<Document> list(const QString &kind);
	/* version 0: the newest one */
	Document show(const QString &kind, const QString &name,
			int version = 0);

	/* A profile is refused when its signature section has nothing for
	 * the key of the CA (OpenXPKI #960): an RSA-only profile on an EC
	 * CA, a curve the profile names no hash for. Keys without a digest
	 * (Ed25519, ML-DSA) sign as BTD-164 decided. */
	void assign(const ServiceContext &ctx, pki_x509 *ca,
			const QString &kind, const QString &name);
	void unassign(const ServiceContext &ctx, pki_x509 *ca,
			const QString &kind, const QString &name);
	void assignToProfile(const ServiceContext &ctx, const QString &profile,
			const QString &policy);
	QStringList assigned(const pki_x509 *ca, const QString &kind);

	pki_x509 *issue(const ServiceContext &ctx, pki_x509 *ca,
			const QString &profile, pki_x509req *request,
			pki_key *key, const Registration &reg);
}

#endif
