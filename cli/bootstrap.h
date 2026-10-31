/* vi: set sw=4 ts=4:
 *
 * bxc-pki bootstrap (BTD-166, bxc-pki PLAN.md 8.2): the bootstrap file
 * as the strict reader (bootstrap_reader.cpp) gives it to the command
 * (bootstrap.cpp). See cli/README.md, section bootstrap.
 */

#ifndef __BXC_PKI_BOOTSTRAP_H
#define __BXC_PKI_BOOTSTRAP_H

#include <QJsonArray>
#include <QJsonObject>
#include <QJsonValue>
#include <QList>
#include <QPair>
#include <QString>
#include <QStringList>

#include "lib/crl_policy.h"
#include "cli.h"

namespace bxcpki {

/* $id of bxc-pki schemas/bootstrap.schema.json, the only accepted value
 * of the member schema */
constexpr char bootstrapSchemaId[] = "urn:bxc-pki:schema:bootstrap:v1";

/* A secret field: its JSON pointer and the reference (env:, file:,
 * op://); never the secret. An empty pointer: the field is absent. */
class SecretField
{
  public:
	QString pointer{};
	QString value{};
	bool isSet() const
	{
		return !pointer.isEmpty();
	}
};

/* One entry of cas, checked; values as the file gives them */
class CaDef
{
  public:
	int index{};
	QString pointer{};              // /cas/<index> in the file
	QString id{}, parent{}, key{}, cn{}, hash{}, rsaPadding{};
	QString validity{}, notBefore{}, notAfter{};
	/* issued_with: the profile the CA certificate is issued with,
	 * recorded and compared, not applied (cli/README.md); profiles,
	 * policies: assigned to the CA (ProfileStore::assign) */
	QString issuedWith{};
	QStringList profiles{}, policies{};
	bool external{};                // parent "external"
	QString skipReason{};           // not set up in this phase
	QJsonObject subject{};          // O, OU, C, L, ST with cn
	QJsonValue dn{};                // RFC 4514 string or RDN list
	int pathLen{ -1 };              // -1: absent
	QJsonObject nameConstraints{};  // with critical (default true)
	QStringList keyUsage{};         // contentCommitment normalised
	SecretField keyPassword{};
	CrlPolicy crl{};                // the defaults with the file's values
	QStringList distributionPoints{};
};

/* One profile or policy: from a file, a directory or inline */
class DocDef
{
  public:
	QString kind{};                 // profile, policy
	QString pointer{};              // /profiles/<i> or /policies/<i>
	QString id{};
	QString source{};               // the relative path, or "inline"
	QJsonObject doc{};
};

class FileDef
{
  public:
	QString path{}, dir{}, sha256{}, schema{};
	QString dbType{}, dbPath{}, dbHost{}, dbName{}, dbUser{};
	int dbPort{};
	SecretField dbPassword{}, dbKeyPassword{};
	QList<CaDef> cas{};             // parents before their children
	QList<DocDef> docs{};           // profiles, then policies
	/* elements not set up in this phase: pointer and reason */
	QList<QPair<QString, QString> > skipped{};

	const CaDef *ca(const QString &id) const;
};

/* Reads and checks the file; throws serviceError invalid_bootstrap_file
 * (or invalid_validity, invalid_value, invalid_uri for a value the
 * schema takes but the fork does not) with the JSON pointer in front of
 * the detail */
FileDef readBootstrapFile(const QString &path);

/* JSON pointers (RFC 6901) and errors naming them */
QString jsonMember(const QString &ptr, const QString &key);
QString jsonItem(const QString &ptr, int i);
/* "/" for the document itself, whose RFC 6901 pointer is empty */
QString shownPointer(const QString &ptr);
/* err with "<pointer>: " in front of its detail; the code of err (a
 * secret error is missing_password) unless code is given */
serviceError located(const QString &ptr, const errorEx &err,
		const QString &code = QString());

} // namespace bxcpki

#endif
