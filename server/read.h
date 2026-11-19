/* vi: set sw=4 ts=4:
 *
 * The read resources of xca-server (BTD-156): jobs for the DB worker only
 * (worker.h), one per GET operation of roles.json.
 *
 * CA scope (BTD-311, decisions of 2026-11-19): a restricted identity sees
 *   a certificate      issued by a CA of its scope, or the CA certificate
 *                      of such a CA itself;
 *   a CRL              issued by a CA of its scope;
 *   a key              used by a certificate it sees;
 *   a request          whose key a certificate it sees uses (the request
 *                      a certificate was issued from);
 *   a profile, policy  unbound (no assignment to a CA, no certificate
 *                      issued under it), or bound to a CA of its scope;
 *   the index          the entries of the certificates it sees.
 * An object outside the scope is unknown_reference (404), so its existence
 * does not leak. Tokens and the audit log belong to no CA and are not
 * filtered: routes.cpp refuses them for a restricted identity
 * (ca_scope_unfiltered).
 *
 * Lists are ordered by item id and paged by keyset: limit (1-1000) items
 * after the item id after; next is the item id to continue after, or null
 * at the end.
 */

#ifndef __XCA_SERVER_READ_H
#define __XCA_SERVER_READ_H

#include <QJsonObject>
#include <QString>

#include "session.h"

namespace xcaserver {

/* listObjects: the item list (kind items) of a collection (keys,
 * requests, certificates, crls) with next */
QJsonObject listObjectsJob(const QString &collection, const CaScope &scope,
		qint64 after, int limit);
/* getObject: the document of bxc-pki show; unknown_reference for an item
 * that does not exist, is deleted, is outside the scope or belongs to
 * another collection (wrong_object_type for the last one) */
QJsonObject getObjectJob(const QString &collection, qint64 id,
		const CaScope &scope);
/* listProfiles, listPolicies: {"documents": [...]}, the newest version of
 * every name the scope sees */
QJsonObject listDocumentsJob(const QString &kind, const CaScope &scope);
/* getProfile, getPolicy: the newest version; document_not_found also for
 * one outside the scope */
QJsonObject getDocumentJob(const QString &kind, const QString &name,
		const CaScope &scope);
/* exportIndex: the list document of kind index or hierarchy */
QJsonObject indexJob(bool hierarchy, const CaScope &scope);
/* listTokens: {"slots": [...]}, the slots of the loaded PKCS#11 libraries
 * (settings pkcs11path) */
QJsonObject tokensJob();
/* verifyAudit: {"report": <the canonical JSON of --audit-verify>} */
QJsonObject verifyAuditJob();
/* exportAudit: {"lines": <JSON Lines>, "unanchored": n, "first", "last",
 * "count"}. Never signs a checkpoint (GET is safe; the export is that of
 * --audit-export without a password source), then writes audit.export
 * with the actor, the range and the count. */
QJsonObject exportAuditJob(const QString &actor, qint64 after);

}

#endif
