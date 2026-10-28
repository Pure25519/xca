/* vi: set sw=4 ts=4:
 *
 * Certificate signing requests without the GUI (BTD-32): the value object
 * that db_x509req::newRequest(const ServiceContext &, const RequestSpec &)
 * takes.
 *
 * Subject and extension inputs are the ones of IssuanceSpec, so the New
 * Request dialog fills the same ExtensionSpec as the New Certificate
 * dialog. NewX509 in request mode only fills this object.
 *
 * A spec holds a non-owning reference to a key of the open database.
 * Create one per call; nothing in here is shared between calls.
 */

#ifndef __REQUEST_H
#define __REQUEST_H

#include <QString>

#include "digest.h"
#include "issuance.h"
#include "pki_base.h"
#include "x509name.h"
#include "x509v3ext.h"

class pki_key;

class RequestSpec
{
  public:
	QString name{};             // internal name
	x509name subject{};
	pki_key *key{};             // private key that signs the request
	digest hashAlgo{};

	ExtensionSpec extensions{};
	/* Extensions that already exist, e.g. those of the certificate a
	 * request is made from; added after the built ones */
	extList copiedExtensions{};

	/* PKCS#9 attributes; empty: absent. The challenge password is
	 * never written to the audit log. */
	QString unstructuredName{};
	QString challengePassword{};

	QString comment{};
	QString templateName{};     // template the input came from, for the audit
	enum pki_source source{ generated };

	/* The requested extensions in the order the dialog built them.
	 * They are built in the context of a temporary self-signed
	 * certificate with the subject and the key of this spec, so that
	 * "hash" (subject key identifier) and DNS:copycn always refer to
	 * this request. Invalid (empty) ones are removed. */
	extList buildExtensions() const;
};

#endif
