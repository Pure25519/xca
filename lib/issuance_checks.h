/* vi: set sw=4 ts=4:
 *
 * The checks before every signature of db_x509::newCert() (BTD-55):
 * the spec itself, the issuer chain, the CSR and the certificate that is
 * about to be signed. Each failed check throws a serviceError whose code
 * names the rule and whose message names the value. They run before a
 * serial is drawn, so a rejection consumes nothing and stores nothing.
 *
 * Order in db_x509::issue(): spec(), issuers(), request(), then the
 * extensions are built, certificate() and names(), then the serial and
 * the signature.
 */

#ifndef __ISSUANCE_CHECKS_H
#define __ISSUANCE_CHECKS_H

#include <QList>

class ExtensionSpec;
class IssuanceSpec;
class pki_key;
class pki_x509;

namespace IssuanceChecks
{
	/* The issuer and its issuers up to the self-signed root, nearest
	 * first; empty for a self-signed certificate. A broken or looping
	 * chain ends where it breaks. */
	QList<const pki_x509 *> issuerChain(const pki_x509 *signer);

	/* pathLen of a CA: empty is absent, otherwise a decimal number of
	 * 0 or more; also for requests (db_x509req) */
	void pathLength(const ExtensionSpec &ext);

	/* pathLength() and the signature digest (never MD5, RIPEMD-160 or
	 * SHA-1) */
	void spec(const IssuanceSpec &spec);

	/* The issuer is a v3 CA with keyCertSign, valid now and from the
	 * start of the new certificate, signkey belongs to it, and no CA
	 * of the chain forbids another CA below it (RFC 5280 4.2.1.9) */
	void issuers(const IssuanceSpec &spec,
			const QList<const pki_x509 *> &chain, pki_key *signkey);

	/* Proof of possession: the CSR signature verifies */
	void request(const IssuanceSpec &spec);

	/* The certificate to be signed: one instance per extension, and the
	 * OPC UA chain rules (PLAN.md 14.4) when the spec asks for them */
	void certificate(const IssuanceSpec &spec, const pki_x509 *cert,
			const QList<const pki_x509 *> &chain);

	/* Hook for the name rules over the whole chain: name constraints
	 * of every CA up to the root, the name policy and the EKU subset
	 * rule (BTD-167). Nothing is checked yet. */
	void names(const IssuanceSpec &spec, const pki_x509 *cert,
			const QList<const pki_x509 *> &chain);
}

#endif
