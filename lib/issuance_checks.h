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

class AuditParams;
class ExtensionSpec;
class IssuanceSpec;
class digest;
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

	/* The issuer is a v3 CA, its key usage (if it has one) allows
	 * keyCertSign, it is valid now and from the start of the new
	 * certificate, signkey belongs to it, and no CA of the chain
	 * forbids another CA below it (RFC 5280 4.2.1.9). An issuer without
	 * key usage may sign (RFC 5280 6.1.4 (n)); params get the warning
	 * issuer_without_key_usage (boss decision 2026-10-29; the strict
	 * variant is a policy option of BTD-167). */
	void issuers(const IssuanceSpec &spec,
			const QList<const pki_x509 *> &chain, pki_key *signkey,
			AuditParams &params);

	/* spec(), issuers() and request() for a dialog that wants to
	 * refuse before it closes (NewX509::validateAndAccept()); the same
	 * checks run again in db_x509::newCert() */
	void preflight(const IssuanceSpec &spec, AuditParams &params);

	/* The CSR (BTD-65): its signature digest (never MD5, SHA-1 by
	 * CsrPolicy::csrSha1), the proof of possession, keyCertSign or
	 * cA=TRUE in a leaf request, forbidden subject characters and the
	 * ApplicationUri. Writes csr_signature_algorithm and, for an
	 * accepted SHA-1 signature, warning=csr_sha1_accepted. */
	void request(const IssuanceSpec &spec, AuditParams &params);

	/* The issuer of a CRL (BTD-188), before the CRL number and any
	 * write: no insecure hash (signature_hash_not_allowed), version 3
	 * and cA (issuer_v1, issuer_not_ca), cRLSign when it has key usage
	 * (issuer_no_crlsign; without key usage warning
	 * issuer_without_key_usage, RFC 5280 6.1.4 (n) as for keyCertSign),
	 * valid now (issuer_expired, issuer_not_yet_valid), signkey its key
	 * (issuer_key_mismatch). The same codes as for certificates. */
	void crlIssuer(const pki_x509 *ca, pki_key *signkey,
			const digest &hashAlgo, AuditParams &params);

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
