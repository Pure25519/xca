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
#include <QString>
#include <QStringList>

#include <openssl/types.h>

class AuditParams;
class ExtensionSpec;
class IssuanceSpec;
class pki_key;
class pki_x509;

namespace IssuanceChecks
{
	/* The key usage bits a subject key of this type may carry (BTD-195;
	 * RFC 5480 3, RFC 8410 5, RFC 9881), one table for every issuance
	 * and for Profile::apply(): RSA all but keyAgreement, encipherOnly,
	 * decipherOnly; EC no keyEncipherment, dataEncipherment; Ed25519,
	 * Ed448, ML-DSA, SLH-DSA and DSA only digitalSignature,
	 * nonRepudiation, keyCertSign, cRLSign; X25519 and X448 only
	 * keyAgreement, encipherOnly, decipherOnly. *keyType receives the
	 * name of the family. An unknown key type: every bit. */
	QStringList keyUsageAllowed(const EVP_PKEY *key, QString *keyType);
	/* Throws key_usage_not_for_key_type for the first of bits a key of
	 * this type may not carry; source names where the bit comes from */
	void keyUsageFits(const EVP_PKEY *key, const QStringList &bits,
			const QString &source);

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
	 * SAN rules of the profile. Writes csr_signature_algorithm and, for
	 * an accepted SHA-1 signature, warning=csr_sha1_accepted. Without a
	 * CSR, under a profile: DNS:copycn in the registration is refused
	 * unless the profile takes the dNSName from the CN (BTD-191). */
	void request(const IssuanceSpec &spec, AuditParams &params);

	/* The certificate to be signed: one instance per extension, the
	 * OPC UA chain rules (PLAN.md 14.4) when the spec asks for them, and
	 * for a server-side key under a profile the SAN rules of the CSR
	 * path on the SAN as built into the certificate (BTD-191) */
	void certificate(const IssuanceSpec &spec, const pki_x509 *cert,
			const QList<const pki_x509 *> &chain);

	/* Hook for the name rules over the whole chain: name constraints
	 * of every CA up to the root, the name policy and the EKU subset
	 * rule (BTD-167). Nothing is checked yet. */
	void names(const IssuanceSpec &spec, const pki_x509 *cert,
			const QList<const pki_x509 *> &chain);
}

#endif
