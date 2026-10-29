/* vi: set sw=4 ts=4:
 *
 * The checks before every signature (BTD-55), see issuance_checks.h.
 */

#include "issuance_checks.h"

#include <QCoreApplication>
#include <QRegularExpression>
#include <QSet>

#include <openssl/evp.h>
#include <openssl/x509v3.h>

#include "audit.h"
#include "exception.h"
#include "issuance.h"
#include "pki_key.h"
#include "pki_x509.h"
#include "pki_x509req.h"

static QString tr(const char *text)
{
	return QCoreApplication::translate("IssuanceChecks", text);
}

static QString name(const pki_x509 *cert)
{
	return cert->getSubject().oneLine();
}

QList<const pki_x509 *> IssuanceChecks::issuerChain(const pki_x509 *signer)
{
	QList<const pki_x509 *> chain;
	for (const pki_x509 *ca = signer; ca && !chain.contains(ca);
	     ca = ca->getSigner())
		chain << ca;
	return chain;
}

void IssuanceChecks::pathLength(const ExtensionSpec &ext)
{
	/* Never an implicit 0: toInt() used to turn any text into 0; the
	 * whole value, "$" alone would let "1\n" through */
	static const QRegularExpression number(
			QRegularExpression::anchoredPattern("[0-9]+"));
	bool ok = false;
	if (ext.basicCA != ExtensionSpec::bc_ca || ext.pathLen.isEmpty())
		return;
	if (number.match(ext.pathLen).hasMatch())
		ext.pathLen.toInt(&ok);
	if (!ok)
		throw serviceError("invalid_path_length",
			tr("The path length '%1' is not a number of 0 or more")
			.arg(ext.pathLen));
}

void IssuanceChecks::spec(const IssuanceSpec &spec)
{
	pathLength(spec.extensions);
	if (spec.hashAlgo.isInsecure())
		throw serviceError("signature_hash_not_allowed",
			tr("A certificate is never signed with %1")
			.arg(spec.hashAlgo.name()));
}

void IssuanceChecks::issuers(const IssuanceSpec &spec,
			const QList<const pki_x509 *> &chain, pki_key *signkey,
			AuditParams &params)
{
	if (chain.isEmpty())
		return;
	const pki_x509 *issuer = chain.first();
	X509 *x = issuer->getCert();

	/* every CA of the path, the self-signed trust anchor above the
	 * issuer excepted (RFC 5280 6.1.4 (k), (n)) */
	for (int i = 0; i < chain.size(); i++) {
		const pki_x509 *c = chain[i];
		X509 *cx = c->getCert();
		if (i > 0 && i == chain.size() - 1 &&
		    !X509_NAME_cmp(X509_get_subject_name(cx),
				X509_get_issuer_name(cx)))
			break;
		if (X509_get_version(cx) < X509_VERSION_3)
			throw serviceError("issuer_v1",
				tr("'%1' is a version %2 certificate and cannot act as a CA")
				.arg(name(c)).arg(X509_get_version(cx) + 1));
		bool ca = false;
		if (!c->caAndPathLen(&ca, nullptr, nullptr) || !ca)
			throw serviceError("issuer_not_ca",
				tr("'%1' is not a CA certificate (basicConstraints cA)")
				.arg(name(c)));
		/* keyCertSign is required when the CA has key usage; without
		 * it the CA may sign (RFC 5280 6.1.4 (n)), noted in the log */
		if (!(X509_get_extension_flags(cx) & EXFLAG_KUSAGE))
			params.warn("issuer_without_key_usage");
		else if (!(X509_get_key_usage(cx) & KU_KEY_CERT_SIGN))
			throw serviceError("issuer_no_keycertsign",
				tr("The key usage of '%1' does not allow keyCertSign")
				.arg(name(c)));
	}

	a1time now, notAfter = issuer->getNotAfter();
	if (!notAfter.isUndefined() && now > notAfter)
		throw serviceError("issuer_expired",
			tr("'%1' expired on %2").arg(name(issuer))
			.arg(notAfter.toPrettyGMT()));
	a1time notBefore = issuer->getNotBefore();
	if (spec.notBefore < notBefore)
		throw serviceError("issuer_not_yet_valid",
			tr("'%1' is valid from %2, after the start of the new certificate on %3")
			.arg(name(issuer)).arg(notBefore.toPrettyGMT())
			.arg(spec.notBefore.toPrettyGMT()));

	if (EVP_PKEY_eq(X509_get0_pubkey(x), signkey->getPubKey()) != 1)
		throw serviceError("issuer_key_mismatch",
			tr("The private key '%1' does not belong to '%2'")
			.arg(signkey->getIntName(), name(issuer)));

	/* RFC 5280 4.2.1.9: pathLen of each CA counts the non-self-issued
	 * intermediate certificates below it, the new CA included */
	if (spec.extensions.basicCA != ExtensionSpec::bc_ca)
		return;
	int below = X509_NAME_cmp(spec.subject.get0(),
				X509_get_subject_name(x)) ? 1 : 0;
	for (const pki_x509 *c : chain) {
		X509 *cx = c->getCert();
		long len = X509_get_pathlen(cx);
		if (len >= 0 && below > len)
			throw serviceError("path_length_exceeded",
				tr("The path length %1 of '%2' allows no further CA below it")
				.arg(len).arg(name(c)));
		if (X509_NAME_cmp(X509_get_subject_name(cx),
				X509_get_issuer_name(cx)))
			below++;
	}
}

void IssuanceChecks::preflight(const IssuanceSpec &spec, AuditParams &params)
{
	IssuanceChecks::spec(spec);
	pki_key *signkey = spec.signer ? spec.signer->getRefKey() : nullptr;
	if (signkey)
		issuers(spec, issuerChain(spec.signer), signkey, params);
	request(spec);
}

void IssuanceChecks::request(const IssuanceSpec &spec)
{
	if (spec.request && !spec.request->verify())
		throw serviceError("invalid_csr_signature",
			tr("The signature of the certificate signing request '%1' does not verify")
			.arg(spec.request->getIntName()));
}

/* OPC UA chains (OPC 10000-6 6.2, PLAN.md 14.4) */
namespace {
class chainKey
{
  public:
	QString subject;
	const EVP_PKEY *key;
	QString family;    // RSA, EC, PQC or the OpenSSL key type
	bool pss;          // RSA-PSS key or RSA-PSS signature
	int bits;
	QString group;     // EC curve

	chainKey(const QString &s, const EVP_PKEY *k, bool pssSig)
		: subject(s), key(k), pss(pssSig)
	{
		const char *type = EVP_PKEY_get0_type_name(k);
		family = type ? type : "unknown";
		if (EVP_PKEY_is_a(k, "RSA-PSS")) {
			family = "RSA";
			pss = true;
		} else if (EVP_PKEY_is_a(k, "RSA")) {
			family = "RSA";
		} else if (EVP_PKEY_is_a(k, "EC")) {
			family = "EC";
		} else if (family.startsWith("ML-DSA") ||
			   family.startsWith("SLH-DSA")) {
			family = "PQC";
		}
		bits = EVP_PKEY_get_bits(k);
		char buf[80];
		size_t len = 0;
		if (family == "EC" &&
		    EVP_PKEY_get_group_name(k, buf, sizeof buf, &len))
			group = QString::fromLatin1(buf, len);
	}
};
}

static void opcChain(const IssuanceSpec &spec, const pki_x509 *cert,
			const QList<const pki_x509 *> &chain)
{
	/* the new certificate first, then its issuers */
	QList<chainKey> keys;
	keys << chainKey(name(cert), X509_get0_pubkey(cert->getCert()), false);
	for (const pki_x509 *c : chain) {
		keys << chainKey(name(c), X509_get0_pubkey(c->getCert()),
			X509_get_signature_nid(c->getCert()) == NID_rsassaPss);
	}
	for (const chainKey &k : keys) {
		if (k.family == "PQC")
			throw serviceError("opc_chain_pqc",
				tr("'%1' has a post-quantum key, outside every OPC UA SecurityPolicy")
				.arg(k.subject));
	}
	for (const chainKey &k : keys) {
		if (k.family != keys.first().family)
			throw serviceError("opc_chain_algorithm_mix",
				tr("'%1' has a %2 key in a chain for a %3 key")
				.arg(k.subject, k.family, keys.first().family));
	}
	for (const chainKey &k : keys) {
		if (k.pss)
			throw serviceError("opc_chain_rsa_pss",
				tr("'%1' uses RSA-PSS; OPC UA chains use PKCS#1 v1.5")
				.arg(k.subject));
		if (k.family == "RSA" && (k.bits < 2048 || k.bits > 4096))
			throw serviceError("opc_chain_rsa_key_size",
				tr("'%1' has an RSA key of %2 bits, OPC UA allows 2048 to 4096")
				.arg(k.subject).arg(k.bits));
	}
	bool newCa = spec.extensions.basicCA == ExtensionSpec::bc_ca;
	if (!newCa && keys.size() > 1 && keys[0].family == "EC" &&
	    keys[0].group != keys[1].group)
		throw serviceError("opc_chain_curve_mismatch",
			tr("The issuing CA '%1' uses %2, the certificate %3")
			.arg(keys[1].subject, keys[1].group, keys[0].group));
	for (int i = 1; i < keys.size(); i++) {
		if (keys[i - 1].bits > keys[i].bits)
			throw serviceError("opc_chain_key_longer_than_issuer",
				tr("'%1' has a %2 bit key, longer than the %3 bits of its issuer '%4'")
				.arg(keys[i - 1].subject).arg(keys[i - 1].bits)
				.arg(keys[i].bits).arg(keys[i].subject));
	}
	/* open62541 rejects issuers without cRLSign */
	for (const pki_x509 *c : chain) {
		X509 *x = c->getCert();
		if (!(X509_get_extension_flags(x) & EXFLAG_KUSAGE) ||
		    !(X509_get_key_usage(x) & KU_CRL_SIGN))
			throw serviceError("opc_chain_issuer_no_crlsign",
				tr("The CA '%1' lacks key usage cRLSign")
				.arg(name(c)));
	}
	if (newCa && !spec.extensions.keyUsage.contains("cRLSign"))
		throw serviceError("opc_chain_issuer_no_crlsign",
			tr("The CA '%1' lacks key usage cRLSign").arg(name(cert)));
	/* AKI on the self-signed root needs BTD-48 first */
}

void IssuanceChecks::certificate(const IssuanceSpec &spec,
			const pki_x509 *cert, const QList<const pki_x509 *> &chain)
{
	X509 *x = cert->getCert();
	QSet<QString> seen;
	for (int i = 0; i < X509_get_ext_count(x); i++) {
		const ASN1_OBJECT *obj =
			X509_EXTENSION_get_object(X509_get_ext(x, i));
		char oid[128];
		OBJ_obj2txt(oid, sizeof oid, obj, 0);
		if (seen.contains(oid))
			throw serviceError("duplicate_extension",
				tr("The extension %1 is present more than once").arg(oid));
		seen << oid;
	}
	if (spec.chainRules == IssuanceSpec::chain_opcua)
		opcChain(spec, cert, chain);
}

void IssuanceChecks::names(const IssuanceSpec &spec, const pki_x509 *cert,
			const QList<const pki_x509 *> &chain)
{
	Q_UNUSED(spec);
	Q_UNUSED(cert);
	Q_UNUSED(chain);
}
