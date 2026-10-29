/* vi: set sw=4 ts=4:
 *
 * The checks before every signature (BTD-55), see issuance_checks.h.
 */

#include "issuance_checks.h"

#include <QCoreApplication>
#include <QMap>
#include <QPair>
#include <QRegularExpression>
#include <QSet>
#include <QUrl>

#include <openssl/evp.h>
#include <openssl/x509v3.h>

#include "audit.h"
#include "exception.h"
#include "issuance.h"
#include "pki_key.h"
#include "policy.h"
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
	request(spec, params);
}

/* The requested extension nid of a CSR, or nullptr */
static void *requested(X509_REQ *req, int nid)
{
	STACK_OF(X509_EXTENSION) *exts = X509_REQ_get_extensions(req);
	void *value = X509V3_get_d2i(exts, nid, nullptr, nullptr);
	sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
	return value;
}

void IssuanceChecks::request(const IssuanceSpec &spec, AuditParams &params)
{
	if (!spec.request)
		return;
	const CsrPolicy &policy = spec.csrPolicy;
	X509_REQ *req = spec.request->getReq();
	QString csr = spec.request->getIntName();

	/* the digest of the device's signature, before verifying it */
	int sigNid = X509_REQ_get_signature_nid(req), mdNid = NID_undef;
	OBJ_find_sigid_algs(sigNid, &mdNid, nullptr);
	params.set("csr_signature_algorithm", OBJ_nid2ln(sigNid));
	switch (mdNid) {
	case NID_md2:
	case NID_md4:
	case NID_md5:
	case NID_md5_sha1:
	case NID_ripemd160:
		throw serviceError("csr_digest_not_allowed",
			tr("The certificate signing request '%1' is signed with %2, which is never accepted")
			.arg(csr, OBJ_nid2ln(sigNid)));
	case NID_sha1:
		if (policy.csrSha1 == CsrPolicy::sha1_reject)
			throw serviceError("csr_sha1_rejected",
				tr("The profile does not accept the SHA-1 signature of '%1'")
				.arg(csr));
		break;
	}
	if (!spec.request->verify())
		throw serviceError("invalid_csr_signature",
			tr("The signature of the certificate signing request '%1' does not verify")
			.arg(csr));
	if (mdNid == NID_sha1)
		params.warn("csr_sha1_accepted");

	/* keyCertSign or cA=TRUE requested for an end entity: they reach
	 * the certificate only when the CSR's extensions are copied */
	bool leaf = spec.extensions.basicCA != ExtensionSpec::bc_ca;
	bool used = policy.profile || spec.copyRequestExtensions;
	if (leaf && used &&
	    policy.keyCertSignRequest == CsrPolicy::keycertsign_reject) {
		ASN1_BIT_STRING *ku = (ASN1_BIT_STRING *)
				requested(req, NID_key_usage);
		bool kcs = ku && ASN1_BIT_STRING_get_bit(ku, 5);
		ASN1_BIT_STRING_free(ku);
		BASIC_CONSTRAINTS *bc = (BASIC_CONSTRAINTS *)
				requested(req, NID_basic_constraints);
		bool ca = bc && bc->ca;
		BASIC_CONSTRAINTS_free(bc);
		if (kcs || ca)
			throw serviceError("csr_keycertsign_not_ca",
				tr("'%1' asks for %2 in an end-entity certificate (RFC 5280 4.2.1.9)")
				.arg(csr, kcs ? "keyCertSign" : "cA=TRUE"));
	}

	/* device classes that break on some characters in the DN */
	const X509_NAME *subject = spec.subject.get0();
	for (int i = 0; !policy.forbiddenCharacters.isEmpty() &&
			i < X509_NAME_entry_count(subject); i++) {
		unsigned char *utf8 = nullptr;
		int len = ASN1_STRING_to_UTF8(&utf8, X509_NAME_ENTRY_get_data(
				X509_NAME_get_entry(subject, i)));
		QString value = len < 0 ? QString() :
				QString::fromUtf8((char *)utf8, len);
		OPENSSL_free(utf8);
		for (const QChar &c : policy.forbiddenCharacters) {
			if (value.contains(c))
				throw serviceError("csr_subject_forbidden_character",
					tr("The subject value '%1' contains '%2', which the profile forbids")
					.arg(value, c));
		}
	}

	/* the ApplicationUri comes from the registration */
	if (!policy.profile)
		return;
	GENERAL_NAMES *san = (GENERAL_NAMES *)
			requested(req, NID_subject_alt_name);
	for (int i = 0; i < sk_GENERAL_NAME_num(san); i++) {
		GENERAL_NAME *gn = sk_GENERAL_NAME_value(san, i);
		if (gn->type != GEN_URI)
			continue;
		QString uri = QString::fromUtf8((const char *)
				ASN1_STRING_get0_data(gn->d.uniformResourceIdentifier),
				ASN1_STRING_get_length(gn->d.uniformResourceIdentifier));
		if (policy.registeredUri.isEmpty() ||
		    uri != policy.registeredUri) {
			GENERAL_NAMES_free(san);
			if (policy.registeredUri.isEmpty())
				throw serviceError("csr_uri_not_allowed",
					tr("The profile allows no URI, '%1' asks for %2")
					.arg(csr, uri));
			throw serviceError("csr_uri_mismatch",
				tr("The URI %1 of '%2' is not the registered %3")
				.arg(uri, csr, policy.registeredUri));
		}
	}
	GENERAL_NAMES_free(san);
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

	/* the signature hash of the SecurityPolicy of the end entity's key
	 * (OPC 10000-7 6.6.x, the OPC research of BTD-63): SHA-256 for RSA
	 * and the 256-bit curves, SHA-384 for the 384-bit curves. An end
	 * entity has the curve of its issuer (above); a CA of the lab
	 * hierarchies may sit below a CA of another curve (PLAN.md 14.1)
	 * and is signed with the hash of that issuer, so CAs are left out. */
	static const QMap<QString, QPair<QString, int>> policies {
		{ "prime256v1", { "ECC_nistP256", NID_sha256 } },
		{ "P-256", { "ECC_nistP256", NID_sha256 } },
		{ "secp384r1", { "ECC_nistP384", NID_sha384 } },
		{ "P-384", { "ECC_nistP384", NID_sha384 } },
		{ "brainpoolP256r1", { "ECC_brainpoolP256r1", NID_sha256 } },
		{ "brainpoolP384r1", { "ECC_brainpoolP384r1", NID_sha384 } },
	};
	QPair<QString, int> policy = keys[0].family == "RSA" ?
		qMakePair(QString("Basic256Sha256"), (int)NID_sha256) :
		policies.value(keys[0].group);
	if (!newCa && !policy.first.isEmpty() && spec.hashAlgo.MD() &&
	    EVP_MD_get_type(spec.hashAlgo.MD()) != policy.second)
		throw serviceError("opc_signature_hash",
			tr("'%1' would be signed with %2; its key belongs to the OPC UA SecurityPolicy %3, which needs %4")
			.arg(name(cert), spec.hashAlgo.name(), policy.first,
				OBJ_nid2sn(policy.second)));
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

/* A dNSName as RFC 5280 4.2.1.6 and the preferred name syntax want it:
 * ASCII labels of letters, digits and hyphens, none empty, no trailing
 * dot, a wildcard only as the whole leftmost label, an A-label that
 * decodes and encodes back to itself; never converted (no blind IDNA,
 * step-ca #2318, #2714). Returns why it is not, or a null string. */
static QString dnsNameError(const QString &name)
{
	static const QRegularExpression ldh(
		QRegularExpression::anchoredPattern(
			"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"));
	if (name.isEmpty())
		return tr("it is empty");
	if (name.endsWith('.'))
		return tr("it ends with a dot");
	QStringList labels = name.split('.');
	for (int i = 0; i < labels.size(); i++) {
		const QString &l = labels[i];
		if (l.isEmpty())
			return tr("it has an empty label");
		if (l == "*" && i == 0 && labels.size() > 1)
			continue;
		for (QChar c : l) {
			if (c.unicode() > 127)
				return tr("it is not ASCII; IDNs are written as A-labels (xn--)");
		}
		if (!ldh.match(l).hasMatch())
			return tr("the label '%1' is no host name label").arg(l);
		if (l.startsWith("xn--", Qt::CaseInsensitive)) {
			QString u = QUrl::fromAce(l.toLatin1(),
					QUrl::IgnoreIDNWhitelist);
			if (u.isEmpty() || u.compare(l, Qt::CaseInsensitive) == 0 ||
			    QString::fromLatin1(QUrl::toAce(u,
				QUrl::IgnoreIDNWhitelist)).compare(l,
					Qt::CaseInsensitive))
				return tr("'%1' is no valid A-label").arg(l);
		}
	}
	return QString();
}

void IssuanceChecks::names(const IssuanceSpec &spec, const pki_x509 *cert,
			const QList<const pki_x509 *> &chain)
{
	X509 *x = cert->getCert();

	/* the syntax of every dNSName, with or without a policy */
	GENERAL_NAMES *san = (GENERAL_NAMES *)X509_get_ext_d2i(x,
			NID_subject_alt_name, nullptr, nullptr);
	for (int i = 0; i < sk_GENERAL_NAME_num(san); i++) {
		GENERAL_NAME *gn = sk_GENERAL_NAME_value(san, i);
		if (gn->type != GEN_DNS)
			continue;
		QString dns = QString::fromUtf8((const char *)
				ASN1_STRING_get0_data(gn->d.dNSName),
				ASN1_STRING_get_length(gn->d.dNSName));
		QString why = dnsNameError(dns);
		if (!why.isNull()) {
			GENERAL_NAMES_free(san);
			throw serviceError("invalid_dns_name",
				tr("The dNSName '%1' is refused: %2").arg(dns, why));
		}
	}
	GENERAL_NAMES_free(san);

	/* name constraints of every CA up to the root (RFC 5280 6.1.3 (b),
	 * PLAN.md 8.4 rule 12; OpenSSL's own check). OpenSSL reads the names
	 * from the extension cache, which the certificate under construction
	 * filled before its SAN was added; a fresh copy of subject and SAN
	 * has a cache of its own. */
	X509 *names = X509_new();
	X509_set_subject_name(names, X509_get_subject_name(x));
	int at = X509_get_ext_by_NID(x, NID_subject_alt_name, -1);
	if (at >= 0)
		X509_add_ext(names, X509_get_ext(x, at), -1);
	X509_check_purpose(names, -1, 0);
	for (const pki_x509 *ca : chain) {
		NAME_CONSTRAINTS *nc = (NAME_CONSTRAINTS *)X509_get_ext_d2i(
			ca->getCert(), NID_name_constraints, nullptr, nullptr);
		if (!nc)
			continue;
		int rc = NAME_CONSTRAINTS_check(names, nc);
		NAME_CONSTRAINTS_free(nc);
		if (rc != X509_V_OK) {
			X509_free(names);
			ign_openssl_error();
			throw serviceError("name_constraints_violation",
				tr("The names of '%1' violate the name constraints of '%2': %3")
				.arg(name(cert), name(ca),
					X509_verify_cert_error_string(rc)));
		}
	}
	X509_free(names);

	/* the EKU is a subset of the EKU of every CA that has one
	 * (step-ca #2536); anyExtendedKeyUsage admits every purpose */
	EXTENDED_KEY_USAGE *eku = (EXTENDED_KEY_USAGE *)X509_get_ext_d2i(x,
			NID_ext_key_usage, nullptr, nullptr);
	for (const pki_x509 *ca : chain) {
		EXTENDED_KEY_USAGE *caEku = (EXTENDED_KEY_USAGE *)
			X509_get_ext_d2i(ca->getCert(), NID_ext_key_usage,
					nullptr, nullptr);
		QSet<int> allowed;
		for (int i = 0; i < sk_ASN1_OBJECT_num(caEku); i++)
			allowed << OBJ_obj2nid(sk_ASN1_OBJECT_value(caEku, i));
		EXTENDED_KEY_USAGE_free(caEku);
		if (!caEku || allowed.contains(NID_anyExtendedKeyUsage))
			continue;
		for (int i = 0; i < sk_ASN1_OBJECT_num(eku); i++) {
			const ASN1_OBJECT *o = sk_ASN1_OBJECT_value(eku, i);
			if (allowed.contains(OBJ_obj2nid(o)))
				continue;
			char purpose[80];
			OBJ_obj2txt(purpose, sizeof purpose, o, 1);
			int nid = OBJ_obj2nid(o);
			EXTENDED_KEY_USAGE_free(eku);
			throw serviceError("eku_not_in_issuer",
				tr("The extended key usage %1 is not among those of the CA '%2'")
				.arg(nid == NID_undef ? purpose : OBJ_nid2sn(nid),
					name(ca)));
		}
	}
	EXTENDED_KEY_USAGE_free(eku);

	/* the name policies assigned to the CA and the profile */
	for (const Policy &p : spec.policies)
		p.check(spec, cert, chain);
}
