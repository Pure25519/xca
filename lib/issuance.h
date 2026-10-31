/* vi: set sw=4 ts=4:
 *
 * Certificate issuance without the GUI (BTD-31): the value objects that
 * db_x509::newCert(const ServiceContext &, const IssuanceSpec &) takes.
 *
 * The extension inputs are the ones the New Certificate dialog offers.
 * Each extension is built from its OpenSSL configuration string, in the
 * order the dialog always used, so a certificate issued from a spec is
 * byte-identical in its extensions to one issued from the dialog with
 * the same input. NewX509 only fills these objects.
 *
 * A spec holds non-owning references to objects of the open database
 * (key, request, signer). Create one per call; nothing in here is shared
 * between calls.
 */

#ifndef __ISSUANCE_H
#define __ISSUANCE_H

#include <QDateTime>
#include <QList>
#include <QMap>
#include <QPair>
#include <QString>
#include <QStringList>

#include <openssl/x509v3.h>

#include "asn1time.h"
#include "digest.h"
#include "pki_base.h"
#include "policy.h"
#include "x509name.h"
#include "x509v3ext.h"

class pki_key;
class pki_x509;
class pki_x509req;

class ExtensionSpec
{
  public:
	enum basicConstraints { bc_absent, bc_ca, bc_not_ca };

	enum basicConstraints basicCA{ bc_absent };
	bool basicCritical{};
	QString pathLen{};          // empty: no path length constraint;
	                            // 0 is a constraint, never a default

	bool subjectKeyId{};
	bool authorityKeyId{};      // also on a self-signed certificate (BTD-48)
	bool authorityKeyIdIssuer{}; // keyid plus issuer and serial, not
	                             // only the keyid (profile aki.form)

	QStringList keyUsage{};     // OpenSSL names, e.g. "keyCertSign"
	bool keyUsageCritical{};
	QStringList extKeyUsage{};  // OpenSSL short names, e.g. "serverAuth"
	bool extKeyUsageCritical{};

	/* OpenSSL configuration values, e.g. "DNS:host.example, IP:10.0.0.1" */
	QString nameConstraints{};
	QString subjectAltName{};
	QString issuerAltName{};
	QString crlDistPoints{};
	QString authInfoAccess{};
	bool ocspMustStaple{};

	/* OpenSSL configuration file, section "default" (Advanced tab) */
	QString advanced{};

	/* What a CSR adds to SAN, key usage and EKU (BTD-54):
	 * merge_legacy   as XCA always did: with "copy extensions from the
	 *                request" the CSR's extension when the template has
	 *                none, otherwise the template alone;
	 * merge_template the template alone, the CSR is ignored;
	 * merge_request  the CSR's extension if it has one, else the
	 *                template's;
	 * merge_union    both: the CSR's entries first, then the template's
	 *                that are not there yet (KU: the bits of both).
	 * Every mode yields at most one instance of each extension. */
	enum requestMerge { merge_legacy, merge_template, merge_request,
				merge_union };
	enum requestMerge sanMerge{ merge_legacy };
	enum requestMerge kuMerge{ merge_legacy };
	enum requestMerge ekuMerge{ merge_legacy };
	/* EKU a CSR may ask for (short names or OIDs); empty: any. A CSR
	 * without EKU counts as asking for ekuDefault when that is set
	 * (Nexus style: clientAuth, PLAN.md 9.1). */
	QStringList ekuAllowed{};
	QStringList ekuDefault{};

	bool netscape{};            // add the Netscape extensions below
	QStringList nsCertType{};   // "client", "server", "email", "objsign", ...
	QString nsBaseUrl{};
	QString nsRevocationUrl{};
	QString nsCARevocationUrl{};
	QString nsRenewalUrl{};
	QString nsCaPolicyUrl{};
	QString nsSslServerName{};
	QString nsComment{};

	/* The single extensions. With ctx->subject_cert set, every valid
	 * extension is also added to that certificate (x509v3ext::create).
	 * forRequest drops the "email:copy" / "issuer:copy" tokens that only
	 * mean something in a certificate. */
	x509v3ext basicConstraintsExt(X509V3_CTX *ctx) const;
	x509v3ext subjectKeyIdExt(X509V3_CTX *ctx) const;
	x509v3ext authorityKeyIdExt(X509V3_CTX *ctx, bool selfSigned) const;
	x509v3ext keyUsageExt(X509V3_CTX *ctx) const;
	x509v3ext extKeyUsageExt(X509V3_CTX *ctx) const;
	x509v3ext nameConstraintsExt(X509V3_CTX *ctx) const;
	x509v3ext subjectAltNameExt(X509V3_CTX *ctx, bool forRequest) const;
	x509v3ext issuerAltNameExt(X509V3_CTX *ctx, bool forRequest) const;
	x509v3ext crlDistPointsExt(X509V3_CTX *ctx) const;
	x509v3ext authInfoAccessExt(X509V3_CTX *ctx) const;
	x509v3ext ocspMustStapleExt(X509V3_CTX *ctx) const;

	/* The dialog's tabs other than Advanced and Netscape */
	extList standardExts(X509V3_CTX *ctx, bool selfSigned,
				bool forRequest) const;
	extList advancedExts(X509V3_CTX *ctx) const;
	extList netscapeExts(X509V3_CTX *ctx) const;
	/* Everything in dialog order, invalid (empty) ones removed */
	extList build(X509V3_CTX *ctx, bool selfSigned, bool forRequest) const;
};

/* An ISO 8601 duration (BTD-41, rule 6 of the certstrap triage):
 * PnYnMnWnDTnHnMnS with non-negative integers, at least one component,
 * e.g. P20Y, P1Y6M, P90D, PT12H. Years and months are calendar units:
 * addTo() adds them first (QDateTime::addYears/addMonths, the end of a
 * shorter month is clamped), then weeks and days, then the time. The
 * same duration is used for --validity and --backdate of bxc-pki and
 * later by the bootstrap file and the REST API. */
class IsoDuration
{
  public:
	qint64 years{}, months{}, weeks{}, days{};
	qint64 hours{}, minutes{}, seconds{};
	bool valid{};

	/* Strict parser; *error receives the reason for an invalid text */
	static IsoDuration parse(const QString &text, QString *error = nullptr);
	bool isValid() const
	{
		return valid;
	}
	bool isZero() const
	{
		return !years && !months && !weeks && !days && !hours &&
			!minutes && !seconds;
	}
	/* The end may be invalid for a huge duration; no certificate ends
	 * after lastEnd(), 9999-12-31T23:59:59Z (RFC 5280 4.1.2.5) */
	QDateTime addTo(const QDateTime &t) const;
	static QDateTime lastEnd();
	QDateTime subtractFrom(const QDateTime &t) const;
	QString toString() const;
};

/* How a device CSR is accepted (BTD-65). The members are the CSR fields
 * of a profile (profiles/<id>.json of bxc-pki, BTD-64); the profile engine
 * (BTD-54) fills them, the GUI keeps the defaults. */
class CsrPolicy
{
  public:
	/* csr_sha1: a SHA-1 CSR signature after the proof of possession,
	 * with an audit warning, or never. MD5 is never accepted. */
	enum sha1 { sha1_accept_with_warning, sha1_reject };
	/* keycertsign_request: a leaf request asking for keyCertSign or
	 * cA=TRUE is refused (RFC 5280 4.2.1.9) or its bits are ignored */
	enum keyCertSign { keycertsign_reject, keycertsign_override };

	/* A profile decides: the CSR's KU, EKU, basicConstraints, AKI, SKI
	 * and Netscape extensions never reach the certificate, its SAN is
	 * taken as it is (order kept), the URI and CN rules below apply */
	bool profile{};
	enum sha1 csrSha1{ sha1_accept_with_warning };
	enum keyCertSign keyCertSignRequest{ keycertsign_reject };
	/* san.uri: with a profile, the ApplicationUri of the registration;
	 * a CSR URI must equal it, a CSR without one gets it appended.
	 * Empty: the profile allows no URI. */
	QString registeredUri{};
	/* subject.add_missing_o: the O of the registration, appended when
	 * the CSR subject has none; empty: off */
	QString missingO{};
	/* subject.forbidden_characters, e.g. "/=" for S7-1500 V02.09.08 */
	QString forbiddenCharacters{};
	/* san.dns_from_cn of a generic profile (XCA DNS:copycn): the CN is
	 * appended as dNSName unless the SAN has it already */
	bool dnsFromCn{};
	/* san.* (mr-processor review of xca#44): the name types a CSR SAN
	 * may carry besides the URI, with their counts (GEN_DNS, GEN_IPADD,
	 * GEN_EMAIL; any other type is refused), the minimum of dNSName plus
	 * iPAddress, wildcard dNSNames, and the criticality of the SAN in
	 * the certificate (the CSR's bytes, the profile's flag) */
	QMap<int, QPair<int, int>> sanCounts{};
	int dnsOrIpMin{};
	bool sanWildcard{};
	bool sanCritical{};
};

/* The serial number is not part of the spec: it is always random, positive
 * and unique per issuer (rule 2 of the certstrap triage), see
 * db_x509::getUniqueSerial(). */
class IssuanceSpec
{
  public:
	QString name{};             // internal name; empty: name of the request
	x509name subject{};         // as given, also with a request:
	                            // copy request->getSubject() to keep it
	pki_key *key{};             // subject key, unless request is set
	pki_x509req *request{};     // CSR: its key or public key is used
	pki_x509 *signer{};         // nullptr: self-signed

	a1time notBefore{};
	a1time notAfter{};          // may be undefined (99991231235959Z)
	/* BTD-41: when valid, the requested end is notBefore + validity
	 * and notAfter is ignored */
	IsoDuration validity{};
	digest hashAlgo{};

	ExtensionSpec extensions{};
	bool copyRequestExtensions{};   // CSR extensions the spec lacks

	/* chain_opcua adds the OPC UA chain rules (PLAN.md 14.4) to the
	 * checks before the signature; a profile of family opcua sets it */
	enum chainRules { chain_rfc5280, chain_opcua };
	enum chainRules chainRules{ chain_rfc5280 };

	CsrPolicy csrPolicy{};          // with a request

	/* Extension order of the certificate as NIDs, e.g. the order of
	 * the golden files of a profile; the rest keeps its place after
	 * them. Empty: the dialog order. */
	QList<int> extensionOrder{};

	QString comment{};
	QString templateName{};     // template the input came from, for the audit
	/* key usage bits the user removed in the dialog because the key
	 * cannot use them (BTD-195), for the audit */
	QStringList keyUsageRemoved{};
	QString profile{};          // profile id the spec came from (BTD-54)
	int profileVersion{};       // stored version (BTD-167); 0: a file
	/* a validity above the profile's validity.max, capped to it */
	QDateTime profileCappedFrom{};
	/* the ids of the profile's device warnings, for the audit entry */
	QStringList profileWarnings{};
	/* The name policies of the CA and the profile (BTD-167), checked
	 * by IssuanceChecks::names() before the serial and the signature */
	QList<Policy> policies{};
	enum pki_source source{ generated };
	/* Renewal (BTD-56): the extensions are the predecessor's, copied
	 * in their order; on a re-key the key identifiers are made from the
	 * new key. The ExtensionSpec above then only carries what the
	 * checks read (basicConstraints, pathLen, key usage). keepSerial
	 * takes the predecessor's serial, which the caller must delete. */
	pki_x509 *predecessor{};
	bool keepSerial{};

	bool selfSigned() const
	{
		return signer == nullptr;
	}

	/* Rule 6 of the certstrap triage (BTD-51): a certificate ends at
	 * the earliest notAfter of its issuer chain, up to the root, if
	 * the requested one is later. The undefined notAfter
	 * (99991231235959Z, kept by a1time as the epoch, so it must never
	 * be compared as a date) means "no end": it never caps and any
	 * defined notAfter caps it. *capped tells whether the result
	 * differs from the request; callers report that, never drop it.
	 * A capped end at or before notBefore leaves no validity window:
	 * newCert() rejects it with invalid_validity. */
	static a1time cappedNotAfter(const a1time &requested,
				const pki_x509 *signer, bool *capped = nullptr);
	/* notAfter, or notBefore + validity */
	a1time requestedNotAfter() const;
	a1time effectiveNotAfter(bool *capped = nullptr) const
	{
		return cappedNotAfter(requestedNotAfter(), signer, capped);
	}
};

/* Renewal or re-key of a certificate (BTD-56), the input of
 * db_x509::renew(). Subject, extensions and issuer are the
 * predecessor's; it is signed by the issuer of the predecessor (itself
 * when it is self-signed) through the same checks as any issuance. */
class RenewalSpec
{
  public:
	pki_x509 *predecessor{};
	pki_key *newKey{};          // re-key; nullptr: the predecessor's key
	QString name{};             // internal name; empty: the predecessor's
	a1time notBefore{};
	a1time notAfter{};          // may be undefined (99991231235959Z)
	IsoDuration validity{};     // when valid, notAfter is ignored
	digest hashAlgo{};
	/* the predecessor's serial instead of a new one; only for a
	 * predecessor that is deleted afterwards (the dialog's "replace") */
	bool keepSerial{};

	/* A new key that differs from the predecessor's */
	bool rekey() const;
	/* The issuance of the renewal. Throws serviceError
	 * missing_certificate, unknown_issuer (the issuer is not in the
	 * database) and key_compromised (the predecessor is revoked with
	 * reason keyCompromise and its key would be used again). */
	IssuanceSpec issuanceSpec() const;
};

#endif
