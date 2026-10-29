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
#include <QString>
#include <QStringList>

#include <openssl/x509v3.h>

#include "asn1time.h"
#include "digest.h"
#include "pki_base.h"
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
	QString pathLen{};          // empty: no path length constraint

	bool subjectKeyId{};
	bool authorityKeyId{};      // never added to a self-signed certificate

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
	QDateTime addTo(const QDateTime &t) const;
	QDateTime subtractFrom(const QDateTime &t) const;
	QString toString() const;
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
	/* With copyRequestExtensions: only CSR extensions of these NIDs,
	 * empty: all (BTD-41: bxc-pki copies the SAN only, rule 3) */
	QList<int> requestExtensionNids{};

	QString comment{};
	QString templateName{};     // template the input came from, for the audit
	enum pki_source source{ generated };

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

#endif
