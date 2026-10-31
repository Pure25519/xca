/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 *
 * Extension building of the New Certificate dialog, moved here from
 * the dialog code NewX509_ext.cpp (BTD-31) so that it works on an ExtensionSpec.
 */

#include "issuance.h"

#include <QCoreApplication>
#include <QRegularExpression>

#include <openssl/conf.h>

#include "BioByteArray.h"
#include "func_base.h"
#include "pki_x509.h"
#include "profile.h"
#include "profile_store.h"
#include "sql.h"

/* Drop the "<token>:copy" entry that only means something in a
 * certificate. splitSanEntries() keeps commas inside single values. */
static QString stripCopyToken(const QString &s, const QString &token)
{
	QStringList sn, sl = splitSanEntries(s);
	foreach (QString str, sl) {
		if (str.trimmed() != token)
			sn += str.trimmed();
	}
	return sn.join(", ");
}

x509v3ext ExtensionSpec::basicConstraintsExt(X509V3_CTX *ctx) const
{
	QStringList cont;
	x509v3ext ext;
	if (basicCA == bc_ca || basicCA == bc_not_ca) {
		if (basicCritical)
			cont << "critical";
		cont << (basicCA == bc_ca ? "CA:TRUE" : "CA:FALSE");
		/* IssuanceChecks::spec() rejects anything but a number;
		 * OpenSSL refuses the rest instead of reading it as 0 */
		if (basicCA == bc_ca && !pathLen.isEmpty())
			cont << QString("pathlen:") + pathLen;
		ext.create(NID_basic_constraints, cont.join(", "), ctx);
	}
	return ext;
}

x509v3ext ExtensionSpec::subjectKeyIdExt(X509V3_CTX *ctx) const
{
	x509v3ext ext;
	if (subjectKeyId)
		ext.create(NID_subject_key_identifier, "hash", ctx);
	return ext;
}

x509v3ext ExtensionSpec::ocspMustStapleExt(X509V3_CTX *ctx) const
{
	x509v3ext ext;
	if (ocspMustStaple)
		ext.create(NID_tlsfeature, "status_request", ctx);
	return ext;
}

x509v3ext ExtensionSpec::authorityKeyIdExt(X509V3_CTX *ctx,
					bool selfSigned) const
{
	x509v3ext ext;
	/* a self-signed certificate too (OPC 10000-6 6.2.4, BTD-48), with
	 * its own SKI as key identifier: without SKI it has none, as
	 * before. OpenSSL leaves the AKI of a self-signed certificate out
	 * unless "always" is given */
	if (!authorityKeyId || (selfSigned && !subjectKeyId))
		return ext;

	ext.create(NID_authority_key_identifier, authorityKeyIdIssuer ?
			"keyid:always,issuer:always" :
			selfSigned ? "keyid:always" : "keyid,issuer", ctx);
	return ext;
}

x509v3ext ExtensionSpec::keyUsageExt(X509V3_CTX *ctx) const
{
	QStringList cont = keyUsage;
	if (keyUsageCritical && cont.count() > 0)
		cont.prepend("critical");

	return x509v3ext(NID_key_usage, cont.join(", "), ctx);
}

x509v3ext ExtensionSpec::extKeyUsageExt(X509V3_CTX *ctx) const
{
	QStringList cont = extKeyUsage;
	if (extKeyUsageCritical && cont.count() > 0)
		cont.prepend("critical");

	return x509v3ext(NID_ext_key_usage, cont.join(", "), ctx);
}

x509v3ext ExtensionSpec::nameConstraintsExt(X509V3_CTX *ctx) const
{
	return x509v3ext(NID_name_constraints, nameConstraints, ctx);
}

x509v3ext ExtensionSpec::subjectAltNameExt(X509V3_CTX *ctx,
					bool forRequest) const
{
	QString s = subjectAltName;
	if (forRequest)
		s = stripCopyToken(s, "email:copy");
	return x509v3ext(NID_subject_alt_name, s, ctx);
}

x509v3ext ExtensionSpec::issuerAltNameExt(X509V3_CTX *ctx,
					bool forRequest) const
{
	QString s = issuerAltName;
	if (forRequest)
		s = stripCopyToken(s, "issuer:copy");
	return x509v3ext(NID_issuer_alt_name, s, ctx);
}

x509v3ext ExtensionSpec::crlDistPointsExt(X509V3_CTX *ctx) const
{
	return x509v3ext(NID_crl_distribution_points, crlDistPoints, ctx);
}

x509v3ext ExtensionSpec::authInfoAccessExt(X509V3_CTX *ctx) const
{
	return x509v3ext(NID_info_access, authInfoAccess, ctx);
}

extList ExtensionSpec::advancedExts(X509V3_CTX *ctx) const
{
	CONF *conf;
	extList elist;
	long err_line=0;
	STACK_OF(X509_EXTENSION) **sk, *sk_tmp = NULL;
	const STACK_OF(X509_EXTENSION) *csk;
	const char *ext_name = "default";
	int ret, start;

	if (advanced.isEmpty())
		return elist;

	conf = NCONF_new(NULL);
	ret = NCONF_load_bio(conf, BioByteArray(advanced.toLatin1()).ro(),
				&err_line);
	if (ret != 1) {
		NCONF_free(conf);
		/* before: printed, and the whole block was dropped (BTD-197);
		 * translation context of the dialog the code came from */
		throw serviceError("invalid_extension", QString("%1\n%2")
			.arg(QCoreApplication::translate("NewX509",
				"Configfile error on line %1\n").arg(err_line)
				.trimmed(), take_openssl_errors()));
	}

	if (ctx->subject_cert) {
		csk = X509_get0_extensions(ctx->subject_cert);
		start = csk? sk_X509_EXTENSION_num(csk): 0;
	} else {
		sk = &sk_tmp;
		start = 0;
	}

	X509V3_set_nconf(ctx, conf);

	/* 1 is success: the check was inverted, and a failure passed
	 * (BTD-197) */
	ret = ctx->subject_cert ?
		X509V3_EXT_add_nconf(conf, ctx, (char *)ext_name,
					ctx->subject_cert) :
		X509V3_EXT_add_nconf_sk(conf, ctx, (char *)ext_name, sk);
	if (ret != 1) {
		QString reason = take_openssl_errors();
		X509V3_set_nconf(ctx, NULL);
		NCONF_free(conf);
		if (!ctx->subject_cert)
			sk_X509_EXTENSION_pop_free(sk_tmp, X509_EXTENSION_free);
		throw serviceError("invalid_extension", QString("%1\n%2")
			.arg(QCoreApplication::translate("NewX509",
				"The advanced extensions cannot be built."),
				reason));
	}
	csk = ctx->subject_cert ? X509_get0_extensions(ctx->subject_cert) :
				*sk;

	elist.setStack(csk, start);
	if (!ctx->subject_cert)
		sk_X509_EXTENSION_pop_free(sk_tmp, X509_EXTENSION_free);

	X509V3_set_nconf(ctx, NULL);
	NCONF_free(conf);
	openssl_error();
	return elist;
}

extList ExtensionSpec::standardExts(X509V3_CTX *ctx, bool selfSigned,
					bool forRequest) const
{
	extList ne;

	ne << basicConstraintsExt(ctx);
	ne << subjectKeyIdExt(ctx);
	ne << authorityKeyIdExt(ctx, selfSigned);
	ne << keyUsageExt(ctx);
	ne << extKeyUsageExt(ctx);
	ne << nameConstraintsExt(ctx);
	ne << subjectAltNameExt(ctx, forRequest);
	ne << issuerAltNameExt(ctx, forRequest);
	ne << crlDistPointsExt(ctx);
	ne << authInfoAccessExt(ctx);
	ne << ocspMustStapleExt(ctx);
	openssl_error();
	return ne;
}

extList ExtensionSpec::netscapeExts(X509V3_CTX *ctx) const
{
	x509v3ext ext;
	extList el;

	el << x509v3ext(NID_netscape_cert_type, nsCertType.join(", "), ctx);
	el << ext.create_ia5(NID_netscape_base_url, nsBaseUrl, ctx);
	el << ext.create_ia5(NID_netscape_revocation_url, nsRevocationUrl, ctx);
	el << ext.create_ia5(NID_netscape_ca_revocation_url, nsCARevocationUrl, ctx);
	el << ext.create_ia5(NID_netscape_renewal_url, nsRenewalUrl, ctx);
	el << ext.create_ia5(NID_netscape_ca_policy_url, nsCaPolicyUrl, ctx);
	el << ext.create_ia5(NID_netscape_ssl_server_name, nsSslServerName, ctx);
	el << ext.create_ia5(NID_netscape_comment, nsComment, ctx);
	return el;
}

extList ExtensionSpec::build(X509V3_CTX *ctx, bool selfSigned,
				bool forRequest) const
{
	extList ne;
	ne = standardExts(ctx, selfSigned, forRequest);
	ne += advancedExts(ctx);
	if (netscape)
		ne += netscapeExts(ctx);
	ne.delInvalid();
	return ne;
}

a1time IssuanceSpec::cappedNotAfter(const a1time &requested,
			const pki_x509 *signer, bool *capped)
{
	a1time end(requested);
	bool cut = false;
	QList<const pki_x509 *> seen;

	/* a root is its own signer; seen also stops a broken chain */
	for (const pki_x509 *ca = signer; ca && !seen.contains(ca);
	     ca = ca->getSigner()) {
		seen << ca;
		a1time caEnd = ca->getNotAfter();
		if (caEnd.isUndefined() || !caEnd.isValid())
			continue;
		if (end.isUndefined() || end > caEnd) {
			end = caEnd;
			cut = true;
		}
	}
	if (capped)
		*capped = cut;
	return end;
}

a1time IssuanceSpec::requestedNotAfter() const
{
	if (!validity.isValid())
		return notAfter;
	return a1time(validity.addTo(notBefore));
}

IsoDuration IsoDuration::parse(const QString &text, QString *error)
{
	static const QRegularExpression re(
		"^P(?:(\\d+)Y)?(?:(\\d+)M)?(?:(\\d+)W)?(?:(\\d+)D)?"
		"(?:T(?:(\\d+)H)?(?:(\\d+)M)?(?:(\\d+)S)?)?$");
	IsoDuration d;
	QRegularExpressionMatch m = re.match(text);
	QString why;

	if (!m.hasMatch()) {
		why = QObject::tr("'%1' is no ISO 8601 duration such as P20Y, "
			"P1Y6M, P90D or PT12H (no fractions, no sign)").arg(text);
	} else if (text == "P" || text.endsWith('T')) {
		why = QObject::tr("'%1' has no component").arg(text);
	} else {
		qint64 *parts[] = { &d.years, &d.months, &d.weeks, &d.days,
				&d.hours, &d.minutes, &d.seconds };
		for (int i = 0; i < 7; i++) {
			QString c = m.captured(i + 1);
			bool ok = true;
			*parts[i] = c.isEmpty() ? 0 : c.toLongLong(&ok);
			/* QDateTime::addYears()/addMonths() take an int; the
			 * end itself is checked by the caller against
			 * 9999-12-31T23:59:59Z (lastEnd()) */
			if (!ok || *parts[i] > 999999999) {
				why = QObject::tr("'%1' is too large").arg(text);
				break;
			}
		}
	}
	if (!why.isEmpty()) {
		if (error)
			*error = why;
		return IsoDuration();
	}
	d.valid = true;
	return d;
}

QDateTime IsoDuration::addTo(const QDateTime &t) const
{
	return t.addYears(years).addMonths(months)
		.addDays(weeks * 7 + days)
		.addSecs(hours * 3600 + minutes * 60 + seconds);
}

QDateTime IsoDuration::subtractFrom(const QDateTime &t) const
{
	return t.addSecs(-(hours * 3600 + minutes * 60 + seconds))
		.addDays(-(weeks * 7 + days))
		.addMonths(-months).addYears(-years);
}

QDateTime IsoDuration::lastEnd()
{
	return QDateTime(QDate(9999, 12, 31), QTime(23, 59, 59), Qt::UTC);
}

QString IsoDuration::toString() const
{
	if (!valid)
		return QString();
	QString s("P"), t;
	if (years) s += QString("%1Y").arg(years);
	if (months) s += QString("%1M").arg(months);
	if (weeks) s += QString("%1W").arg(weeks);
	if (days) s += QString("%1D").arg(days);
	if (hours) t += QString("%1H").arg(hours);
	if (minutes) t += QString("%1M").arg(minutes);
	if (seconds) t += QString("%1S").arg(seconds);
	if (!t.isEmpty())
		s += "T" + t;
	return s == "P" ? QString("PT0S") : s;
}

bool RenewalSpec::rekey() const
{
	return newKey && predecessor && EVP_PKEY_eq(newKey->getPubKey(),
			X509_get0_pubkey(predecessor->getCert())) != 1;
}

/* The bits of a key usage extension by their OpenSSL names */
static QStringList keyUsageNames(X509 *x)
{
	static const char *names[] = { "digitalSignature", "nonRepudiation",
		"keyEncipherment", "dataEncipherment", "keyAgreement",
		"keyCertSign", "cRLSign", "encipherOnly", "decipherOnly" };
	QStringList bits;
	ASN1_BIT_STRING *ku = (ASN1_BIT_STRING *)X509_get_ext_d2i(x,
			NID_key_usage, nullptr, nullptr);
	for (int b = 0; ku && b < 9; b++) {
		if (ASN1_BIT_STRING_get_bit(ku, b))
			bits << names[b];
	}
	ASN1_BIT_STRING_free(ku);
	return bits;
}

IssuanceSpec RenewalSpec::issuanceSpec() const
{
	if (!predecessor)
		throw serviceError("missing_certificate",
			QCoreApplication::translate("RenewalSpec",
			"No certificate given"));
	pki_x509 *signer = predecessor->getSigner();
	if (!signer)
		throw serviceError("unknown_issuer",
			QCoreApplication::translate("RenewalSpec",
			"The issuer of '%1' is not in the database")
			.arg(predecessor->getIntName()));
	x509rev rev = predecessor->getRevocation();
	if (predecessor->isRevoked() && !rekey() &&
	    rev.getReasonBit() == CRL_REASON_KEY_COMPROMISE)
		throw serviceError("key_compromised",
			QCoreApplication::translate("RenewalSpec",
			"'%1' is revoked for key compromise; its key is never used again, only a re-key renews it")
			.arg(predecessor->getIntName()));

	IssuanceSpec spec;
	spec.name = name.isEmpty() ? predecessor->getIntName() : name;
	spec.subject = predecessor->getSubject();
	/* the predecessor's key, if it is in the database; its public key
	 * otherwise (db_x509::issue()) */
	spec.key = newKey ? newKey : predecessor->getRefKey();
	spec.signer = signer == predecessor ? nullptr : signer;
	spec.notBefore = notBefore;
	spec.notAfter = notAfter;
	spec.validity = validity;
	spec.hashAlgo = hashAlgo;
	spec.source = renewed;
	spec.predecessor = predecessor;
	spec.keepSerial = keepSerial;

	/* what the checks read from the spec */
	ExtensionSpec &e = spec.extensions;
	bool ca = false, hasLen = false;
	a1int pathLen;
	if (predecessor->caAndPathLen(&ca, &pathLen, &hasLen)) {
		e.basicCA = ca ? ExtensionSpec::bc_ca : ExtensionSpec::bc_not_ca;
		if (ca && hasLen)
			e.pathLen = pathLen.toDec();
	}
	e.keyUsage = keyUsageNames(predecessor->getCert());

	/* the stored profile the predecessor was issued under: its
	 * policies and, for family opcua, the OPC UA chain rules apply
	 * again, and the successor records it (BTD-167) */
	XSqlQuery q;
	SQL_PREPARE(q, "SELECT profile, version FROM issued_profiles "
			"WHERE item=?");
	q.bindValue(0, predecessor->getSqlItemId());
	q.exec();
	if (q.first()) {
		spec.profile = q.value(0).toString();
		spec.profileVersion = q.value(1).toInt();
		Profile profile = Profile::fromJson(ProfileStore::show(
			"profile", spec.profile, spec.profileVersion).document);
		if (profile.family == "opcua")
			spec.chainRules = IssuanceSpec::chain_opcua;
	}
	return spec;
}
