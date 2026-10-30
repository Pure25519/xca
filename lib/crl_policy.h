/* vi: set sw=4 ts=4:
 *
 * CRL lifecycle settings of a CA (BTD-42; rule 7 of bxc-pki PLAN.md 8.4,
 * PLAN.md 14.6, bootstrap schema $defs/crlSettings). The defaults are the
 * initial values the user confirmed on 2026-10-27: validity P7D, a new
 * CRL after one third of the validity (IDIAL replaces a CRL on a device
 * once half of its lifetime has passed, so bxc-pki must hold a newer one
 * before that), 4096 bytes per CRL (the S7 budget).
 *
 * Storage: the validity also sets the CA's crlDays (authority table,
 * rounded up to whole days, what the GUI shows and uses); the whole
 * setting is one row of the settings table, key "crlpolicy_<CA item id>",
 * value a JSON object {"validity": "P7D", "reissue_fraction": 0.333...,
 * "size_budget": 4096}. A CA without that row has the defaults, its
 * validity from crlDays.
 */

#ifndef __CRL_POLICY_H
#define __CRL_POLICY_H

#include <QDateTime>
#include <QJsonObject>
#include <QString>

#include "issuance.h"

class pki_crl;
class pki_x509;
class ServiceContext;

class CrlPolicy
{
  public:
	static const char defaultValidity[];        // "P7D"
	static const double defaultReissueFraction; // 1/3
	static const qint64 defaultSizeBudget;      // 4096
	static const qint64 defaultTrustListBudget; // 65535
	static const char actionSettings[];         // "ca.crl_settings"

	IsoDuration validity{};
	double reissueFraction{ defaultReissueFraction };
	qint64 sizeBudget{ defaultSizeBudget };

	CrlPolicy();
	/* The stored setting of ca, or the defaults with its crlDays */
	static CrlPolicy of(const pki_x509 *ca);
	/* Stores the setting of ca and its crlDays in the caller's
	 * transaction (or one of its own) and writes one audit entry
	 * ca.crl_settings (ca_id, name, crl_validity, reissue_fraction,
	 * size_budget); throws serviceError issuer_not_ca,
	 * database_error. */
	void store(const ServiceContext &ctx, pki_x509 *ca) const;

	/* nextUpdate of a CRL issued at thisUpdate */
	QDateTime nextUpdate(const QDateTime &thisUpdate) const;
	/* thisUpdate + reissueFraction * (nextUpdate - thisUpdate) */
	QDateTime reissueAt(const pki_crl *crl) const;
	bool reissueDue(const pki_crl *crl, const QDateTime &now) const;
	static bool expired(const pki_crl *crl, const QDateTime &now);

	/* "1/3", "0.25": strictly between 0 and 0.5; throws serviceError
	 * invalid_value naming option */
	static double parseFraction(const QString &text,
			const QString &option);
	/* A validity of at least one minute; throws invalid_value */
	static IsoDuration checkValidity(const IsoDuration &d,
			const QString &option);
	static QString fractionText(double f);
	QJsonObject toJson() const;

	/* The CRL of ca with the highest CRL number in the store, or
	 * nullptr */
	static pki_crl *latestCrl(const pki_x509 *ca);
	/* An ISO 8601 duration of whole seconds, e.g. "P6DT23H59M58S";
	 * "PT0S" for zero or less */
	static QString durationText(qint64 seconds);
};

#endif
