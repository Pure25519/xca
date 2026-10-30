/* vi: set sw=4 ts=4:
 *
 * The CRL lifecycle of bxc-pki part 2 (BTD-42): the commands revoke and
 * crl, and the CRL helpers that init, sign and export share (rule 7 and 8
 * of bxc-pki PLAN.md 8.4, PLAN.md 14.6). The handlers work on the service
 * layer only and run inside the runner's transaction (cli.h).
 */

#include <QRegularExpression>

#include <openssl/evp.h>

#include "lib/database_model.h"
#include "lib/db_crl.h"
#include "lib/db_x509.h"
#include "lib/func.h"
#include "lib/issuance_checks.h"
#include "lib/json_report.h"
#include "lib/pki_crl.h"
#include "lib/pki_key.h"
#include "lib/pki_x509.h"
#include "lib/x509rev.h"
#include "cli.h"

namespace bxcpki {

/* --- CRL settings ------------------------------------------------------- */

QList<OptionSpec> crlOptions(const QString &scope)
{
	return QList<OptionSpec> {
		opt("crl-validity", OptionSpec::duration, "<duration>",
			QObject::tr("CRL validity, nextUpdate - thisUpdate "
			"(default %1)%2").arg(CrlPolicy::defaultValidity)
			.arg(scope)),
		opt("crl-reissue-fraction", OptionSpec::string, "<fraction>",
			QObject::tr("a new CRL is issued once this fraction of "
			"its validity has passed, e.g. 1/3 or 0.25, below 1/2 "
			"(default 1/3)%1").arg(scope)),
		opt("crl-size-budget", OptionSpec::integer, "<bytes>",
			QObject::tr("DER size budget of one CRL, at least 512 "
			"(default %1)%2").arg(CrlPolicy::defaultSizeBudget)
			.arg(scope)),
	};
}

bool hasCrlOptions(const Options &o)
{
	return o.has("crl-validity") || o.has("crl-reissue-fraction") ||
		o.has("crl-size-budget");
}

CrlPolicy crlPolicy(const Options &o, const pki_x509 *ca)
{
	CrlPolicy p = CrlPolicy::of(ca);
	/* wrong values are usage errors (exit code 2) */
	try {
		if (o.has("crl-validity"))
			p.validity = CrlPolicy::checkValidity(parseDuration(
				o.value("crl-validity"), "crl-validity"),
				"crl-validity");
		if (o.has("crl-reissue-fraction"))
			p.reissueFraction = CrlPolicy::parseFraction(
				o.value("crl-reissue-fraction"),
				"crl-reissue-fraction");
	} catch (usageError &) {
		throw;
	} catch (serviceError &err) {
		throw usageError(err.code, err.getString());
	}
	if (o.has("crl-size-budget")) {
		qint64 b = o.value("crl-size-budget").toLongLong();
		if (b < 512)
			throw usageError("invalid_value", QObject::tr(
				"--crl-size-budget must be at least 512"));
		p.sizeBudget = b;
	}
	return p;
}

/* --- CRL issue and report ------------------------------------------------ */

QJsonObject crlReport(const pki_crl *crl, const CrlPolicy &policy,
		const QDateTime &now)
{
	QJsonObject r;
	pki_x509 *ca = crl->getIssuer();
	if (ca) {
		r["ca_id"] = ca->getSqlItemId().toLongLong();
		r["ca_name"] = ca->getIntName();
	}
	r["crl_id"] = crl->getSqlItemId().isValid() ?
		QJsonValue(crl->getSqlItemId().toLongLong()) : QJsonValue();
	r["crl_name"] = crl->getIntName();
	a1int no(0L);
	if (crl->getCrlNumber(&no))
		r["crl_number"] = no.toDec().toLongLong();
	r["revoked_count"] = crl->numRev();
	r["this_update"] = JsonReport::timestamp(crl->getLastUpdate());
	r["next_update"] = JsonReport::timestamp(crl->getNextUpdate());
	r["reissue_fraction"] = policy.reissueFraction;
	r["reissue_at"] = JsonReport::timestamp(
				a1time(policy.reissueAt(crl)));
	qint64 left = now.secsTo(crl->getNextUpdate());
	r["remaining_seconds"] = left;
	r["remaining_validity"] = CrlPolicy::durationText(left);
	r["reissue_due"] = policy.reissueDue(crl, now);
	r["expired"] = CrlPolicy::expired(crl, now);
	qint64 size = crl->i2d().size();
	r["der_size"] = size;
	r["size_budget"] = policy.sizeBudget;
	r["within_budget"] = size <= policy.sizeBudget;
	return r;
}

static void budgetWarning(CommandContext &ctx, const QJsonObject &r)
{
	if (r["within_budget"].toBool(true))
		return;
	ctx.result->warning("budget_exceeded", QObject::tr(
		"The CRL of '%1' has %2 bytes, more than its budget of %3")
		.arg(r["ca_name"].toString())
		.arg(r["der_size"].toVariant().toString())
		.arg(r["size_budget"].toVariant().toString()));
}

pki_crl *issueCrl(CommandContext &ctx, pki_x509 *ca, const CrlPolicy &policy,
		const QString &trigger, const QDateTime &thisUpdate, bool report)
{
	crljob job(ca);
	job.trigger = trigger;
	QDateTime t = thisUpdate.isValid() ? thisUpdate : nowSeconds();
	job.lastUpdate = a1time(t);
	job.nextUpdate = a1time(policy.nextUpdate(t));
	pki_key *signkey = ca->getRefKey();
	/* --hash, or none for a key type without digest (EdDSA, ML-DSA,
	 * SLH-DSA); else the default as the CA's key allows */
	if (ctx.opts.has("hash") || (signkey &&
			keytype::byType(signkey->getKeyType()).fixed()))
		job.hashAlgo = hashFrom(ctx.opts, signkey);
	QString step = ctx.step;
	ctx.step = QObject::tr("CRL of '%1'").arg(ca->getIntName());

	if (ctx.plan) {
		/* the checks of db_crl::newCrl() that need no signature */
		if (!signkey || signkey->isPubKey())
			throw serviceError(ca->isCA() ? "no_private_signing_key" :
				"issuer_not_ca", QObject::tr(
				"There is no private key for '%1'")
				.arg(ca->getIntName()));
		AuditParams params;
		IssuanceChecks::crlIssuer(ca, signkey, job.hashAlgo, params);
		unlockCheck(signkey);
		ctx.result->planned("crl", ca->getIntName());
		QJsonObject r;
		r["ca_id"] = ca->getSqlItemId().toLongLong();
		r["ca_name"] = ca->getIntName();
		r["crl_id"] = QJsonValue();
		r["this_update"] = JsonReport::timestamp(job.lastUpdate);
		r["next_update"] = JsonReport::timestamp(job.nextUpdate);
		r["reissue_fraction"] = policy.reissueFraction;
		r["size_budget"] = policy.sizeBudget;
		r["trigger"] = trigger;
		if (report)
			ctx.result->append("crls", r);
		ctx.step = step;
		return nullptr;
	}
	pki_crl *crl = Database.model<db_crl>()->newCrl(ctx.svc, job);
	ctx.result->written(crl);
	QJsonObject r = crlReport(crl, policy, nowSeconds());
	r["trigger"] = trigger;
	if (report) {
		ctx.result->append("crls", r);
		budgetWarning(ctx, r);
	}
	ctx.step = step;
	return crl;
}

pki_crl *reissueIfDue(CommandContext &ctx, pki_x509 *ca,
		const CrlPolicy &policy)
{
	pki_crl *latest = CrlPolicy::latestCrl(ca);
	if (!latest || !policy.reissueDue(latest, nowSeconds()))
		return nullptr;
	pki_key *key = ca->getRefKey();
	if (!key || key->isPubKey())
		return nullptr;
	return issueCrl(ctx, ca, policy, "reissue_due");
}

/* --- revoke ------------------------------------------------------------- */

/* The RFC 5280 names in the order of x509rev::crlreasons(), which holds
 * the display names ("Key Compromise") that x509rev::setReason() takes.
 * removeFromCRL belongs to delta CRLs only and is refused. */
static const QStringList rfcReasons { "unspecified", "keyCompromise",
	"CACompromise", "affiliationChanged", "superseded",
	"cessationOfOperation", "certificateHold", "removeFromCRL",
	"privilegeWithdrawn", "AACompromise" };

/* The display name for x509rev; *rfc receives the RFC 5280 name */
static QString reasonName(const QString &given, QString *rfc)
{
	QStringList display = x509rev::crlreasons();
	for (int i = 0; i < rfcReasons.size() && i < display.size(); i++) {
		if (rfcReasons[i] == "removeFromCRL")
			continue;
		if (rfcReasons[i].compare(given, Qt::CaseInsensitive) == 0 ||
		    display[i].compare(given, Qt::CaseInsensitive) == 0) {
			*rfc = rfcReasons[i];
			return display[i];
		}
	}
	QStringList l = rfcReasons;
	l.removeAll("removeFromCRL");
	throw usageError("invalid_reason", QObject::tr(
		"--reason '%1' is not one of %2").arg(given, l.join(", ")));
}

static QString hexOnly(QString s)
{
	return s.remove(':').toUpper();
}

static pki_x509 *byFingerprint(const QString &given)
{
	static const QRegularExpression sha256("^[0-9A-F]{64}$");
	QString fp = hexOnly(given.trimmed());
	if (fp.startsWith("SHA256", Qt::CaseInsensitive))
		fp = fp.mid(6);
	if (!sha256.match(fp).hasMatch())
		throw usageError("invalid_fingerprint", QObject::tr(
			"--fingerprint '%1' is no SHA-256 fingerprint (64 hex "
			"digits, colons allowed)").arg(given));
	QList<pki_x509 *> hits;
	for (pki_x509 *c : Store.getAll<pki_x509>())
		if (hexOnly(c->fingerprint(EVP_sha256())) == fp)
			hits << c;
	if (hits.isEmpty())
		throw serviceError("unknown_reference", QObject::tr(
			"--fingerprint: no certificate with the SHA-256 "
			"fingerprint %1").arg(given));
	/* the same DER twice cannot be stored; kept for safety */
	if (hits.size() > 1)
		throw serviceError("ambiguous_reference", QObject::tr(
			"--fingerprint %1 matches %2 certificates")
			.arg(given).arg(hits.size()));
	return hits[0];
}

static void cmdRevoke(CommandContext &ctx)
{
	const Options &o = ctx.opts;
	int selectors = (o.args().isEmpty() ? 0 : 1) +
		(o.has("serial") ? 1 : 0) + (o.has("fingerprint") ? 1 : 0);
	if (selectors == 0)
		throw usageError("missing_argument", QObject::tr(
			"revoke needs a certificate, --serial with --ca or "
			"--fingerprint"));
	if (selectors > 1)
		throw usageError("conflicting_options", QObject::tr(
			"revoke takes one of a certificate reference, --serial "
			"and --fingerprint"));
	if (o.has("serial") && !o.has("ca"))
		throw usageError("missing_option", QObject::tr(
			"--serial needs --ca: a serial number is unique per "
			"issuer only"));
	QString rfcReason;
	QString reason = reasonName(o.value("reason"), &rfcReason);
	checkOutOptions(ctx, false);

	pki_x509 *ca = nullptr, *cert = nullptr, *issuer = nullptr;
	db_x509 *certs = Database.model<db_x509>();
	try {
		if (o.has("ca"))
			ca = resolveAs<pki_x509>(o.value("ca"), "certificate",
						"--ca");
		if (o.has("serial"))
			/* hex (digits only too) or dec:<decimal>;
			 * unknown_serial */
			cert = certs->certBySerial(ca, o.value("serial"));
		else if (o.has("fingerprint"))
			cert = byFingerprint(o.value("fingerprint"));
		else
			cert = resolveAs<pki_x509>(o.args()[0], "certificate",
						"<certificate>");
		issuer = cert->getSigner();
		if (ca && issuer != ca)
			throw serviceError("wrong_issuer", QObject::tr(
				"'%1' is issued by %2, not by --ca '%3'")
				.arg(cert->getIntName())
				.arg(issuer ? QString("'%1'").arg(
					issuer->getIntName()) :
					QObject::tr("a CA outside the database"))
				.arg(ca->getIntName()));
	} catch (serviceError &err) {
		AuditParams p;
		p.set("reason", reason);
		for (const QString &n : { QString("serial"),
					QString("fingerprint") })
			if (o.has(n))
				p.set(n, o.value(n));
		if (!o.args().isEmpty())
			p.set("name", o.args()[0]);
		if (ca)
			p.set("issuer", ca->getIntName());
		auditRefusal(ctx, "certificate.revoke", cert, p, err.code);
		throw;
	}

	x509rev rev;
	rev.setReason(reason);
	if (o.has("invalidity-date"))
		rev.setInvalDate(parseTimestamp(o.value("invalidity-date"),
					"invalidity-date"));
	ctx.step = QObject::tr("revocation of '%1'").arg(cert->getIntName());

	QJsonObject r;
	r["certificate_id"] = cert->getSqlItemId().toLongLong();
	r["certificate_name"] = cert->getIntName();
	r["serial"] = JsonReport::serial(cert->getSerial());
	r["reason"] = rfcReason;
	if (issuer) {
		r["ca_id"] = issuer->getSqlItemId().toLongLong();
		r["ca_name"] = issuer->getIntName();
	}
	if (ctx.plan) {
		/* the checks of db_x509::revoke() */
		if (!issuer)
			throw serviceError("unknown_issuer", QObject::tr(
				"The issuer of '%1' is not in the database")
				.arg(cert->getIntName()));
		if (issuer == cert)
			throw serviceError("self_signed", QObject::tr(
				"The self-signed certificate '%1' has no issuer "
				"to revoke it").arg(cert->getIntName()));
		if (cert->isRevoked())
			throw serviceError("already_revoked", QObject::tr(
				"The certificate '%1' is already revoked")
				.arg(cert->getIntName()));
		ctx.result->set("revocation", r);
		issueCrl(ctx, issuer, CrlPolicy::of(issuer), "revoke");
		writeOut(ctx, nullptr, "crl", issuer->getIntName());
		return;
	}
	certs->revoke(ctx.svc, cert, rev);
	r["revocation_date"] = JsonReport::timestamp(
				cert->getRevocation().getDate());
	ctx.result->set("revocation", r);
	/* the CRL of the issuing CA at once, through the same key unlock
	 * as sign and crl */
	pki_crl *crl = issueCrl(ctx, issuer, CrlPolicy::of(issuer), "revoke");
	writeOut(ctx, crl, "crl");
}

/* --- crl ---------------------------------------------------------------- */

static void cmdCrl(CommandContext &ctx)
{
	const Options &o = ctx.opts;
	checkOutOptions(ctx, false);
	pki_x509 *ca = resolveAs<pki_x509>(o.value("ca"), "certificate",
					"--ca");
	CrlPolicy policy = crlPolicy(o, ca);
	QDateTime thisUpdate;
	if (o.has("this-update"))
		thisUpdate = parseTimestamp(o.value("this-update"),
					"this-update");
	/* the given settings become the CA's */
	if (hasCrlOptions(o) && !ctx.plan) {
		ctx.step = QObject::tr("CRL settings of '%1'")
				.arg(ca->getIntName());
		policy.store(ctx.svc, ca);
	}
	pki_crl *crl = issueCrl(ctx, ca, policy, "command", thisUpdate);
	writeOut(ctx, crl, "crl", ca->getIntName());
}

/* --- Registration ------------------------------------------------------- */

void registerLifecycleCommands(Registry &r)
{
	Command c;
	c.name = "revoke";
	c.usage = "[<certificate>]";
	c.summary = QObject::tr("revoke a certificate and issue the new CRL "
				"of its CA");
	c.description = QObject::tr(
		"  The certificate is a database id or a unique name (an "
		"ambiguous name is refused\n  with the candidates), or "
		"--serial (hex as XCA shows it, with or without 0x\n  and "
		"colons, also digits only; decimal as dec:<digits>) with "
		"--ca, or\n  --fingerprint (SHA-256). --reason is "
		"required; with --ca the issuer must be that\n  CA. The "
		"CRL of the issuing CA is issued at once (rule 8 of PLAN.md "
		"8.4).");
	c.options = QList<OptionSpec> {
		opt("reason", OptionSpec::string, "<reason>", QObject::tr(
			"RFC 5280 reason: unspecified, keyCompromise, "
			"CACompromise, affiliationChanged, superseded, "
			"cessationOfOperation, certificateHold, "
			"privilegeWithdrawn, AACompromise"), false, true),
		opt("serial", OptionSpec::string, "<serial>", QObject::tr(
			"the serial number of the certificate, hex or "
			"dec:<digits> (needs --ca)")),
		opt("fingerprint", OptionSpec::string, "<sha256>",
			QObject::tr("the SHA-256 fingerprint of the "
			"certificate")),
		opt("ca", OptionSpec::reference, "<ca>", QObject::tr(
			"the issuing CA; the certificate must be one of its")),
		opt("invalidity-date", OptionSpec::timestamp, "<date-time>",
			QObject::tr("RFC 3339: since when the key is known or "
			"suspected to be compromised")),
	} + outOptions(false);
	c.maxArgs = 1;
	c.writes = true;
	c.handler = cmdRevoke;
	r.add(c);

	c = Command();
	c.name = "crl";
	c.summary = QObject::tr("issue a new CRL of a CA");
	c.description = QObject::tr(
		"  Next CRL number, nextUpdate = thisUpdate + the CRL validity "
		"of the CA. Given\n  --crl-* options become the CA's stored "
		"CRL settings. Publishing to targets\n  is Phase 4.");
	c.options = QList<OptionSpec> {
		opt("ca", OptionSpec::reference, "<ca>",
			QObject::tr("the CA certificate"), false, true),
		opt("this-update", OptionSpec::timestamp, "<date-time>",
			QObject::tr("thisUpdate, RFC 3339 (default: now)")),
		opt("hash", OptionSpec::string, "<digest>", QObject::tr(
			"signature digest (default: the database default; "
			"none for EdDSA, ML-DSA and SLH-DSA)")),
	} + crlOptions(QObject::tr("; stored as the CA's setting")) +
		outOptions(false);
	c.writes = true;
	c.handler = cmdCrl;
	r.add(c);
}

} // namespace bxcpki
