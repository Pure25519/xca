/* vi: set sw=4 ts=4:
 *
 * The commands of bxc-pki part 1 (BTD-41): init, request-cert, sign,
 * list, show. Each handler works on the service layer only and can run
 * inside a caller-owned transaction (cli.h, runInTransaction()).
 */

#include <algorithm>

#include <openssl/evp.h>
#include <openssl/objects.h>

#include "lib/BioByteArray.h"
#include "lib/crl_policy.h"
#include "lib/database_model.h"
#include "lib/db_key.h"
#include "lib/db_temp.h"
#include "lib/db_x509.h"
#include "lib/db_x509req.h"
#include "lib/digest.h"
#include "lib/func.h"
#include "lib/issuance.h"
#include "lib/issuance_checks.h"
#include "lib/json_report.h"
#include "lib/pki_crl.h"
#include "lib/pki_key.h"
#include "lib/pki_multi.h"
#include "lib/pki_temp.h"
#include "lib/pki_x509.h"
#include "lib/pki_x509req.h"
#include "lib/request.h"
#include "lib/template.h"
#include "lib/x509name.h"
#include "cli.h"

namespace bxcpki {

OptionSpec opt(const QString &name, enum OptionSpec::kind type,
		const QString &valueName, const QString &help,
		bool repeatable, bool required)
{
	OptionSpec o;
	o.name = name;
	o.type = type;
	o.valueName = valueName;
	o.help = help;
	o.repeatable = repeatable;
	o.required = required;
	return o;
}

/* --- Shared pieces ---------------------------------------------------- */

static x509name commonName(const QString &cn)
{
	x509name n;
	X509_NAME *name = X509_NAME_new();
	QByteArray v = cn.toUtf8();
	X509_NAME_add_entry_by_NID(name, NID_commonName, V_ASN1_UTF8STRING,
		(const unsigned char *)v.constData(), v.size(), -1, 0);
	n = x509name(name);
	X509_NAME_free(name);
	return n;
}

/* --cn or --subject; empty if neither (CN never from IP or URI) */
static x509name subjectFrom(const Options &o)
{
	if (o.has("subject"))
		return parseDn(o.value("subject"));
	if (o.has("cn"))
		return commonName(o.value("cn"));
	return x509name();
}

digest hashFrom(const Options &o, const pki_key *signKey)
{
	if (!o.has("hash")) {
		/* Key types without size or curve (EdDSA, ML-DSA, SLH-DSA)
		 * sign without a separate digest; the dialogs' digest list
		 * keeps SHA-256 for ML-DSA/SLH-DSA until BTD-164 */
		if (signKey && keytype::byType(signKey->getKeyType()).fixed())
			return digest(QString());
		return digest::getDefault();
	}
	QString name = o.value("hash");
	int nid = OBJ_txt2nid(name.toLatin1().constData());
	ign_openssl_error();
	if (!digest::all_digests.contains(nid))
		throw usageError("invalid_hash", QObject::tr(
			"--hash '%1' is not one of the digests XCA signs with")
			.arg(name));
	return digest(nid);
}

QDateTime nowSeconds()
{
	QDateTime t = QDateTime::currentDateTimeUtc();
	t.setTime(QTime(t.time().hour(), t.time().minute(),
			t.time().second()));
	return t;
}

/* Rule 6: --not-before or now - --backdate; --not-after or a duration
 * (--validity, else the template's period, else def) */
static void applyValidity(const Options &o, IssuanceSpec &spec,
		const IsoDuration &def, bool fromTemplate)
{
	/* the period of a template, kept for the new start: a template
	 * starts at the minute (or midnight), which may be before the
	 * start of a CA made in the same minute (issuer_not_yet_valid) */
	a1time tmplStart = spec.notBefore, tmplEnd = spec.notAfter;

	if (o.has("not-before"))
		spec.notBefore = parseTimestamp(o.value("not-before"),
					"not-before");
	else if (o.has("backdate"))
		spec.notBefore = a1time(parseDuration(o.value("backdate"),
				"backdate").subtractFrom(nowSeconds()));
	else
		spec.notBefore = a1time(nowSeconds());

	if (o.has("not-after")) {
		spec.notAfter = parseTimestamp(o.value("not-after"),
					"not-after");
		spec.validity = IsoDuration();
	} else if (o.has("validity")) {
		spec.validity = parseDuration(o.value("validity"), "validity");
	} else if (!fromTemplate) {
		spec.validity = def;
	} else if (!tmplEnd.isUndefined()) {
		spec.notAfter = a1time(((QDateTime)spec.notBefore).addSecs(
			((QDateTime)tmplStart).secsTo(tmplEnd)));
	}
	a1time end = spec.requestedNotAfter();
	/* no certificate ends after 9999 (review of xca#54: P10000Y) */
	if (!end.isValid() || (!end.isUndefined() &&
			(QDateTime)end > IsoDuration::lastEnd()))
		throw usageError("invalid_validity", QObject::tr(
			"The certificate would end after %1")
			.arg(IsoDuration::lastEnd().toString(Qt::ISODate)));
	if (!end.isUndefined() && end <= spec.notBefore)
		throw usageError("invalid_validity", QObject::tr(
			"The certificate would end on %1, not after its start "
			"on %2").arg(end.toPrettyGMT())
			.arg(spec.notBefore.toPrettyGMT()));
}

static QList<OptionSpec> validityOptions(const QString &def)
{
	return QList<OptionSpec> {
		opt("validity", OptionSpec::duration, "<duration>", QObject::tr(
			"validity period as ISO 8601 duration, e.g. P20Y, P1Y6M, "
			"P90D (default %1); the end is capped at the issuer "
			"chain and the cap is reported (validity_capped)")
			.arg(def)),
		opt("not-before", OptionSpec::timestamp, "<date-time>",
			QObject::tr("start, RFC 3339 (default: now)")),
		opt("not-after", OptionSpec::timestamp, "<date-time>",
			QObject::tr("end, RFC 3339, instead of --validity")),
		opt("backdate", OptionSpec::duration, "<duration>",
			QObject::tr("start this long before now, e.g. PT5M "
			"(default PT0S)")),
		opt("hash", OptionSpec::string, "<digest>", QObject::tr(
			"signature digest, e.g. sha256, sha384, sha512 (default: "
			"the database default; none for Ed25519)")),
	};
}

static QList<QPair<QString, QString> > validityConflicts()
{
	return QList<QPair<QString, QString> > {
		{ "validity", "not-after" }, { "not-before", "backdate" },
	};
}

/* The key of a new object: --use-key <ref>, --key-file <file> (not
 * stored) or a new key of type --key. A new key is written and recorded. */
static pki_key *obtainKey(CommandContext &ctx, const QString &name,
		const QString &defaultType, pki_multi *fileItems)
{
	const Options &o = ctx.opts;
	if (o.has("use-key")) {
		pki_key *key = resolveAs<pki_key>(o.value("use-key"), "key",
						"--use-key");
		if (!key || key->isPubKey())
			throw serviceError("no_private_key", QObject::tr(
				"--use-key '%1' has no private key")
				.arg(o.value("use-key")));
		return key;
	}
	if (o.has("key-file")) {
		fileItems->probeAnything(o.value("key-file"));
		for (pki_base *pki : fileItems->get()) {
			pki_key *key = dynamic_cast<pki_key *>(pki);
			if (key && !key->isPubKey())
				return key;
		}
		throw serviceError("no_private_key", QObject::tr(
			"--key-file '%1' holds no private key")
			.arg(o.value("key-file")));
	}
	keyjob job(keyJobText(o.value("key", defaultType)));
	ctx.step = QObject::tr("key '%1'").arg(name);
	if (ctx.plan) {
		/* --plan generates nothing; the name fixes a valid job */
		ctx.result->planned("key", name);
		return nullptr;
	}
	pki_key *key = Database.model<db_key>()->newKey(ctx.svc, job, name);
	ctx.result->written(key);
	return key;
}

/* --plan: the key would sign; decrypting it checks its password (or
 * PIN) without making a signature */
void unlockCheck(const pki_key *key)
{
	if (!key)
		return;
	EVP_PKEY *pkey = key->decryptKey();
	EVP_PKEY_free(pkey);
}

/* --plan of an issuance: the checks of db_x509::issue() that need no
 * signature (IssuanceChecks::preflight(): spec, issuer chain, CSR), the
 * private key of the signer, its unlock and the validity cap; the
 * extension checks run only when the certificate is built. Nothing is
 * signed, so the result has no document (review of xca#54). */
static void planCertificate(CommandContext &ctx, IssuanceSpec &spec)
{
	AuditParams params;
	pki_key *signkey = spec.signer ? spec.signer->getRefKey() : spec.key;
	if (spec.signer && (!signkey || signkey->isPubKey()))
		throw serviceError("no_private_signing_key", QObject::tr(
			"The key you selected for signing is not a private one."));
	IssuanceChecks::preflight(spec, params);
	unlockCheck(signkey);
	bool capped;
	a1time end = spec.effectiveNotAfter(&capped);
	if (capped && end <= spec.notBefore)
		throw serviceError("invalid_validity", QObject::tr(
			"The issuer chain ends on %1, not after the start of the "
			"certificate on %2").arg(end.toPrettyGMT())
			.arg(spec.notBefore.toPrettyGMT()));
	ctx.result->plannedCertificate(spec);
}

static QList<OptionSpec> keyOptions(const QString &def, bool withFile)
{
	QList<OptionSpec> l {
		opt("key", OptionSpec::string, "<type>", QObject::tr(
			"type of the new key, the names of the bootstrap file: "
			"%1 (default %2)")
			.arg(supportedKeyTypes().join(", ")).arg(def)),
		opt("use-key", OptionSpec::reference, "<key>", QObject::tr(
			"use this key of the database instead of a new one")),
	};
	if (withFile)
		l << opt("key-file", OptionSpec::string, "<file>", QObject::tr(
			"use the private key of this file (PEM, DER, PKCS#8; "
			"encrypted: --import-pass); it is not stored"));
	return l;
}

static QString nameFrom(const Options &o, const x509name &subject,
		const QStringList &sans)
{
	if (o.has("name"))
		return o.value("name");
	QString cn = subject.getEntryByNid(NID_commonName);
	if (!cn.isEmpty())
		return cn;
	if (subject.entryCount() > 0)
		return subject.getEntry(subject.entryCount() - 1);
	return sans.isEmpty() ? QString() : sans.first().section(':', 1);
}

/* --- init ------------------------------------------------------------- */

static void cmdInit(CommandContext &ctx)
{
	const Options &o = ctx.opts;
	IssuanceSpec spec;
	pki_x509 *parent = nullptr;

	spec.subject = subjectFrom(o);
	if (spec.subject.entryCount() == 0)
		throw usageError("missing_option",
			QObject::tr("init needs --cn or --subject"));
	if (o.has("parent")) {
		parent = resolveAs<pki_x509>(o.value("parent"), "certificate",
						"--parent");
		spec.signer = parent;
	}
	spec.name = nameFrom(o, spec.subject, QStringList());
	applyValidity(o, spec, parseDuration(parent ? "P5Y" : "P10Y",
				"validity"), false);

	ExtensionSpec &e = spec.extensions;
	e.basicCA = ExtensionSpec::bc_ca;
	e.basicCritical = true;
	/* rule 1: only explicit; absent means no constraint, never 0 */
	if (o.has("path-len"))
		e.pathLen = QString::number(o.value("path-len").toInt());
	e.subjectKeyId = true;
	e.authorityKeyId = true;
	e.keyUsage << "keyCertSign" << "cRLSign";
	e.keyUsageCritical = true;
	e.netscape = false;

	/* the CRL settings and --out before anything is generated */
	CrlPolicy policy = crlPolicy(o, nullptr);
	checkOutOptions(ctx, true);

	pki_multi fileItems;
	spec.key = obtainKey(ctx, spec.name, "ec-p384", &fileItems);
	spec.hashAlgo = hashFrom(o, parent ? parent->getRefKey() : spec.key);
	ctx.step = QObject::tr("certificate '%1'").arg(spec.name);
	if (ctx.plan) {
		planCertificate(ctx, spec);
		/* rule 7: the empty CRL of the new CA */
		ctx.result->planned("crl", spec.name);
		writeOut(ctx, spec.key, "key", spec.name);
		writeOut(ctx, nullptr, "crt", spec.name);
		writeOut(ctx, nullptr, "crl", spec.name);
		return;
	}
	pki_x509 *cert = Database.model<db_x509>()->newCert(ctx.svc, spec);
	ctx.result->writtenCertificate(cert, spec);
	if (hasCrlOptions(o)) {
		ctx.step = QObject::tr("CRL settings of '%1'").arg(spec.name);
		policy.store(ctx.svc, cert);
	}
	/* rule 7: a new CA issues its empty CRL at once; a CA that is not
	 * valid now (--not-before in the future, --not-after in the past)
	 * cannot sign one (IssuanceChecks::crlIssuer) */
	pki_crl *crl = nullptr;
	QDateTime now = nowSeconds();
	if ((QDateTime)cert->getNotBefore() <= now &&
	    now < (QDateTime)cert->getNotAfter())
		crl = issueCrl(ctx, cert, policy, "init");
	else
		ctx.result->warning("crl_not_issued", QObject::tr(
			"The CA '%1' is not valid now (%2 to %3); it issues "
			"its first CRL with 'bxc-pki crl --ca' while it is")
			.arg(cert->getIntName())
			.arg(cert->getNotBefore().toPrettyGMT())
			.arg(cert->getNotAfter().toPrettyGMT()));
	writeOut(ctx, spec.key, "key");
	writeOut(ctx, cert, "crt");
	if (crl)
		writeOut(ctx, crl, "crl");
}

/* --- request-cert ----------------------------------------------------- */

static void cmdRequestCert(CommandContext &ctx)
{
	const Options &o = ctx.opts;
	RequestSpec spec;
	QStringList sans;

	spec.subject = subjectFrom(o);
	for (const QString &v : o.all("dns"))
		sans << "DNS:" + checkDns(v);
	for (const QString &v : o.all("ip"))
		sans << "IP:" + checkIp(v);
	for (const QString &v : o.all("uri"))
		sans << "URI:" + checkUri(v);
	for (const QString &v : o.all("email"))
		sans << "email:" + checkEmail(v);
	if (spec.subject.entryCount() == 0 && sans.isEmpty())
		throw usageError("missing_option", QObject::tr(
			"request-cert needs --cn, --subject or a SAN (--dns, "
			"--ip, --uri, --email)"));
	/* RFC 5280 4.2.1.6: without a subject the SAN is critical */
	if (!sans.isEmpty())
		spec.extensions.subjectAltName =
			(spec.subject.entryCount() == 0 ? "critical, " : "") +
			sans.join(", ");
	spec.extensions.netscape = false;
	spec.name = nameFrom(o, spec.subject, sans);
	if (spec.name.isEmpty())
		throw usageError("missing_option",
			QObject::tr("request-cert needs --name"));

	checkOutOptions(ctx, !o.has("key-file"));

	pki_multi fileItems;
	spec.key = obtainKey(ctx, spec.name, "ec-p256", &fileItems);
	spec.hashAlgo = hashFrom(o, spec.key);
	ctx.step = QObject::tr("request '%1'").arg(spec.name);
	if (ctx.plan) {
		/* the key that would sign the request must unlock */
		unlockCheck(spec.key);
		ctx.result->planned("request", spec.name);
		if (!o.has("key-file"))
			writeOut(ctx, spec.key, "key", spec.name);
		writeOut(ctx, nullptr, "csr", spec.name);
		return;
	}
	pki_x509req *req = Database.model<db_x509req>()->newRequest(ctx.svc,
								spec);
	ctx.result->written(req);
	/* a --key-file key is not stored, so it is not written either */
	if (!o.has("key-file"))
		writeOut(ctx, spec.key, "key");
	writeOut(ctx, req, "csr");
}

/* --- sign ------------------------------------------------------------- */

static void cmdSign(CommandContext &ctx)
{
	const Options &o = ctx.opts;
	IssuanceSpec spec;

	pki_x509req *req = resolveAs<pki_x509req>(o.args().value(0),
					"request", "<request>");
	pki_x509 *ca = resolveAs<pki_x509>(o.value("ca"), "certificate",
					"--ca");
	bool fromTemplate = o.has("template");
	if (fromTemplate) {
		pki_temp *t = resolveAs<pki_temp>(o.value("template"),
					"template", "--template");
		/* subject, extensions and period of the template */
		TemplateSpec::fromTemplate(t).applyTo(spec, a1time(nowSeconds()));
	} else {
		/* rule 3: no EKU unless a template has one; no
		 * keyEncipherment but for RSA */
		ExtensionSpec &e = spec.extensions;
		e.basicCA = ExtensionSpec::bc_not_ca;
		e.basicCritical = true;
		e.subjectKeyId = true;
		e.authorityKeyId = true;
		e.keyUsage << "digitalSignature";
		pki_key *pub = req->getPubKey();
		if (pub && pub->getKeyType() == EVP_PKEY_RSA)
			e.keyUsage << "keyEncipherment";
		delete pub;
		e.keyUsageCritical = true;
	}
	spec.extensions.netscape = false;
	/* the subject of the request, never the template's */
	spec.subject = req->getSubject();
	spec.request = req;
	spec.signer = ca;
	/* Rules 3 and 4 with the merge modes of BTD-54: no other CSR
	 * extension is copied; the CSR's SAN is taken (the template's
	 * only without one); key usage and EKU as the template's merge
	 * settings say, without a template from the template part alone */
	ExtensionSpec &m = spec.extensions;
	spec.copyRequestExtensions = false;
	if (m.sanMerge == ExtensionSpec::merge_legacy)
		m.sanMerge = ExtensionSpec::merge_request;
	if (!fromTemplate)
		m.kuMerge = m.ekuMerge = ExtensionSpec::merge_template;
	spec.name = o.value("name", req->getIntName());
	applyValidity(o, spec, parseDuration("P1Y", "validity"),
			fromTemplate);
	spec.hashAlgo = hashFrom(o, ca->getRefKey());
	checkOutOptions(ctx, false);
	ctx.step = QObject::tr("certificate '%1'").arg(spec.name);
	if (ctx.plan) {
		planCertificate(ctx, spec);
		writeOut(ctx, nullptr, "crt", spec.name);
		reissueIfDue(ctx, ca, CrlPolicy::of(ca));
		return;
	}
	pki_x509 *cert = Database.model<db_x509>()->newCert(ctx.svc, spec);
	ctx.result->writtenCertificate(cert, spec);
	writeOut(ctx, cert, "crt");
	/* rule 7: a CRL of the CA past its re-issue point is renewed */
	reissueIfDue(ctx, ca, CrlPolicy::of(ca));
}

/* --- list and show (read only) --------------------------------------- */

static const QStringList objectTypes { "key", "certificate", "request",
					"crl", "template" };

static void checkType(const Options &o)
{
	if (o.has("type") && !objectTypes.contains(o.value("type")))
		throw usageError("invalid_value", QObject::tr(
			"--type '%1' is not one of %2").arg(o.value("type"))
			.arg(objectTypes.join(", ")));
}

static void cmdList(CommandContext &ctx)
{
	checkType(ctx.opts);
	QList<pki_base *> items;
	for (pki_base *pki : Store.getAll<pki_base>())
		if (!ctx.opts.has("type") || JsonReport::objectType(pki) ==
						ctx.opts.value("type"))
			items << pki;
	std::sort(items.begin(), items.end(), [](pki_base *a, pki_base *b) {
		return a->getSqlItemId().toLongLong() <
			b->getSqlItemId().toLongLong();
	});
	if (!ctx.text) {
		JsonReport::write(stdout, JsonReport::itemList(items));
		return;
	}
	QString s;
	for (pki_base *pki : items)
		s += QString("%1 %2 %3\n").arg(pki->getSqlItemId().toString(), 6)
			.arg(JsonReport::objectType(pki), -12)
			.arg(pki->getIntName());
	console_write(stdout, s.toUtf8());
}

static void showItem(CommandContext &ctx, pki_base *pki)
{
	if (!ctx.text) {
		QJsonObject doc = JsonReport::object(pki);
		if (doc.isEmpty())
			throw serviceError("unsupported_type", QObject::tr(
				"No JSON document for '%1'")
				.arg(pki->getIntName()));
		JsonReport::write(stdout, doc);
		return;
	}
	BioByteArray bba;
	pki->print(bba, pki_base::print_openssl_txt);
	console_write(stdout, bba.byteArray());
}

static void cmdShow(CommandContext &ctx)
{
	const Options &o = ctx.opts;
	checkType(o);
	if (o.has("file")) {
		if (!o.args().isEmpty())
			throw usageError("conflicting_options", QObject::tr(
				"show takes a reference or --file, not both"));
		pki_multi items;
		items.probeAnything(o.value("file"));
		if (items.get().isEmpty())
			throw serviceError("no_pki_data", QObject::tr(
				"'%1' holds no certificate, key, request, CRL "
				"or template").arg(o.value("file")));
		for (pki_base *pki : items.get())
			showItem(ctx, pki);
		return;
	}
	if (o.args().isEmpty())
		throw usageError("missing_argument",
			QObject::tr("show needs a reference or --file"));
	ctx.openDatabase();
	QStringList kinds;
	if (o.has("type"))
		kinds << o.value("type");
	for (const QString &ref : o.args())
		showItem(ctx, resolve(ref, kinds, "<reference>"));
}

/* --- Registration ----------------------------------------------------- */

void registerCommands(Registry &r)
{
	Command c;
	c.name = "init";
	c.summary = QObject::tr("create a root CA, or with --parent an "
				"intermediate CA (key and certificate)");
	c.description = QObject::tr(
		"  basicConstraints CA:TRUE critical, keyUsage keyCertSign and "
		"cRLSign critical,\n  subject and authority key identifier. "
		"Without --path-len the path length is\n  not constrained "
		"(never an implicit 0). Default validity P10Y, P5Y with "
		"--parent.\n  The empty CRL of the new CA is issued at once "
		"(rule 7).");
	c.options = QList<OptionSpec> {
		opt("cn", OptionSpec::string, "<name>",
			QObject::tr("subject CN (UTF8String)")),
		opt("subject", OptionSpec::string, "<RFC 4514 DN>",
			QObject::tr("full subject, e.g. \"CN=BxC Root,O=BxC,"
			"DC=lab,DC=example\"; order kept, '+' for multi-valued "
			"RDNs")),
		opt("name", OptionSpec::string, "<name>", QObject::tr(
			"internal name of key and certificate (default: CN)")),
		opt("parent", OptionSpec::reference, "<ca>", QObject::tr(
			"issuing CA: creates an intermediate CA")),
		opt("path-len", OptionSpec::integer, "<n>", QObject::tr(
			"basicConstraints pathLenConstraint; only when given")),
	} + keyOptions("ec-p384", false) + validityOptions("P10Y") +
		crlOptions(QObject::tr("; stored as the CA's setting")) +
		outOptions(true);
	c.conflicts = QList<QPair<QString, QString> > {
		{ "cn", "subject" }, { "key", "use-key" },
		{ "key-unencrypted", "no-key-file" } } +
		validityConflicts();
	c.writes = true;
	c.handler = cmdInit;
	r.add(c);

	c = Command();
	c.name = "request-cert";
	c.summary = QObject::tr("create a key and a certificate signing "
				"request");
	c.description = QObject::tr(
		"  SANs from --dns, --ip, --uri and --email; a request with a "
		"URI only is allowed.\n  The CN is never taken from an IP "
		"address or URI. No keyUsage or extended key\n  usage in the "
		"request: they come from the template when signing.");
	c.options = QList<OptionSpec> {
		opt("cn", OptionSpec::string, "<name>",
			QObject::tr("subject CN (UTF8String)")),
		opt("subject", OptionSpec::string, "<RFC 4514 DN>",
			QObject::tr("full subject, see init")),
		opt("dns", OptionSpec::string, "<name>",
			QObject::tr("SAN dNSName"), true),
		opt("ip", OptionSpec::string, "<address>",
			QObject::tr("SAN iPAddress, IPv4 or IPv6"), true),
		opt("uri", OptionSpec::string, "<uri>", QObject::tr(
			"SAN uniformResourceIdentifier, e.g. the OPC UA "
			"ApplicationUri urn:..."), true),
		opt("email", OptionSpec::string, "<address>",
			QObject::tr("SAN rfc822Name"), true),
		opt("name", OptionSpec::string, "<name>", QObject::tr(
			"internal name of key and request (default: CN, else "
			"the first SAN)")),
		opt("hash", OptionSpec::string, "<digest>", QObject::tr(
			"signature digest of the request (default: the database "
			"default; none for Ed25519)")),
	} + keyOptions("ec-p256", true) + outOptions(true);
	c.conflicts = QList<QPair<QString, QString> > {
		{ "cn", "subject" }, { "key", "use-key" },
		{ "use-key", "key-file" }, { "key", "key-file" },
		{ "key-unencrypted", "no-key-file" } };
	c.writes = true;
	c.handler = cmdRequestCert;
	r.add(c);

	c = Command();
	c.name = "sign";
	c.usage = "<request>";
	c.summary = QObject::tr("issue a certificate for a request with a CA");
	c.description = QObject::tr(
		"  Subject and SAN from the request; keyUsage and extended key "
		"usage only from\n  --template. Without a template: CA:FALSE, "
		"keyUsage digitalSignature (and\n  keyEncipherment for RSA), "
		"no extended key usage. Default validity P1Y, or\n  the "
		"period of the template.");
	c.options = QList<OptionSpec> {
		opt("ca", OptionSpec::reference, "<ca>",
			QObject::tr("issuing CA certificate"), false, true),
		opt("template", OptionSpec::reference, "<template>",
			QObject::tr("template of the database or a predefined "
			"one (CA, TLS_server, TLS_client)")),
		opt("profile", OptionSpec::string, "<profile>", QString()),
		opt("name", OptionSpec::string, "<name>", QObject::tr(
			"internal name of the certificate (default: the "
			"request's)")),
	} + validityOptions("P1Y") + outOptions(false);
	for (OptionSpec &s : c.options)
		if (s.name == "profile") {
			s.help = QObject::tr("certificate profile");
			s.reserved = QObject::tr("profiles come in Phase 2; "
					"use --template");
		}
	c.conflicts = validityConflicts();
	c.minArgs = c.maxArgs = 1;
	c.writes = true;
	c.handler = cmdSign;
	r.add(c);

	registerLifecycleCommands(r);
	registerExportCommands(r);

	c = Command();
	c.name = "list";
	c.summary = QObject::tr("list the objects of the database");
	c.options = QList<OptionSpec> {
		opt("type", OptionSpec::string, "<type>",
			QObject::tr("only %1").arg(objectTypes.join(", "))),
	};
	c.handler = cmdList;
	r.add(c);

	c = Command();
	c.name = "show";
	c.usage = "<reference>...";
	c.summary = QObject::tr("show objects as JSON documents (or text)");
	c.options = QList<OptionSpec> {
		opt("type", OptionSpec::string, "<type>", QObject::tr(
			"the reference names a %1").arg(objectTypes.join(", "))),
		opt("file", OptionSpec::string, "<file>", QObject::tr(
			"show the objects of a file instead (encrypted: "
			"--import-pass); nothing is stored")),
	};
	c.maxArgs = 100;
	/* --file reads no database */
	c.needsDatabase = false;
	c.handler = cmdShow;
	r.add(c);
}

} // namespace bxcpki
