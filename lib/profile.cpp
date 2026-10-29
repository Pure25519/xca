/* vi: set sw=4 ts=4:
 *
 * Certificate profiles of bxc-pki (BTD-54), see profile.h.
 */

#include "profile.h"

#include <QCoreApplication>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QRegularExpression>

#include <openssl/x509v3.h>

#include "exception.h"
#include "pki_key.h"
#include "pki_x509.h"
#include "pki_x509req.h"
#include "template.h"

static QString tr(const char *text)
{
	return QCoreApplication::translate("Profile", text);
}

static serviceError invalid(const QString &field)
{
	return serviceError("invalid_profile",
		tr("The profile has no valid '%1'").arg(field));
}

/* The key usage bits a profile may name: every bit for the family generic
 * (schema v1.1), the end-entity bits of the key family for opcua and tls
 * (never keyEncipherment on EC keys, PLAN.md 8.4 rule 3) */
static bool kuBitsAllowed(const QJsonObject &ku, bool generic)
{
	static const QMap<QString, QStringList> ot {
		{ "rsa", { "digitalSignature", "nonRepudiation",
			   "keyEncipherment", "dataEncipherment" } },
		{ "ec", { "digitalSignature", "nonRepudiation", "keyAgreement" } },
	};
	static const QStringList all { "digitalSignature", "nonRepudiation",
		"keyEncipherment", "dataEncipherment", "keyAgreement",
		"keyCertSign", "cRLSign", "encipherOnly", "decipherOnly" };
	for (auto f = ku.begin(); f != ku.end(); ++f) {
		if (!ot.contains(f.key()))
			return false;
		const QStringList &allowed = generic ? all : ot[f.key()];
		const QJsonArray bits = f.value().toObject()["bits"].toArray();
		if (bits.isEmpty())
			return false;
		for (const QJsonValue &b : bits) {
			if (!allowed.contains(b.toString()))
				return false;
		}
	}
	return true;
}

Profile Profile::fromJson(const QJsonObject &doc)
{
	Profile p;
	p.doc = doc;
	QString schema = doc["schema"].toString();
	if (schema != "urn:bxc-pki:schema:profile:v1" &&
	    schema != "urn:bxc-pki:schema:profile:v1.1")
		throw invalid("schema");
	p.id = doc["id"].toString();
	if (p.id.isEmpty())
		throw invalid("id");
	p.family = doc["family"].toString();
	if (p.family != "opcua" && p.family != "tls" && p.family != "generic")
		throw invalid("family");
	/* the family generic is new in schema v1.1 (BTD-167) */
	bool generic = p.family == "generic";
	if (generic && schema != "urn:bxc-pki:schema:profile:v1.1")
		throw invalid("schema");
	p.keySource = doc["key_source"].toString();
	if (p.keySource != "csr" && p.keySource != "server")
		throw invalid("key_source");
	for (const char *array : { "key_types" }) {
		if (!doc[array].isArray() || doc[array].toArray().isEmpty())
			throw invalid(array);
	}
	for (const char *object : { "ku_by_key_type", "basic_constraints",
			"san", "subject", "aki", "signature", "validity" }) {
		if (!doc[object].isObject())
			throw invalid(object);
	}
	/* a generic profile without EKU issues none (CA profiles) */
	if (!generic || doc.contains("eku")) {
		if (!doc["eku"].isObject())
			throw invalid("eku");
		if (doc["eku"].toObject()["purposes"].toArray().isEmpty())
			throw invalid("eku.purposes");
	}
	if (!kuBitsAllowed(doc["ku_by_key_type"].toObject(), generic))
		throw invalid("ku_by_key_type");
	/* opcua and tls: end entity, critical; generic: pathLen only for a CA */
	QJsonObject bc = doc["basic_constraints"].toObject();
	if (!bc["ca"].isBool() || !bc["critical"].isBool() ||
	    (!generic && (bc["ca"].toBool() || !bc["critical"].toBool() ||
			  bc.contains("path_len"))) ||
	    (bc.contains("path_len") && (!bc["ca"].toBool() ||
			!bc["path_len"].isDouble() ||
			bc["path_len"].toInt(-1) < 0)))
		throw invalid("basic_constraints");
	/* the CN as dNSName and e-mail addresses only in generic profiles */
	QJsonObject san = doc["san"].toObject();
	if (!generic && (san["dns_from_cn"].toBool() || san.contains("email")))
		throw invalid("san");
	/* Nexus-style default only outside OPC UA (PLAN.md 14.2 rule 5) */
	if (doc.contains("eku_default") && p.family != "tls")
		throw invalid("eku_default");
	if (doc["csr_sha1"].toString() != "accept-with-warning" &&
	    doc["csr_sha1"].toString() != "reject")
		throw invalid("csr_sha1");
	if (doc["keycertsign_request"].toString() != "reject" &&
	    doc["keycertsign_request"].toString() != "override")
		throw invalid("keycertsign_request");
	return p;
}

static serviceError notMigratable(const TemplateSpec &t, const QString &field)
{
	return serviceError("template_not_migratable",
		tr("The template '%1' cannot become a profile: a profile has no %2")
		.arg(t.name, field));
}

/* The migration rule of XCA templates (BTD-167), see profile.h */
QJsonObject Profile::fromTemplate(const TemplateSpec &t, const QString &id)
{
	const ExtensionSpec &e = t.extensions;
	/* fixed values a profile cannot hold: refused, never dropped */
	if (t.subject.entryCount() > 0)
		throw notMigratable(t, "subject");
	const QList<std::pair<QString, bool>> fixed {
		{ "subjectAltName", !e.subjectAltName.isEmpty() &&
			e.subjectAltName.simplified() != "DNS:copycn" },
		{ "nameConstraints", !e.nameConstraints.isEmpty() },
		{ "issuerAltName", !e.issuerAltName.isEmpty() },
		{ "crlDistPoints", !e.crlDistPoints.isEmpty() },
		{ "authInfoAccess", !e.authInfoAccess.isEmpty() },
		{ "ocspMustStaple", e.ocspMustStaple },
		{ "advanced", !e.advanced.trimmed().isEmpty() },
		{ "basicConstraints", e.basicCA == ExtensionSpec::bc_absent },
		{ "keyUsage", e.keyUsage.isEmpty() },
		{ "subjectKeyIdentifier", !e.subjectKeyId },
		{ "authorityKeyIdentifier", !e.authorityKeyId },
		{ "ekuDefault", !e.ekuDefault.isEmpty() || !e.ekuAllowed.isEmpty() },
		{ "midnight", t.midnight },
		{ "noWellDefinedExpDate", t.noWellDefinedExpDate },
	};
	for (const auto &f : fixed) {
		if (f.second)
			throw notMigratable(t, f.first);
	}

	QString name = id;
	if (name.isEmpty()) {
		name = "xca-" + t.name.toLower();
		name.replace(QRegularExpression("[^a-z0-9]+"), "-");
		name.remove(QRegularExpression("-+$"));
		name = name.left(63);
	}
	QJsonArray bits;
	for (const QString &b : e.keyUsage)
		bits << b;
	QJsonObject ku { { "bits", bits }, { "critical", e.keyUsageCritical } };
	QJsonObject bc { { "ca", e.basicCA == ExtensionSpec::bc_ca },
			 { "critical", e.basicCritical } };
	if (e.basicCA == ExtensionSpec::bc_ca && !e.pathLen.isEmpty())
		bc["path_len"] = e.pathLen.toInt();
	static const char *units[] = { "D", "M", "Y" };
	QString period = QString("P%1%2").arg(t.validity).arg(units[t.unit]);
	QJsonObject count { { "min", 0 }, { "max", 16 } };

	QJsonObject doc {
		{ "schema", "urn:bxc-pki:schema:profile:v1.1" },
		{ "id", name },
		{ "description", tr("Migrated from the XCA template '%1'%2")
			.arg(t.name, t.comment.isEmpty() ? QString() :
				": " + t.comment) },
		{ "family", "generic" },
		{ "key_source", "csr" },
		{ "key_types", QJsonArray{ "rsa-2048", "rsa-3072", "rsa-4096",
					"ec-p256", "ec-p384" } },
		{ "ku_by_key_type", QJsonObject{ { "rsa", ku }, { "ec", ku } } },
		{ "csr_eku", "ignore" },
		{ "csr_basic_constraints", "ignore" },
		{ "csr_aki_ski", "ignore" },
		{ "basic_constraints", bc },
		{ "san", QJsonObject{
			{ "uri", QJsonObject{ { "count", 0 } } },
			{ "dns", count }, { "ip", count }, { "email", count },
			{ "dns_or_ip_min", 0 }, { "keep_csr_order", true },
			{ "dns_from_cn", !e.subjectAltName.isEmpty() },
			{ "critical", false } } },
		{ "subject", QJsonObject{ { "copy", "byte-faithful" },
			{ "required_attributes", QJsonArray() },
			{ "add_missing_o", false }, { "cn_source", "csr" } } },
		{ "aki", QJsonObject{ { "form", e.authorityKeyIdIssuer ?
				"key-id-issuer-serial" : "key-id" } } },
		{ "signature", QJsonObject{
			{ "rsa", QJsonObject{ { "padding", "pkcs1v15" },
				{ "hashes", QJsonArray{ "sha256" } } } },
			{ "ec", QJsonObject{ { "hash_by_curve", QJsonObject{
				{ "ec-p256", "sha256" },
				{ "ec-p384", "sha384" } } } } } } },
		{ "validity", QJsonObject{ { "default", period },
			{ "max", period }, { "backdate", "PT0S" } } },
		{ "csr_sha1", "accept-with-warning" },
		{ "keycertsign_request", "override" },
		{ "warnings", QJsonArray() },
	};
	if (!e.extKeyUsage.isEmpty()) {
		QJsonArray purposes;
		for (const QString &p : e.extKeyUsage)
			purposes << p;
		doc["eku"] = QJsonObject{ { "purposes", purposes },
				{ "critical", e.extKeyUsageCritical } };
	}
	return doc;
}

Profile Profile::fromFile(const QString &path)
{
	QFile f(path);
	if (!f.open(QIODevice::ReadOnly))
		throw serviceError("invalid_profile",
			tr("The profile file '%1' cannot be read").arg(path));
	QJsonParseError err;
	QJsonDocument d = QJsonDocument::fromJson(f.readAll(), &err);
	if (err.error != QJsonParseError::NoError || !d.isObject())
		throw serviceError("invalid_profile",
			tr("The profile file '%1' is no JSON object: %2")
			.arg(path, err.errorString()));
	return fromJson(d.object());
}

QString Profile::keyType(const EVP_PKEY *pkey)
{
	if (!pkey)
		return QString();
	if (EVP_PKEY_is_a(pkey, "RSA"))
		return QString("rsa-%1").arg(EVP_PKEY_get_bits(pkey));
	if (EVP_PKEY_is_a(pkey, "EC")) {
		char group[80];
		size_t len = 0;
		if (!EVP_PKEY_get_group_name(pkey, group, sizeof group, &len))
			return "ec";
		static const QMap<QString, QString> curves {
			{ "prime256v1", "ec-p256" }, { "P-256", "ec-p256" },
			{ "secp384r1", "ec-p384" }, { "P-384", "ec-p384" },
			{ "secp521r1", "ec-p521" }, { "P-521", "ec-p521" },
		};
		return curves.value(QString::fromLatin1(group, len), "ec");
	}
	const char *name = EVP_PKEY_get0_type_name(pkey);
	return name ? QString(name).toLower() : QString();
}

/* now plus or minus an ISO 8601 duration such as P1Y, P90D, PT1H */
static QDateTime shifted(const QDateTime &now, const QString &iso, int sign)
{
	static const QRegularExpression re("^P(?:(\\d+)Y)?(?:(\\d+)M)?"
		"(?:(\\d+)W)?(?:(\\d+)D)?(?:T(?:(\\d+)H)?(?:(\\d+)M)?(?:(\\d+)S)?)?$");
	QRegularExpressionMatch m = re.match(iso);
	if (iso.isEmpty() || iso == "P" || !m.hasMatch())
		throw invalid("validity");
	auto n = [&](int i) { return sign * m.captured(i).toInt(); };
	return now.addYears(n(1)).addMonths(n(2)).addDays(7 * n(3) + n(4))
		.addSecs(3600LL * n(5) + 60 * n(6) + n(7));
}

static QStringList strings(const QJsonValue &v)
{
	QStringList list;
	for (const QJsonValue &s : v.toArray())
		list << s.toString();
	return list;
}

/* The first value of attribute nid in name, or a null string */
static QString entry(const x509name &name, int nid)
{
	int i = X509_NAME_get_index_by_NID(name.get0(), nid, -1);
	return i < 0 ? QString() : name.getEntry(i);
}

IssuanceSpec Profile::apply(pki_x509req *request, pki_key *key,
			const Registration &reg, pki_x509 *signer) const
{
	IssuanceSpec spec;
	ExtensionSpec &e = spec.extensions;
	CsrPolicy &policy = spec.csrPolicy;

	/* the key and where it comes from */
	EVP_PKEY *pkey = nullptr;
	if (keySource == "csr") {
		if (!request || key)
			throw serviceError("profile_key_source",
				tr("The profile '%1' signs a certificate signing request").arg(id));
		pkey = X509_REQ_get0_pubkey(request->getReq());
		spec.request = request;
		spec.name = request->getIntName();
	} else {
		if (!key || request)
			throw serviceError("profile_key_source",
				tr("The profile '%1' signs a key generated by bxc-pki").arg(id));
		pkey = key->getPubKey();
		spec.key = key;
	}
	QString type = keyType(pkey);
	if (!strings(doc["key_types"]).contains(type))
		throw serviceError("profile_key_type",
			tr("The profile '%1' does not allow a %2 key").arg(id, type));
	QString keyFamily = type.section('-', 0, 0);

	/* subject: the device's own, byte for byte, or normalized */
	QJsonObject subj = doc["subject"].toObject();
	x509name subject = request ? request->getSubject() : reg.subject;
	QString cnSource = subj["cn_source"].toString("csr");
	QString cn = cnSource == "user" ? reg.userName :
			cnSource == "https-host" ? reg.httpsHost : QString();
	if (subj["copy"].toString() == "normalized") {
		x509name n;
		QString o = entry(subject, NID_organizationName);
		if (!cn.isEmpty())
			n.addEntryByNid(NID_commonName, cn);
		else if (!entry(subject, NID_commonName).isEmpty())
			n.addEntryByNid(NID_commonName,
					entry(subject, NID_commonName));
		if (!o.isEmpty())
			n.addEntryByNid(NID_organizationName, o);
		subject = n;
	} else if (cnSource != "csr" &&
		   entry(subject, NID_commonName) != cn) {
		throw serviceError("csr_cn_mismatch",
			tr("The common name '%1' is not the registered '%2'")
			.arg(entry(subject, NID_commonName), cn));
	}
	if (subj["add_missing_o"].toBool())
		policy.missingO = reg.organization;
	static const QMap<QString, int> attributes {
		{ "CN", NID_commonName }, { "O", NID_organizationName },
		{ "OU", NID_organizationalUnitName }, { "DC", NID_domainComponent },
		{ "C", NID_countryName }, { "L", NID_localityName },
		{ "ST", NID_stateOrProvinceName },
	};
	for (const QString &a : strings(subj["required_attributes"])) {
		bool added = a == "O" && !policy.missingO.isEmpty();
		if (entry(subject, attributes.value(a)).isEmpty() && !added)
			throw serviceError("csr_subject_missing_attribute",
				tr("The profile '%1' needs the subject attribute %2")
				.arg(id, a));
	}
	for (const QJsonValue &f : subj["forbidden_characters"].toArray())
		policy.forbiddenCharacters += f.toObject()["characters"].toString();
	spec.subject = subject;

	/* the extensions the profile fixes */
	QJsonObject bc = doc["basic_constraints"].toObject();
	e.basicCA = bc["ca"].toBool() ? ExtensionSpec::bc_ca :
					ExtensionSpec::bc_not_ca;
	e.basicCritical = bc["critical"].toBool();
	if (bc.contains("path_len"))
		e.pathLen = QString::number(bc["path_len"].toInt());
	QJsonObject ku = doc["ku_by_key_type"].toObject()[keyFamily].toObject();
	if (ku.isEmpty())
		throw serviceError("profile_key_type",
			tr("The profile '%1' has no key usage for %2 keys").arg(id, keyFamily));
	e.keyUsage = strings(ku["bits"]);
	if (request && ku.contains("optional_bits")) {
		/* only the bits the device asked for */
		STACK_OF(X509_EXTENSION) *exts =
			X509_REQ_get_extensions(request->getReq());
		ASN1_BIT_STRING *asked = (ASN1_BIT_STRING *)X509V3_get_d2i(
				exts, NID_key_usage, nullptr, nullptr);
		sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
		static const QMap<QString, int> bits {
			{ "keyAgreement", 4 }, { "nonRepudiation", 1 },
		};
		for (const QString &b : strings(ku["optional_bits"])) {
			if (asked && ASN1_BIT_STRING_get_bit(asked, bits.value(b, 9)))
				e.keyUsage << b;
		}
		ASN1_BIT_STRING_free(asked);
	}
	e.keyUsageCritical = ku["critical"].toBool();
	e.extKeyUsage = strings(doc["eku"].toObject()["purposes"]);  // none: no EKU
	e.extKeyUsageCritical = doc["eku"].toObject()["critical"].toBool();
	if (doc.contains("eku_default")) {
		e.ekuDefault = strings(doc["eku_default"]);
		e.ekuMerge = ExtensionSpec::merge_request;
		e.ekuAllowed = e.extKeyUsage;
		e.extKeyUsage = e.ekuDefault;
	}
	e.subjectKeyId = true;
	e.authorityKeyId = true;
	e.authorityKeyIdIssuer =
		doc["aki"].toObject()["form"].toString() == "key-id-issuer-serial";

	/* SAN: the CSR's (BTD-65) or, without a CSR, the registration's */
	QJsonObject san = doc["san"].toObject();
	policy.profile = true;
	if (san["uri"].toObject()["count"].toInt() == 1) {
		policy.registeredUri = reg.applicationUri;
		if (reg.applicationUri.isEmpty())
			throw serviceError("profile_registration_uri",
				tr("The profile '%1' needs the registered ApplicationUri").arg(id));
	}
	policy.dnsFromCn = san["dns_from_cn"].toBool();
	int dns = 0, ip = 0, email = 0;
	if (request) {
		STACK_OF(X509_EXTENSION) *exts =
			X509_REQ_get_extensions(request->getReq());
		GENERAL_NAMES *names = (GENERAL_NAMES *)X509V3_get_d2i(
				exts, NID_subject_alt_name, nullptr, nullptr);
		sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
		for (int i = 0; i < sk_GENERAL_NAME_num(names); i++) {
			int t = sk_GENERAL_NAME_value(names, i)->type;
			dns += t == GEN_DNS;
			ip += t == GEN_IPADD;
			email += t == GEN_EMAIL;
		}
		GENERAL_NAMES_free(names);
	} else {
		e.subjectAltName = reg.subjectAltName;
		if (!policy.registeredUri.isEmpty())
			e.subjectAltName = "URI:" + policy.registeredUri +
				(reg.subjectAltName.isEmpty() ? QString() :
					", " + reg.subjectAltName);
		dns = reg.subjectAltName.count("DNS:");
		ip = reg.subjectAltName.count("IP:");
		email = reg.subjectAltName.count("email:");
	}
	/* e-mail addresses only where a generic profile counts them; the OT
	 * profiles of schema v1 keep their behaviour */
	if (family == "generic" &&
	    (email < san["email"].toObject()["min"].toInt() ||
	     email > san["email"].toObject()["max"].toInt()))
		throw serviceError("csr_san_count",
			tr("The profile '%1' does not allow %2 e-mail addresses")
			.arg(id).arg(email));
	if (dns < san["dns"].toObject()["min"].toInt() || dns > san["dns"].toObject()["max"].toInt() ||
	    ip < san["ip"].toObject()["min"].toInt() || ip > san["ip"].toObject()["max"].toInt() ||
	    dns + ip < san["dns_or_ip_min"].toInt())
		throw serviceError("csr_san_count",
			tr("The profile '%1' does not allow %2 DNS names and %3 IP addresses")
			.arg(id).arg(dns).arg(ip));

	/* the CSR rules of BTD-65, the chain rules of BTD-55 */
	policy.csrSha1 = doc["csr_sha1"].toString() == "reject" ?
		CsrPolicy::sha1_reject : CsrPolicy::sha1_accept_with_warning;
	policy.keyCertSignRequest =
		doc["keycertsign_request"].toString() == "reject" ?
		CsrPolicy::keycertsign_reject : CsrPolicy::keycertsign_override;
	if (family == "opcua")
		spec.chainRules = IssuanceSpec::chain_opcua;

	/* signature: the hash the profile names for the issuing key */
	spec.signer = signer;
	QString caType = signer ? keyType(X509_get0_pubkey(signer->getCert())) :
				type;
	QString hash = caType.startsWith("rsa") ?
		doc["signature"].toObject()["rsa"].toObject()["hashes"].toArray().first().toString() :
		doc["signature"].toObject()["ec"].toObject()["hash_by_curve"].toObject()[caType].toString();
	int md = hash.isEmpty() ? NID_undef : OBJ_sn2nid(CCHAR(hash.toUpper()));
	if (md == NID_undef)
		throw serviceError("profile_signature",
			tr("The profile '%1' names no signature hash for a %2 CA").arg(id, caType));
	spec.hashAlgo = digest(md);

	/* validity relative to now, backdated for device clocks */
	QDateTime now = QDateTime::currentDateTimeUtc();
	QJsonObject validity = doc["validity"].toObject();
	spec.notBefore = a1time(shifted(now,
			validity["backdate"].toString("PT0S"), -1));
	/* the backdating is a default for device clocks: it ends at the
	 * start of the issuer, which IssuanceChecks::issuers() requires */
	if (signer && spec.notBefore < signer->getNotBefore())
		spec.notBefore = signer->getNotBefore();
	spec.notAfter = a1time(shifted(now, validity["default"].toString(), 1));

	/* the order of the golden files of BTD-64; a generic profile keeps
	 * the order XCA builds, as the template it came from did */
	if (family != "generic")
		spec.extensionOrder = { NID_basic_constraints, NID_key_usage,
		NID_ext_key_usage, NID_subject_alt_name,
		NID_subject_key_identifier, NID_authority_key_identifier,
		NID_crl_distribution_points, NID_info_access };
	spec.profile = id;
	return spec;
}
