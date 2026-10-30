/* vi: set sw=4 ts=4:
 *
 * Name policies of bxc-pki (BTD-167), see policy.h.
 */

#include "policy.h"

#include <QCoreApplication>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QMap>
#include <QRegularExpression>
#include <QUrl>

#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "exception.h"
#include "issuance.h"
#include "pki_base.h"
#include "pki_x509.h"

static QString tr(const char *text)
{
	return QCoreApplication::translate("Policy", text);
}

static serviceError invalid(const QString &field)
{
	return serviceError("invalid_policy",
		tr("The policy has no valid '%1'").arg(field));
}

static const QMap<QString, int> &dnAttributes()
{
	static const QMap<QString, int> attributes {
		{ "CN", NID_commonName }, { "O", NID_organizationName },
		{ "OU", NID_organizationalUnitName }, { "DC", NID_domainComponent },
		{ "C", NID_countryName }, { "L", NID_localityName },
		{ "ST", NID_stateOrProvinceName }, { "serialNumber", NID_serialNumber },
	};
	return attributes;
}

static const char *const nameForms[] = { "dns", "ip", "uri", "email", "dn" };

/* An IP network as the schema has it: address/prefix, the prefix in
 * range for the family */
static bool cidr(const QString &text, QByteArray *net, int *prefix)
{
	if (text.count('/') != 1)
		return false;
	bool ok = false;
	*prefix = text.section('/', 1, 1).toInt(&ok);
	ASN1_OCTET_STRING *a = a2i_IPADDRESS(CCHAR(text.section('/', 0, 0)));
	if (!a) {
		ERR_clear_error();
		return false;
	}
	*net = QByteArray((const char *)ASN1_STRING_get0_data(a),
			ASN1_STRING_get_length(a));
	ASN1_OCTET_STRING_free(a);
	return ok && *prefix >= 0 && *prefix <= 8 * net->size();
}

static bool fqdn(const QJsonValue &v)
{
	static const QRegularExpression re(QRegularExpression::anchoredPattern(
		"(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
		"(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+"));
	return v.isString() && re.match(v.toString()).hasMatch();
}

static bool regex(const QJsonValue &v)
{
	return v.isString() && !v.toString().isEmpty() &&
		QRegularExpression(v.toString()).isValid();
}

/* One rule of a name form as schemas/policy.schema.json defines it; a
 * rule that does not fit would admit or deny nothing (review of xca#56) */
static bool validRule(const QString &form, const QJsonValue &v)
{
	if (form == "ip") {
		QByteArray net;
		int prefix;
		return v.isString() && cidr(v.toString(), &net, &prefix);
	}
	if (!v.isObject())
		return false;
	QJsonObject r = v.toObject();
	QString type = r["type"].toString();
	QStringList keys { "type" };
	bool ok = false;
	if (form == "dns") {
		if (type == "exact") {
			keys << "value";
			ok = fqdn(r["value"]);
		} else if (type == "subtree") {
			keys << "value" << "wildcard";
			ok = fqdn(r["value"]) &&
				(!r.contains("wildcard") || r["wildcard"].isBool());
		} else if (type == "single-label") {
			keys << "pattern";
			ok = regex(r["pattern"]);
		}
	} else if (form == "uri") {
		static const QRegularExpression uri(QRegularExpression::anchoredPattern(
			"[a-z][a-z0-9+.-]*:\\S*"));
		keys << "value";
		if (type == "exact" || type == "prefix")
			ok = r["value"].isString() &&
				uri.match(r["value"].toString()).hasMatch();
		else if (type == "host" || type == "host-subtree")
			ok = fqdn(r["value"]);
	} else if (form == "email") {
		keys << "value";
		QString value = r["value"].toString();
		if (type == "mailbox")
			ok = value.count('@') == 1 && !value.startsWith('@') &&
				fqdn(QJsonValue(value.section('@', 1)));
		else if (type == "host" || type == "host-subtree")
			ok = fqdn(r["value"]);
	} else if (form == "dn") {
		if (type == "exact") {
			keys << "value";
			ok = r["value"].isString() && !r["value"].toString().isEmpty();
		} else if (type == "pattern") {
			keys << "pattern";
			ok = regex(r["pattern"]);
		}
	}
	for (auto k = r.begin(); ok && k != r.end(); ++k)
		ok = keys.contains(k.key());
	return ok;
}

static void validRules(const QString &where, const QString &form,
			const QJsonObject &rules)
{
	for (auto l = rules.begin(); l != rules.end(); ++l) {
		if (l.key() != "allow" && l.key() != "deny")
			throw invalid(QString("%1.%2").arg(where, l.key()));
		if (!l.value().isArray())
			throw invalid(QString("%1.%2").arg(where, l.key()));
		for (const QJsonValue &v : l.value().toArray()) {
			if (!validRule(form, v))
				throw invalid(QString("%1.%2 rule %3").arg(where,
					l.key(), QString::fromUtf8(QJsonDocument(
					QJsonArray{ v }).toJson(QJsonDocument::Compact))));
		}
	}
}

Policy Policy::fromJson(const QJsonObject &doc)
{
	Policy p;
	p.doc = doc;
	if (doc["schema"].toString() != "urn:bxc-pki:schema:policy:v1")
		throw invalid("schema");
	p.id = doc["id"].toString();
	if (p.id.isEmpty())
		throw invalid("id");
	if (!doc.contains("names") && !doc.contains("uniqueness") &&
	    !doc.contains("content") && !doc.contains("issuer"))
		throw invalid("names");
	/* every rule as the schema has it: a rule that does not fit would
	 * admit or deny nothing, an IP rule without prefix everything */
	QJsonObject names = doc["names"].toObject();
	for (auto f = names.begin(); f != names.end(); ++f) {
		QStringList forms;
		for (const char *form : nameForms)
			forms << form;
		if (!forms.contains(f.key()) || !f.value().isObject())
			throw invalid(QString("names.%1").arg(f.key()));
		QJsonObject rules = f.value().toObject();
		if (f.key() != "dn") {
			validRules("names." + f.key(), f.key(), rules);
			continue;
		}
		for (auto a = rules.begin(); a != rules.end(); ++a) {
			if (!dnAttributes().contains(a.key()) || !a.value().isObject())
				throw invalid(QString("names.dn.%1").arg(a.key()));
			validRules("names.dn." + a.key(), "dn", a.value().toObject());
		}
	}
	QJsonObject u = doc["uniqueness"].toObject();
	if (doc.contains("uniqueness") &&
	    (u["fields"].toArray().isEmpty() || u["status"].toArray().isEmpty() ||
	     (u["scope"].toString() != "issuer" &&
	      u["scope"].toString() != "database")))
		throw invalid("uniqueness");
	return p;
}

Policy Policy::fromFile(const QString &path)
{
	QFile f(path);
	if (!f.open(QIODevice::ReadOnly))
		throw serviceError("invalid_policy",
			tr("The policy file '%1' cannot be read").arg(path));
	QJsonParseError err;
	QJsonDocument d = QJsonDocument::fromJson(f.readAll(), &err);
	if (err.error != QJsonParseError::NoError || !d.isObject())
		throw serviceError("invalid_policy",
			tr("The policy file '%1' is no JSON object: %2")
			.arg(path, err.errorString()));
	return fromJson(d.object());
}

namespace {

/* One name of the certificate: its form as the policy names it and its
 * value as text (IP addresses also as bytes) */
struct Name {
	QString form;
	QString value;
	QByteArray ip{};
};

QString ia5(const ASN1_IA5STRING *s)
{
	return QString::fromLatin1((const char *)ASN1_STRING_get0_data(s),
				ASN1_STRING_get_length(s));
}

/* 192.168.0.10 or 2001:db8:0:0:0:0:0:1, for messages only */
QString ipText(const QByteArray &b)
{
	QStringList parts;
	if (b.size() == 4) {
		for (char c : b)
			parts << QString::number((unsigned char)c);
		return parts.join('.');
	}
	for (int i = 0; i + 1 < b.size(); i += 2)
		parts << QString::number(((unsigned char)b[i] << 8) |
					(unsigned char)b[i + 1], 16);
	return parts.join(':');
}

QList<Name> sanNames(X509 *x)
{
	QList<Name> list;
	GENERAL_NAMES *san = (GENERAL_NAMES *)X509_get_ext_d2i(x,
			NID_subject_alt_name, nullptr, nullptr);
	for (int i = 0; i < sk_GENERAL_NAME_num(san); i++) {
		GENERAL_NAME *gn = sk_GENERAL_NAME_value(san, i);
		switch (gn->type) {
		case GEN_DNS:
			list << Name{ "dns", ia5(gn->d.dNSName) };
			break;
		case GEN_URI:
			list << Name{ "uri", ia5(gn->d.uniformResourceIdentifier) };
			break;
		case GEN_EMAIL:
			list << Name{ "email", ia5(gn->d.rfc822Name) };
			break;
		case GEN_IPADD: {
			QByteArray b((const char *)ASN1_STRING_get0_data(gn->d.iPAddress),
				ASN1_STRING_get_length(gn->d.iPAddress));
			/* an IPv4-mapped IPv6 address is the IPv4 address */
			if (b.size() == 16 && b.startsWith(QByteArray(10, 0) +
						QByteArray(2, (char)0xff)))
				b = b.mid(12);
			list << Name{ "ip", ipText(b), b };
			break;
		}
		default: {
			/* otherName, directoryName, registeredID, x400Address,
			 * ediPartyName: no rule form of the policy fits them */
			BIO *bio = BIO_new(BIO_s_mem());
			GENERAL_NAME_print(bio, gn);
			char *data;
			long len = BIO_get_mem_data(bio, &data);
			list << Name{ "other", QString::fromUtf8(data, len) };
			BIO_free(bio);
		}
		}
	}
	GENERAL_NAMES_free(san);
	return list;
}

bool inSubtree(const QString &name, const QString &domain)
{
	return name == domain || name.endsWith("." + domain);
}

/* The rule as text for an error message */
QString ruleText(const QJsonObject &r)
{
	return QString::fromUtf8(QJsonDocument(r).toJson(QJsonDocument::Compact));
}

bool fullMatch(const QString &pattern, const QString &value)
{
	return QRegularExpression(QRegularExpression::anchoredPattern(pattern))
		.match(value).hasMatch();
}

bool dnsMatch(const QJsonObject &r, const QString &name)
{
	QString type = r["type"].toString();
	QString value = r["value"].toString().toLower();
	bool wildcard = name.startsWith("*.");
	QString base = wildcard ? name.mid(2) : name;
	if (type == "single-label")
		return !wildcard && !name.contains('.') &&
			fullMatch(r["pattern"].toString(), name);
	if (!name.contains('.'))
		return false;
	if (type == "exact")
		return !wildcard && name == value;
	if (type == "subtree")
		return inSubtree(base, value) &&
			(!wildcard || r["wildcard"].toBool());
	return false;
}

/* For a deny rule a wildcard *.B is denied when it lies in a denied
 * subtree, whatever the wildcard flag says, and when it covers a denied
 * name: a rule value one label below B (review of xca#56) */
bool dnsDenied(const QJsonObject &r, const QString &name)
{
	QString type = r["type"].toString();
	QString value = r["value"].toString().toLower();
	if (!name.startsWith("*.") || type == "single-label")
		return dnsMatch(r, name);
	QString base = name.mid(2);
	bool covered = value.section('.', 1) == base;
	if (type == "subtree")
		return inSubtree(base, value) || covered;
	return covered;
}

bool ipMatch(const QString &rule, const QByteArray &address)
{
	QByteArray n;
	int prefix;
	if (!cidr(rule, &n, &prefix) || n.size() != address.size())
		return false;
	for (int bit = 0; bit < prefix && bit < 8 * n.size(); bit++) {
		unsigned char m = 0x80 >> (bit % 8);
		if ((n[bit / 8] & m) != (address[bit / 8] & m))
			return false;
	}
	return true;
}

QString uriHost(const QString &uri)
{
	return QUrl(uri).host().toLower();
}

bool uriMatch(const QJsonObject &r, const QString &uri)
{
	QString type = r["type"].toString();
	QString value = r["value"].toString();
	if (type == "exact")
		return uri == value;
	/* a prefix ends at a boundary: https://plc.example.com does not
	 * admit https://plc.example.com.evil.org or ...@evil.org */
	if (type == "prefix")
		return uri.startsWith(value) && (uri.size() == value.size() ||
			QString("/:?#").contains(value.back()) ||
			QString("/?#").contains(uri.at(value.size())));
	QString host = uriHost(uri);
	if (host.isEmpty())
		return false;
	if (type == "host")
		return host == value.toLower();
	return inSubtree(host, value.toLower());
}

bool emailMatch(const QJsonObject &r, const QString &email)
{
	QString type = r["type"].toString();
	QString value = r["value"].toString();
	QString host = email.section('@', 1).toLower();
	if (type == "mailbox")
		return email.section('@', 0, 0) == value.section('@', 0, 0) &&
			host == value.section('@', 1).toLower();
	if (type == "host")
		return host == value.toLower();
	return inSubtree(host, value.toLower());
}

bool dnMatch(const QJsonObject &r, const QString &value)
{
	if (r["type"].toString() == "exact")
		return value == r["value"].toString();
	return fullMatch(r["pattern"].toString(), value);
}

bool matches(const QString &form, const QJsonObject &r, const Name &n,
		bool deny)
{
	if (form == "dns")
		return deny ? dnsDenied(r, n.value.toLower()) :
			      dnsMatch(r, n.value.toLower());
	if (form == "uri")
		return uriMatch(r, n.value);
	if (form == "email")
		return emailMatch(r, n.value);
	return dnMatch(r, n.value);
}

const QMap<QString, QString> &formNames()
{
	static const QMap<QString, QString> names {
		{ "dns", "dNSName" }, { "ip", "iPAddress" },
		{ "uri", "URI" }, { "email", "rfc822Name" },
	};
	return names;
}

/* The certificate's status as the uniqueness rule names it */
QString status(const pki_x509 *c)
{
	if (c->isRevoked())
		return "revoked";
	return c->getNotAfter() < a1time() ? "expired" : "valid";
}

bool sameSan(X509 *a, X509 *b)
{
	GENERAL_NAMES *x = (GENERAL_NAMES *)X509_get_ext_d2i(a,
			NID_subject_alt_name, nullptr, nullptr);
	GENERAL_NAMES *y = (GENERAL_NAMES *)X509_get_ext_d2i(b,
			NID_subject_alt_name, nullptr, nullptr);
	bool same = false;
	for (int i = 0; !same && i < sk_GENERAL_NAME_num(x); i++) {
		for (int j = 0; !same && j < sk_GENERAL_NAME_num(y); j++)
			same = !GENERAL_NAME_cmp(sk_GENERAL_NAME_value(x, i),
					sk_GENERAL_NAME_value(y, j));
	}
	GENERAL_NAMES_free(x);
	GENERAL_NAMES_free(y);
	return same;
}

} // namespace

void Policy::check(const IssuanceSpec &spec, const pki_x509 *cert,
			const QList<const pki_x509 *> &chain) const
{
	X509 *x = cert->getCert();

	/* names: deny first, then the allow list of the name form */
	QList<Name> names = sanNames(x);
	const X509_NAME *subject = X509_get_subject_name(x);
	QJsonObject policyNames = doc["names"].toObject();
	for (int i = 0; i < X509_NAME_entry_count(subject); i++) {
		const X509_NAME_ENTRY *e = X509_NAME_get_entry(subject, i);
		int nid = OBJ_obj2nid(X509_NAME_ENTRY_get_object(e));
		QString attr = dnAttributes().key(nid);
		const ASN1_STRING *d = X509_NAME_ENTRY_get_data(e);
		unsigned char *utf8 = nullptr;
		int len = ASN1_STRING_to_UTF8(&utf8, d);
		QString value = QString::fromUtf8((char *)utf8, qMax(len, 0));
		OPENSSL_free(utf8);
		/* the e-mail address of the subject is an e-mail address */
		if (nid == NID_pkcs9_emailAddress)
			names << Name{ "email", value };
		else if (!attr.isEmpty())
			names << Name{ "dn:" + attr, value };
		else if (policyNames.contains("dn"))
			throw serviceError("policy_name_not_allowed",
				tr("Policy '%1' has no rule for the subject attribute %2 '%3'")
				.arg(id, OBJ_nid2sn(nid), value));
	}
	for (const Name &n : names) {
		/* a policy that rules on names admits no name it cannot rule on */
		if (n.form == "other" ||
		    (n.form == "ip" && n.ip.size() != 4 && n.ip.size() != 16) ||
		    (n.form == "email" && n.value.count('@') != 1)) {
			if (policyNames.isEmpty())
				continue;
			throw serviceError("policy_name_not_allowed",
				tr("Policy '%1' has no rule for the name '%2'")
				.arg(id, n.value));
		}
		bool dn = n.form.startsWith("dn:");
		QString form = dn ? "dn" : n.form;
		QJsonObject rules = dn ?
			policyNames["dn"].toObject()[n.form.mid(3)].toObject() :
			policyNames[form].toObject();
		QString what = dn ? n.form.mid(3) : formNames().value(form);
		auto match = [&](const QJsonObject &r, bool deny) {
			return form == "ip" ? ipMatch(r["network"].toString(), n.ip) :
					matches(form, r, n, deny);
		};
		for (const QJsonValue &v : rules["deny"].toArray()) {
			QJsonObject r = form == "ip" ?
				QJsonObject{ { "network", v.toString() } } : v.toObject();
			if (match(r, true))
				throw serviceError("policy_name_denied",
					tr("Policy '%1': the %2 '%3' is denied by the rule %4")
					.arg(id, what, n.value, form == "ip" ?
						v.toString() : ruleText(r)));
		}
		if (!rules.contains("allow"))
			continue;
		bool allowed = false;
		for (const QJsonValue &v : rules["allow"].toArray()) {
			QJsonObject r = form == "ip" ?
				QJsonObject{ { "network", v.toString() } } : v.toObject();
			allowed |= match(r, false);
		}
		if (!allowed)
			throw serviceError("policy_name_not_allowed",
				tr("Policy '%1': no allow rule admits the %2 '%3'")
				.arg(id, what, n.value));
	}

	/* the minimum content */
	QJsonObject content = doc["content"].toObject();
	if (content["require_extensions"].toBool() && X509_get_ext_count(x) == 0)
		throw serviceError("policy_no_extensions",
			tr("Policy '%1': a certificate without any extension is not issued (rule content.require_extensions)")
			.arg(id));
	for (const QJsonValue &a : content["required_dn_attributes"].toArray()) {
		if (X509_NAME_get_index_by_NID(subject,
				dnAttributes().value(a.toString()), -1) < 0)
			throw serviceError("policy_missing_dn_attribute",
				tr("Policy '%1': the subject has no %2 (rule content.required_dn_attributes)")
				.arg(id, a.toString()));
	}

	/* strict issuer key usage; the default lets an issuer without key
	 * usage sign with a warning (RFC 5280 6.1.4 (n), BTD-55) */
	if (doc["issuer"].toObject()["require_key_usage"].toBool() &&
	    !chain.isEmpty() &&
	    !(X509_get_extension_flags(chain.first()->getCert()) & EXFLAG_KUSAGE))
		throw serviceError("policy_issuer_key_usage",
			tr("Policy '%1': the issuer '%2' has no key usage extension (rule issuer.require_key_usage)")
			.arg(id, chain.first()->getSubject().oneLine()));

	/* uniqueness among the certificates of the scope with a status */
	QJsonObject u = doc["uniqueness"].toObject();
	if (u.isEmpty())
		return;
	QStringList fields, statuses;
	for (const QJsonValue &v : u["fields"].toArray())
		fields << v.toString();
	for (const QJsonValue &v : u["status"].toArray())
		statuses << v.toString();
	bool byIssuer = u["scope"].toString() == "issuer";
	for (pki_x509 *other : Store.getAll<pki_x509>()) {
		if (other == cert || (byIssuer && other->getSigner() != spec.signer) ||
		    !statuses.contains(status(other)))
			continue;
		X509 *o = other->getCert();
		QString field;
		if (fields.contains("subject_dn") &&
		    !X509_NAME_cmp(X509_get_subject_name(o), subject))
			field = "subject_dn";
		else if (fields.contains("public_key") &&
			 EVP_PKEY_eq(X509_get0_pubkey(o), X509_get0_pubkey(x)) == 1)
			field = "public_key";
		else if (fields.contains("san") && sameSan(o, x))
			field = "san";
		if (!field.isEmpty())
			throw serviceError("policy_not_unique",
				tr("Policy '%1': '%2' (%3) has the same %4 (rule uniqueness)")
				.arg(id, other->getIntName(), status(other), field));
	}
}
