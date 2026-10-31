/* vi: set sw=4 ts=4:
 *
 * Input checks of the bxc-pki command line (BTD-41): RFC 4514 subject
 * (rule 12), SAN values (rule 4), RFC 3339 dates and ISO 8601 durations
 * (rule 6), key types. Strict: a value that does not fit is an error,
 * never corrected silently.
 */

#include <QDateTime>
#include <QRegularExpression>

#include <openssl/objects.h>
#include <openssl/x509.h>

#include "lib/func.h"
#include "lib/builtin_curves.h"
#include "lib/pki_key.h"
#include "lib/x509name.h"
#include "cli.h"

namespace bxcpki {

/* --- RFC 4514 ------------------------------------------------------- */

namespace {

struct Attr
{
	QString type;
	QByteArray value;     // UTF-8
};

int hexValue(QChar c)
{
	if (c >= '0' && c <= '9')
		return c.unicode() - '0';
	if (c >= 'a' && c <= 'f')
		return c.unicode() - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c.unicode() - 'A' + 10;
	return -1;
}

/* The DN and where it comes from: an option (--subject) or a JSON
 * pointer of the bootstrap file, which gets a ':' after it as in every
 * bootstrap error */
class DnText
{
  public:
	QString text{};
	QString source{};
};

[[noreturn]] void badDn(const DnText &where, const QString &why)
{
	QString source = where.source.startsWith('/') ?
			where.source + ":" : where.source;
	throw usageError("invalid_subject", QObject::tr(
		"%1 '%2' is no RFC 4514 distinguished name: %3")
		.arg(source, where.text, why));
}

/* The attribute type: a descriptor of RFC 4514 or known to OpenSSL
 * (case-insensitive), or a dotted OID */
ASN1_OBJECT *attributeType(const DnText &where, const QString &type)
{
	static const QRegularExpression oid("^[0-9]+(\\.[0-9]+)+$");
	static const QRegularExpression descr("^[A-Za-z][A-Za-z0-9-]*$");
	static const QMap<QString, QString> rfc4514 {
		{ "cn", "CN" }, { "l", "L" }, { "st", "ST" }, { "o", "O" },
		{ "ou", "OU" }, { "c", "C" }, { "street", "street" },
		{ "dc", "DC" }, { "uid", "UID" },
		{ "emailaddress", "emailAddress" },
		{ "serialnumber", "serialNumber" },
	};
	ASN1_OBJECT *obj = nullptr;

	if (oid.match(type).hasMatch()) {
		obj = OBJ_txt2obj(type.toLatin1().constData(), 1);
	} else if (descr.match(type).hasMatch()) {
		QString name = rfc4514.value(type.toLower(), type);
		int nid = OBJ_txt2nid(name.toLatin1().constData());
		if (nid == NID_undef)
			nid = OBJ_ln2nid(name.toLatin1().constData());
		if (nid != NID_undef)
			obj = OBJ_dup(OBJ_nid2obj(nid));
	}
	ign_openssl_error();
	if (!obj)
		badDn(where, QObject::tr("unknown attribute type '%1'")
			.arg(type));
	return obj;
}

/* RFC 5280: countryName, serialNumber and dnQualifier are
 * PrintableString, domainComponent and emailAddress IA5String; every
 * other attribute is a UTF8String (rule 12) */
int stringType(const DnText &where, int nid, const QByteArray &value)
{
	static const QRegularExpression printable(
		"^[A-Za-z0-9 '()+,\\-./:=?]*$");
	switch (nid) {
	case NID_countryName:
		if (value.size() != 2)
			badDn(where, QObject::tr("C needs two letters, not '%1'")
				.arg(QString::fromUtf8(value)));
		/* fall through */
	case NID_serialNumber:
	case NID_dnQualifier:
		if (!printable.match(QString::fromUtf8(value)).hasMatch())
			badDn(where, QObject::tr("'%1' is no PrintableString")
				.arg(QString::fromUtf8(value)));
		return V_ASN1_PRINTABLESTRING;
	case NID_domainComponent:
	case NID_pkcs9_emailAddress:
		for (char c : value)
			if ((unsigned char)c > 0x7f)
				badDn(where, QObject::tr("'%1' is no IA5String")
					.arg(QString::fromUtf8(value)));
		return V_ASN1_IA5STRING;
	}
	return V_ASN1_UTF8STRING;
}

} // namespace

x509name parseDn(const QString &dn, const QString &source)
{
	const DnText where{ dn, source };
	static const QString special("\"+,;<>\\=# ");
	QList<QList<Attr> > rdns;
	QList<Attr> rdn;
	int i = 0, n = dn.size();

	if (dn.trimmed().isEmpty())
		badDn(where, QObject::tr("it is empty"));
	while (i < n) {
		Attr a;
		while (i < n && dn[i] == ' ')
			i++;
		int start = i;
		while (i < n && dn[i] != '=' && dn[i] != ',' && dn[i] != '+')
			i++;
		if (i >= n || dn[i] != '=')
			badDn(where, QObject::tr("'=' missing after '%1'")
				.arg(dn.mid(start, i - start)));
		a.type = dn.mid(start, i - start).trimmed();
		i++;
		if (i < n && dn[i] == '#')
			badDn(where, QObject::tr("hex encoded values (#...) are "
				"not supported"));
		int trailingSpaces = 0;
		while (i < n && dn[i] != ',' && dn[i] != '+') {
			QChar c = dn[i];
			if (c == '\\') {
				if (i + 1 >= n)
					badDn(where, QObject::tr("'\\' at the end"));
				QChar e = dn[i + 1];
				if (special.contains(e)) {
					a.value += QString(e).toUtf8();
					i += 2;
				} else if (i + 2 < n && hexValue(e) >= 0 &&
					   hexValue(dn[i + 2]) >= 0) {
					a.value += (char)(hexValue(e) * 16 +
							hexValue(dn[i + 2]));
					i += 3;
				} else {
					badDn(where, QObject::tr("invalid escape "
						"'\\%1'").arg(e));
				}
				trailingSpaces = 0;
				continue;
			}
			if (c == '"' || c == ';' || c == '<' || c == '>')
				badDn(where, QObject::tr("'%1' must be escaped")
					.arg(c));
			if (c == ' ' && a.value.isEmpty()) {
				i++;    /* space after '=' */
				continue;
			}
			trailingSpaces = c == ' ' ? trailingSpaces + 1 : 0;
			a.value += QString(c).toUtf8();
			i++;
		}
		a.value.chop(trailingSpaces);
		if (a.value.isEmpty())
			badDn(where, QObject::tr("the value of %1 is empty")
				.arg(a.type));
		if (QString::fromUtf8(a.value).toUtf8() != a.value)
			badDn(where, QObject::tr("the value of %1 is no UTF-8")
				.arg(a.type));
		rdn << a;
		if (i < n && dn[i] == '+') {
			i++;
			continue;
		}
		rdns << rdn;
		rdn.clear();
		if (i < n) {   /* ',' */
			i++;
			if (i >= n)
				badDn(where, QObject::tr("',' at the end"));
		}
	}
	if (!rdn.isEmpty())
		badDn(where, QObject::tr("'+' at the end"));

	/* RFC 4514 writes the last RDN of the sequence first */
	X509_NAME *name = X509_NAME_new();
	Q_CHECK_PTR(name);
	for (int r = rdns.size() - 1; r >= 0; r--) {
		for (int k = 0; k < rdns[r].size(); k++) {
			const Attr &a = rdns[r][k];
			ASN1_OBJECT *obj = nullptr;
			try {
				obj = attributeType(where, a.type);
				int type = stringType(where, OBJ_obj2nid(obj), a.value);
				X509_NAME_ENTRY *ne = X509_NAME_ENTRY_create_by_OBJ(
					nullptr, obj, type,
					(const unsigned char *)a.value.constData(),
					a.value.size());
				/* set 0: a new RDN, -1: into the previous one */
				if (!ne || !X509_NAME_add_entry(name, ne, -1,
							k == 0 ? 0 : -1)) {
					X509_NAME_ENTRY_free(ne);
					ign_openssl_error();
					badDn(where, QObject::tr("%1 is not accepted")
						.arg(a.type));
				}
				X509_NAME_ENTRY_free(ne);
				ASN1_OBJECT_free(obj);
			} catch (...) {
				ASN1_OBJECT_free(obj);
				X509_NAME_free(name);
				throw;
			}
		}
	}
	x509name result(name);
	X509_NAME_free(name);
	return result;
}

/* --- SAN values (rule 4) -------------------------------------------- */

static bool ipv4(const QString &s)
{
	static const QRegularExpression re(
		"^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
		"(\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$");
	return re.match(s).hasMatch();
}

static bool ipv6(const QString &s)
{
	static const QRegularExpression group("^[0-9A-Fa-f]{1,4}$");
	if (s.count("::") > 1 || s.contains(":::"))
		return false;
	QStringList halves = s.split("::");
	int groups = 0;
	bool v4tail = false;
	for (int h = 0; h < halves.size(); h++) {
		if (halves[h].isEmpty())
			continue;
		QStringList parts = halves[h].split(':');
		for (int p = 0; p < parts.size(); p++) {
			bool last = h == halves.size() - 1 &&
				p == parts.size() - 1;
			if (last && parts[p].contains('.')) {
				if (!ipv4(parts[p]))
					return false;
				groups += 2;
				v4tail = true;
			} else if (group.match(parts[p]).hasMatch()) {
				groups++;
			} else {
				return false;
			}
		}
	}
	(void)v4tail;
	return halves.size() == 2 ? groups <= 7 : groups == 8;
}

QString checkIp(const QString &ip)
{
	if (ipv4(ip) || (ip.contains(':') && ipv6(ip)))
		return ip;
	throw usageError("invalid_ip", QObject::tr(
		"--ip '%1' is no IPv4 address in dotted decimal without leading "
		"zeros or IPv6 address (no prefix length, no zone)").arg(ip));
}

QString checkDns(const QString &dns)
{
	static const QRegularExpression label(
		"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$");
	QString name = dns.startsWith("*.") ? dns.mid(2) : dns;
	bool ok = !name.isEmpty() && dns.size() <= 253;
	for (const QString &l : name.split('.'))
		ok = ok && label.match(l).hasMatch();
	if (ok && ipv4(dns))
		throw usageError("invalid_dns", QObject::tr(
			"--dns '%1' is an IP address; use --ip").arg(dns));
	if (!ok)
		throw usageError("invalid_dns", QObject::tr(
			"--dns '%1' is no DNS name (letters, digits and '-' per "
			"label, at most 63 per label and 253 in all, optional "
			"leading '*.')").arg(dns));
	return dns;
}

QString checkUri(const QString &uri)
{
	/* RFC 3986: scheme ":" and only URI characters, %HH escapes */
	static const QRegularExpression re(
		"^[A-Za-z][A-Za-z0-9+.\\-]*:"
		"([A-Za-z0-9\\-._~!$&'()*+,;=:@/?#\\[\\]]|%[0-9A-Fa-f]{2})+$");
	/* x509v3ext splits the SAN text before these keywords */
	static const QRegularExpression keyword(
		",(DNS|IP|email|URI|RID|otherName|dirName|issuer|UPN):");
	QString why;
	if (!re.match(uri).hasMatch())
		why = QObject::tr("no absolute URI of RFC 3986 (scheme, ':', "
			"no spaces or other unescaped characters)");
	else if (uri.section(':', 1).startsWith("//") &&
		 uri.section(':', 1).mid(2).section('/', 0, 0).isEmpty())
		why = QObject::tr("the authority after '//' is empty");
	else if (keyword.match(uri).hasMatch())
		why = QObject::tr("',' before a SAN type keyword must be "
			"percent-encoded (%2C)");
	if (!why.isEmpty())
		throw usageError("invalid_uri",
			QObject::tr("--uri '%1': %2").arg(uri).arg(why));
	return uri;
}

QString checkEmail(const QString &email)
{
	static const QRegularExpression local(
		"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~\\-]+$");
	int at = email.lastIndexOf('@');
	bool ok = at > 0 && local.match(email.left(at)).hasMatch();
	if (ok) {
		try {
			checkDns(email.mid(at + 1));
		} catch (usageError &) {
			ok = false;
		}
	}
	if (!ok)
		throw usageError("invalid_email", QObject::tr(
			"--email '%1' is no mail address local@domain").arg(email));
	return email;
}

/* --- Dates and durations (rule 6) ---------------------------------- */

a1time parseTimestamp(const QString &text, const QString &option)
{
	static const QRegularExpression re(
		"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
		"(Z|[+-][0-9]{2}:[0-9]{2})$");
	QDateTime t;
	QString upper = text.toUpper();
	if (re.match(upper).hasMatch())
		t = QDateTime::fromString(upper, Qt::ISODate);
	if (!t.isValid())
		throw usageError("invalid_value", QObject::tr(
			"--%1 '%2' is no RFC 3339 date-time with seconds and "
			"zone, e.g. 2026-10-29T12:00:00Z").arg(option).arg(text));
	return a1time(t.toUTC());
}

IsoDuration parseDuration(const QString &text, const QString &option)
{
	QString why;
	IsoDuration d = IsoDuration::parse(text, &why);
	if (!d.isValid())
		throw usageError("invalid_value",
			QString("--%1: %2").arg(option).arg(why));
	return d;
}

/* --- Key types ----------------------------------------------------- */

/* The key types of --key: exactly the vocabulary of the bootstrap file
 * (bxc-pki schemas/bootstrap.schema.json $defs/keyType), mapped onto the
 * keyjob text of the service layer in this one table. The name implies
 * size or curve, so bxc-pki cannot pass a wrong size; the service still
 * checks it (xca --keygen, invalid_key_size). */
static const struct {
	const char *name;
	const char *job;
} keyTypeTable[] = {
	{ "rsa-2048", "RSA:2048" },
	{ "rsa-3072", "RSA:3072" },
	{ "rsa-4096", "RSA:4096" },
	{ "ec-p256", "EC:prime256v1" },
	{ "ec-p384", "EC:secp384r1" },
	{ "ec-p521", "EC:secp521r1" },
	{ "ec-brainpoolp256r1", "EC:brainpoolP256r1" },
	{ "ec-brainpoolp384r1", "EC:brainpoolP384r1" },
	{ "ec-brainpoolp512r1", "EC:brainpoolP512r1" },
	{ "ed25519", "ED25519" },
	{ "ed448", "ED448" },
	{ "ml-dsa-44", "ML-DSA-44" },
	{ "ml-dsa-65", "ML-DSA-65" },
	{ "ml-dsa-87", "ML-DSA-87" },
	{ "slh-dsa-sha2-128s", "SLH-DSA-SHA2-128s" },
	{ "slh-dsa-sha2-128f", "SLH-DSA-SHA2-128f" },
	{ "slh-dsa-sha2-192s", "SLH-DSA-SHA2-192s" },
	{ "slh-dsa-sha2-192f", "SLH-DSA-SHA2-192f" },
	{ "slh-dsa-sha2-256s", "SLH-DSA-SHA2-256s" },
	{ "slh-dsa-sha2-256f", "SLH-DSA-SHA2-256f" },
	{ "slh-dsa-shake-128s", "SLH-DSA-SHAKE-128s" },
	{ "slh-dsa-shake-128f", "SLH-DSA-SHAKE-128f" },
	{ "slh-dsa-shake-192s", "SLH-DSA-SHAKE-192s" },
	{ "slh-dsa-shake-192f", "SLH-DSA-SHAKE-192f" },
	{ "slh-dsa-shake-256s", "SLH-DSA-SHAKE-256s" },
	{ "slh-dsa-shake-256f", "SLH-DSA-SHAKE-256f" },
};

/* Whether this build can generate the keyjob: the type exists in
 * keytype::types() and an EC curve is one of the builtin curves */
static bool generatable(const QString &job)
{
	keyjob j(job);
	if (!j.ktype.isValid())
		return false;
	return !j.isEC() || builtinCurves.containNid(j.ec_nid);
}

QStringList supportedKeyTypes()
{
	QStringList l;
	for (const auto &t : keyTypeTable)
		if (generatable(t.job))
			l << t.name;
	return l;
}

QStringList keyTypeNames()
{
	QStringList l;
	for (const auto &t : keyTypeTable)
		l << t.name;
	return l;
}

QString keyJobText(const QString &keyType)
{
	for (const auto &t : keyTypeTable) {
		if (keyType != t.name)
			continue;
		if (!generatable(t.job))
			throw serviceError("not_supported", QObject::tr(
				"The key type '%1' cannot be generated by this "
				"build; available: %2").arg(keyType)
				.arg(supportedKeyTypes().join(", ")));
		return t.job;
	}
	throw serviceError("invalid_key_type", QObject::tr(
		"Unknown key type '%1'; available: %2").arg(keyType)
		.arg(supportedKeyTypes().join(", ")));
}

} // namespace bxcpki
