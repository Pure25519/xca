/* vi: set sw=4 ts=4:
 *
 * JSON documents of the XCA objects and of the list outputs (BTD-39),
 * see json_report.h.
 */

#include "json_report.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QRegularExpression>
#include <QStringList>

#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include "audit.h"
#include "BioByteArray.h"
#include "database_model.h"
#include "func.h"
#include "pki_crl.h"
#include "pki_key.h"
#include "pki_temp.h"
#include "pki_x509.h"
#include "pki_x509req.h"
#include "x509name.h"
#include "x509rev.h"
#include "xfile.h"

#define SCHEMA(kind) QString("urn:bxc-pki:schema:" kind ":v1")

bool JsonReport::json = false;

void JsonReport::setActive(bool on)
{
	json = on;
}

bool JsonReport::active()
{
	return json;
}

/* RFC 3339 in UTC; the undefined date of RFC 5280 (99991231235959Z,
 * a1time keeps it as "undefined") is the last second of 9999 */
QJsonValue JsonReport::timestamp(const a1time &t)
{
	if (t.isUndefined())
		return QString("9999-12-31T23:59:59Z");
	if (!t.isValid())
		return QJsonValue();
	return AuditLog::rfc3339(t);
}

static QJsonValue optionalTimestamp(const a1time &t)
{
	if (!t.isValid() || t.isUndefined())
		return QJsonValue();
	return JsonReport::timestamp(t);
}

QJsonValue JsonReport::oidName(const ASN1_OBJECT *obj)
{
	if (!obj)
		return QJsonValue();
	int nid = OBJ_obj2nid(obj);
	const char *sn = nid == NID_undef ? nullptr : OBJ_nid2sn(nid);
	QJsonObject o;
	o["oid"] = OBJ_obj2QString(obj, 1);
	o["name"] = sn ? QJsonValue(QString(sn)) : QJsonValue();
	return o;
}

/* CRLReason of RFC 5280 5.3.1 by its code, null for none or unknown */
QJsonValue JsonReport::revocationReason(int code)
{
	static const char * const names[] = {
		"unspecified", "keyCompromise", "cACompromise",
		"affiliationChanged", "superseded", "cessationOfOperation",
		"certificateHold", nullptr /* 7 is not used */,
		"removeFromCRL", "privilegeWithdrawn", "aACompromise",
	};
	if (code < 0 || code >= (int)ARRAY_SIZE(names) || !names[code])
		return QJsonValue();
	return QString(names[code]);
}

QString JsonReport::serial(const a1int &serial)
{
	QString hex = serial.toHex();
	/* BN_bn2hex: "0" for zero; an empty INTEGER gives "" */
	if (hex.isEmpty() || hex == "0")
		return QString("00");
	return hex;
}

QString JsonReport::objectType(const pki_base *pki)
{
	switch (pki->getType()) {
	case x509:       return "certificate";
	case asym_key:
	case smartCard:  return "key";
	case x509_req:   return "request";
	case revocation: return "crl";
	case tmpl:       return "template";
	default:         return QString();
	}
}

QJsonObject JsonReport::dn(const x509name &name)
{
	QJsonObject o;
	QJsonArray attributes;
	BioByteArray bba;

	/* RFC 4514: most significant RDN last; UTF-8 stays unescaped */
	X509_NAME_print_ex(bba, name.get0(), 0,
			XN_FLAG_RFC2253 & ~ASN1_STRFLGS_ESC_MSB);
	ign_openssl_error();
	o["rfc4514"] = QString::fromUtf8(bba.byteArray());

	for (int i = 0; i < name.entryCount(); i++) {
		const X509_NAME_ENTRY *ne = X509_NAME_get_entry(name.get0(), i);
		QJsonObject a = oidName(X509_NAME_ENTRY_get_object(ne))
					.toObject();
		a["value"] = name.getEntry(i);
		attributes.append(a);
	}
	o["attributes"] = attributes;
	return o;
}

/* PEM as the OpenSSL writer makes it: LF, 64 characters per line */
template <class T>
static QString pem(int (*writer)(BIO *, const T *), const T *obj)
{
	BioByteArray bba;
	writer(bba, obj);
	ign_openssl_error();
	return QString::fromLatin1(bba.byteArray());
}

QJsonObject JsonReport::publicKey(const EVP_PKEY *pkey)
{
	QJsonObject o;
	if (!pkey)
		return o;

	int base = EVP_PKEY_get_base_id(pkey);
	/* ML-DSA and SLH-DSA by their name (keytype::nid(), BTD-16) */
	QString type = keytype::byPKEY(pkey).name;
	if (type.isEmpty()) {
		/* Not one of XCA's key types: the OpenSSL name */
		const char *n = EVP_PKEY_get0_type_name(pkey);
		type = n ? QString(n) : QString("unknown");
	}
	o["type"] = type;
	o["size"] = EVP_PKEY_get_bits(pkey);

	QJsonValue curve;
	if (base == EVP_PKEY_EC) {
		char gname[80];
		if (EVP_PKEY_get_group_name(pkey, gname, sizeof gname,
						nullptr) > 0) {
			int nid = OBJ_txt2nid(gname);
			if (nid != NID_undef)
				curve = oidName(OBJ_nid2obj(nid));
		}
	}
	o["curve"] = curve;

	QByteArray der = i2d_bytearray(I2D_VOID(i2d_PUBKEY), pkey);
	o["fingerprint"] = formatHash(Digest(der, EVP_sha256()), ":", 2);
	o["pem"] = pem(PEM_write_bio_PUBKEY, pkey);
	ign_openssl_error();
	return o;
}

/* Value of an extension as OpenSSL prints it, like x509v3ext::getValue()
 * but also for an OID OpenSSL does not know */
static QString extensionValue(const X509_EXTENSION *ext)
{
	BioByteArray bba;
	X509_EXTENSION *e = const_cast<X509_EXTENSION *>(ext);
	int ret = X509V3_EXT_print(bba, e, X509V3_EXT_DEFAULT, 0);
	if (ign_openssl_error() || !ret) {
		bba = BioByteArray();
		ret = ASN1_STRING_print(bba, X509_EXTENSION_get_data(e));
	}
	if (ign_openssl_error() || !ret)
		return QString();
	return QString::fromUtf8(bba.byteArray()).trimmed();
}

static QJsonArray extensions(const STACK_OF(X509_EXTENSION) *sk)
{
	QJsonArray list;
	for (int i = 0; i < sk_X509_EXTENSION_num(sk); i++) {
		const X509_EXTENSION *ext = sk_X509_EXTENSION_value(sk, i);
		QJsonObject o = JsonReport::oidName(
				X509_EXTENSION_get_object(ext)).toObject();
		o["critical"] = X509_EXTENSION_get_critical(ext) > 0;
		o["value"] = extensionValue(ext);
		list.append(o);
	}
	return list;
}

static QJsonValue algorithm(const X509_ALGOR *alg)
{
	const ASN1_OBJECT *obj = nullptr;
	if (alg)
		X509_ALGOR_get0(&obj, nullptr, nullptr, alg);
	return JsonReport::oidName(obj);
}

static QJsonValue itemRef(const pki_base *pki)
{
	if (!pki || !pki->getSqlItemId().isValid())
		return QJsonValue();
	QJsonObject o;
	o["id"] = pki->getSqlItemId().toLongLong();
	o["name"] = pki->getIntName();
	return o;
}

static const char *sourceName(enum pki_source s)
{
	switch (s) {
	case imported:    return "imported";
	case generated:   return "generated";
	case transformed: return "transformed";
	case token:       return "token";
	case legacy_db:   return "legacy_db";
	case renewed:     return "renewed";
	case unknown:
	default:          return "unknown";
	}
}

/* The members every object has; id and created are null for an item
 * that is not stored in the database */
static QJsonObject base(const char *schema, const pki_base *pki)
{
	QJsonObject o;
	bool stored = pki->getSqlItemId().isValid();

	o["schema"] = QString(schema);
	o["id"] = stored ? QJsonValue(pki->getSqlItemId().toLongLong()) :
			QJsonValue();
	o["name"] = pki->getIntName();
	o["created"] = stored ? JsonReport::timestamp(pki->getInsertionDate()) :
			QJsonValue();
	o["source"] = QString(sourceName(pki->pkiSource));
	o["comment"] = pki->getComment();
	return o;
}

QJsonObject JsonReport::certificate(const pki_x509 *cert)
{
	QJsonObject o = base("urn:bxc-pki:schema:certificate:v1", cert);
	const X509 *x = cert->getCert();
	const X509_ALGOR *alg = nullptr;
	bool ca = false;

	o["version"] = (int)X509_get_version(x) + 1;
	o["serial"] = JsonReport::serial(cert->getSerial());
	o["subject"] = dn(cert->getSubject());
	o["issuer"] = dn(cert->getIssuerName());
	o["issuer_item"] = itemRef(cert->getSigner());
	o["key_item"] = itemRef(cert->getRefKey());
	o["not_before"] = timestamp(cert->getNotBefore());
	o["not_after"] = timestamp(cert->getNotAfter());
	/* Like the GUI: "Self signed" verifies with its own key */
	o["self_signed"] = cert->verify_only(cert);
	if (!cert->caAndPathLen(&ca, nullptr, nullptr))
		ca = false;
	o["ca"] = ca;
	o["public_key"] = publicKey(X509_get0_pubkey(x));
	X509_get0_signature(nullptr, &alg, x);
	o["signature_algorithm"] = algorithm(alg);

	QJsonObject fp;
	fp["sha256"] = formatHash(Digest(cert->i2d(), EVP_sha256()), ":", 2);
	o["fingerprints"] = fp;
	o["extensions"] = extensions(X509_get0_extensions(x));

	QJsonValue revocation;
	if (cert->isRevoked()) {
		x509rev rev = cert->getRevocation();
		QJsonObject r;
		r["date"] = timestamp(rev.getDate());
		r["reason"] = revocationReason(rev.getReasonBit());
		r["invalidity_date"] = optionalTimestamp(rev.getInvalDate());
		revocation = r;
	}
	o["revocation"] = revocation;

	/* XCA column CRL Expiration: the nextUpdate of the CA's last CRL */
	a1time crlExpire = cert->getCrlExpire();
	o["crl_expiration"] = ca && cert->getSqlItemId().isValid() ?
			optionalTimestamp(crlExpire) : QJsonValue();
	o["pem"] = pem(PEM_write_bio_X509, x);
	ign_openssl_error();
	return o;
}

/* A value of a request attribute: the text of a string type, any other
 * type as '#' and the hex DER (RFC 4514 2.4) */
static QString attributeValue(const ASN1_TYPE *t)
{
	switch (t->type) {
	case V_ASN1_UTF8STRING:
	case V_ASN1_PRINTABLESTRING:
	case V_ASN1_IA5STRING:
	case V_ASN1_T61STRING:
	case V_ASN1_BMPSTRING:
	case V_ASN1_UNIVERSALSTRING:
	case V_ASN1_VISIBLESTRING:
	case V_ASN1_NUMERICSTRING:
		return asn1ToQString(t->value.asn1_string);
	}
	QByteArray der = i2d_bytearray(I2D_VOID(i2d_ASN1_TYPE), t);
	return QString("#") + QString::fromLatin1(der.toHex()).toUpper();
}

QJsonObject JsonReport::request(const pki_x509req *req)
{
	QJsonObject o = base("urn:bxc-pki:schema:csr:v1", req);
	const X509_REQ *r = req->getReq();
	X509_REQ *rw = const_cast<X509_REQ *>(r);
	const X509_ALGOR *alg = nullptr;

	o["version"] = (int)X509_REQ_get_version(r);
	o["subject"] = dn(req->getSubject());
	o["key_item"] = itemRef(req->getRefKey());
	o["public_key"] = publicKey(X509_REQ_get0_pubkey(rw));
	X509_REQ_get0_signature(r, nullptr, &alg);
	o["signature_algorithm"] = algorithm(alg);
	o["signature_valid"] = req->verify();
	o["signed"] = req->getDone();
	o["certificate_count"] = Database.isOpen() ? req->issuedCerts() : 0;

	STACK_OF(X509_EXTENSION) *sk = X509_REQ_get_extensions(rw);
	o["extensions"] = extensions(sk);
	sk_X509_EXTENSION_pop_free(sk, X509_EXTENSION_free);
	ign_openssl_error();

	/* The challenge password is a secret (PLAN.md 6.4); the extension
	 * requests are listed as extensions */
	QJsonArray attributes;
	bool challenge = false;
	for (int i = 0; i < X509_REQ_get_attr_count(r); i++) {
		X509_ATTRIBUTE *att = X509_REQ_get_attr(r, i);
		const ASN1_OBJECT *obj = X509_ATTRIBUTE_get0_object(att);
		int nid = OBJ_obj2nid(obj);
		if (nid == NID_pkcs9_challengePassword)
			challenge = true;
		if (nid == NID_pkcs9_challengePassword || nid == NID_ext_req ||
		    nid == NID_ms_ext_req)
			continue;
		QStringList values;
		for (int j = 0; j < X509_ATTRIBUTE_count(att); j++)
			values << attributeValue(X509_ATTRIBUTE_get0_type(att, j));
		QJsonObject a = oidName(obj).toObject();
		a["value"] = values.join(", ");
		attributes.append(a);
	}
	o["attributes"] = attributes;
	/* The signed request carries the challenge password and cannot be
	 * shown without it: such a request has no pem, only the flag */
	o["challenge_password_present"] = challenge;
	if (!challenge)
		o["pem"] = pem(PEM_write_bio_X509_REQ, r);
	ign_openssl_error();
	return o;
}

QJsonObject JsonReport::crl(const pki_crl *crl)
{
	QJsonObject o = base("urn:bxc-pki:schema:crl:v1", crl);
	const X509_CRL *c = crl->getCrl();
	X509_CRL *cw = const_cast<X509_CRL *>(c);
	const X509_ALGOR *alg = nullptr;
	a1int number;

	o["version"] = (int)X509_CRL_get_version(c) + 1;
	o["issuer"] = dn(crl->getSubject());
	o["issuer_item"] = itemRef(crl->getIssuer());
	o["this_update"] = timestamp(crl->getLastUpdate());
	const ASN1_TIME *next = X509_CRL_get0_nextUpdate(c);
	o["next_update"] = next ? timestamp(a1time(next)) : QJsonValue();
	o["crl_number"] = crl->getCrlNumber(&number) ?
			QJsonValue(number.toDec().toLongLong()) : QJsonValue();
	X509_CRL_get0_signature(c, nullptr, &alg);
	o["signature_algorithm"] = algorithm(alg);

	/* Read from the CRL itself: an entry without reason extension has
	 * reason null (x509rev would call it unspecified) */
	QJsonArray revoked;
	STACK_OF(X509_REVOKED) *st = X509_CRL_get_REVOKED(cw);
	for (int i = 0; i < sk_X509_REVOKED_num(st); i++) {
		X509_REVOKED *rev = sk_X509_REVOKED_value(st, i);
		QJsonObject r;
		int crit = -1;

		r["serial"] = serial(a1int(X509_REVOKED_get0_serialNumber(rev)));
		r["date"] = timestamp(a1time(
				X509_REVOKED_get0_revocationDate(rev)));
		ASN1_ENUMERATED *reason = static_cast<ASN1_ENUMERATED *>(
			X509_REVOKED_get_ext_d2i(rev, NID_crl_reason, &crit,
						 nullptr));
		r["reason"] = reason ?
			revocationReason(ASN1_ENUMERATED_get(reason)) :
			QJsonValue();
		ASN1_ENUMERATED_free(reason);
		ASN1_GENERALIZEDTIME *inval = static_cast<ASN1_GENERALIZEDTIME *>(
			X509_REVOKED_get_ext_d2i(rev, NID_invalidity_date,
						 &crit, nullptr));
		r["invalidity_date"] = inval ? timestamp(a1time(inval)) :
						QJsonValue();
		ASN1_GENERALIZEDTIME_free(inval);
		revoked.append(r);
	}
	o["revoked_count"] = revoked.size();
	o["revoked"] = revoked;
	o["extensions"] = extensions(X509_CRL_get0_extensions(c));
	o["pem"] = pem(PEM_write_bio_X509_CRL, c);
	ign_openssl_error();
	return o;
}

QJsonObject JsonReport::key(const pki_key *key)
{
	QJsonObject o = base("urn:bxc-pki:schema:key:v1", key);
	bool token = key->getType() == smartCard;

	/* Public part only: PEM_write_bio_PUBKEY and i2d_PUBKEY never
	 * write the private part, nothing here decrypts the key */
	o["public_key"] = publicKey(key->getEvpKey());
	o["kind"] = key->isPubKey() ? "public_only" : "key_pair";
	/* A key read from a file and not stored (BTD-41): its own
	 * protection, never the database's */
	bool file = !token && !key->getSqlItemId().isValid();
	o["storage"] = token ? "token" : file ? "file" : "database";

	QJsonValue protection;
	if (file) {
		if (!key->isPubKey())
			protection = key->fileEncrypted() ? "own" : "none";
	} else if (!key->isPubKey()) {
		switch (key->getOwnPass()) {
		case pki_key::ptCommon:  protection = "database"; break;
		case pki_key::ptPrivate: protection = "own"; break;
		case pki_key::ptBogus:   protection = "none"; break;
		case pki_key::ptPin:     protection = "token"; break;
		}
	}
	o["protection"] = protection;
	o["use_count"] = key->getSqlItemId().isValid() ?
			qMax(key->getUcount(), 0) : 0;
	return o;
}

QJsonObject JsonReport::temp(const pki_temp *temp)
{
	QJsonObject o = base("urn:bxc-pki:schema:template:v1", temp);
	bool predefined = temp->isPreDefined();

	if (predefined) {
		/* As XCA shows it: "[default] CA"; not in the database */
		o["name"] = temp->comboText();
		o["id"] = QJsonValue();
		o["created"] = QJsonValue();
	}
	o["predefined"] = predefined;
	o["subject"] = dn(temp->getSubject());

	QJsonObject settings;
	QMap<QString, QString> s = temp->getSettings();
	for (auto i = s.constBegin(); i != s.constEnd(); ++i)
		settings[i.key()] = i.value();
	o["settings"] = settings;
	return o;
}

QJsonObject JsonReport::object(const pki_base *pki)
{
	if (const pki_x509 *c = dynamic_cast<const pki_x509 *>(pki))
		return certificate(c);
	if (const pki_x509req *r = dynamic_cast<const pki_x509req *>(pki))
		return request(r);
	if (const pki_crl *c = dynamic_cast<const pki_crl *>(pki))
		return crl(c);
	if (const pki_key *k = dynamic_cast<const pki_key *>(pki))
		return key(k);
	if (const pki_temp *t = dynamic_cast<const pki_temp *>(pki))
		return temp(t);
	return QJsonObject();
}

static QJsonObject list(const char *kind, const QJsonArray &items)
{
	QJsonObject o;
	o["schema"] = SCHEMA("list");
	o["kind"] = QString(kind);
	o["items"] = items;
	return o;
}

QJsonObject JsonReport::itemList(const QList<pki_base *> &items)
{
	QJsonArray a;
	for (const pki_base *pki : items) {
		QJsonObject i;
		i["id"] = pki->getSqlItemId().toLongLong();
		i["type"] = objectType(pki);
		i["name"] = pki->getIntName();
		a.append(i);
	}
	return list("items", a);
}

QJsonObject JsonReport::issuerList(const QList<pki_x509 *> &issuers)
{
	QJsonArray a;
	for (const pki_x509 *iss : issuers) {
		QJsonObject i;
		i["id"] = iss->getSqlItemId().toLongLong();
		i["name"] = iss->getIntName();
		/* The type of the certificate's key, without "Token" */
		i["key_type"] = publicKey(X509_get0_pubkey(iss->getCert()))
					.value("type");
		a.append(i);
	}
	return list("issuers", a);
}

/* One line of the OpenSSL index (pki_x509::getIndexEntry()) */
static QJsonObject indexEntry(pki_x509 *cert)
{
	QJsonObject o;
	bool revoked = cert->isRevoked();
	x509rev rev = cert->getRevocation();

	o["status"] = revoked ? "revoked" :
			cert->checkDate() ? "valid" : "expired";
	o["not_after"] = JsonReport::timestamp(cert->getNotAfter());
	o["revocation_date"] = revoked ?
			JsonReport::timestamp(rev.getDate()) : QJsonValue();
	o["reason"] = revoked ?
			JsonReport::revocationReason(rev.getReasonBit()) :
			QJsonValue();
	o["serial"] = JsonReport::serial(cert->getSerial());
	o["subject"] = JsonReport::dn(cert->getSubject()).value("rfc4514");
	return o;
}

static QJsonArray indexEntries(const QList<pki_x509 *> &certs)
{
	QJsonArray a;
	for (pki_x509 *cert : certs)
		if (cert)
			a.append(indexEntry(cert));
	return a;
}

QJsonObject JsonReport::index()
{
	return list("index", indexEntries(Store.sqlSELECTpki<pki_x509>(
				"SELECT item FROM certs")));
}

QJsonObject JsonReport::hierarchy()
{
	QJsonArray a;
	QList<pki_x509 *> issuers = Store.sqlSELECTpki<pki_x509>(
		"SELECT DISTINCT issuer FROM certs WHERE issuer != item");
	for (pki_x509 *ca : issuers) {
		QJsonObject node, issuer;
		issuer["id"] = ca->getSqlItemId().toLongLong();
		issuer["name"] = ca->getIntName();
		node["issuer"] = issuer;
		node["entries"] = indexEntries(Store.sqlSELECTpki<pki_x509>(
			"SELECT item FROM certs WHERE issuer=?",
			QList<QVariant>() << QVariant(ca->getSqlItemId())));
		a.append(node);
	}
	return list("hierarchy", a);
}

QJsonObject JsonReport::error(const QString &code, const QString &detail)
{
	QString title = code;
	title.replace('_', ' ');
	if (!title.isEmpty())
		title[0] = title[0].toUpper();

	QJsonObject o;
	o["schema"] = SCHEMA("error");
	o["type"] = QString("urn:bxc-pki:error:") + code;
	o["title"] = title;
	o["detail"] = detail;
	o["code"] = code;
	return o;
}

QJsonObject JsonReport::error(const errorEx &err)
{
	static const QRegularExpression valid("^[a-z][a-z0-9_]*$");
	const serviceError *s = dynamic_cast<const serviceError *>(&err);
	const secretError *pw = dynamic_cast<const secretError *>(&err);
	QString code = s && valid.match(s->code).hasMatch() ?
			s->code : QString("internal_error");
	/* BTD-41: a missing or unreadable source is missing_password */
	if (pw)
		code = pw->why == secretError::rejected ?
			"password_rejected" : "missing_password";
	if (dynamic_cast<const confirmationError *>(&err))
		code = "not_confirmed";
	return error(code, err.getString());
}

QByteArray JsonReport::line(const QJsonObject &doc)
{
	return QJsonDocument(doc).toJson(QJsonDocument::Compact) + '\n';
}

void JsonReport::write(FILE *fp, const QJsonObject &doc)
{
	console_write(fp, line(doc));
}

void JsonReport::writeTo(const QString &path, const QJsonObject &doc)
{
	if (path == "-") {
		write(stdout, doc);
		return;
	}
	QByteArray data = line(doc);
	XFile file(path);
	if (!file.open_write() || file.write(data) != data.size())
		throw errorEx(QObject::tr("Failed to write '%1'").arg(path));
	file.close();
}
