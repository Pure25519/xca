/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2009 -2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "pki_scard.h"
#include "pass_info.h"
#include "pk11_attribute.h"
#include "openssl_compat.h"
#include "exception.h"
#include "db_base.h"
#include "pkcs11.h"
#include "x509name.h"
#include "func.h"
#include "XcaProgress.h"
#include "XcaPresentation.h"

#include "XcaWarningCore.h"
#include "PwDialogCore.h"

#include <memory>

#include <QThread>
#include <QSharedPointer>

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

void pki_scard::init(void)
{
	ownPass = ptPin;
	pkiType = smartCard;
	isPub = false;
}

pki_scard::pki_scard(const QString &name)
	:pki_key(name)
{
	init();
}

QString pki_scard::getMsg(msg_type msg, int n) const
{
	/*
	 * We do not construct english sentences from fragments
	 * to allow proper translations.
	 *
	 * %1 will be replaced by the name of the smartcard
	 */
	switch (msg) {
	case msg_import: return tr("Successfully imported the token key '%1'");
	case msg_delete: return tr("Delete the %n token key(s): '%1'?", "", n);
	case msg_create: return tr("Successfully created the token key '%1'");
	}
	return pki_base::getMsg(msg);
}

QSqlError pki_scard::insertSqlData()
{
	XSqlQuery q;
	QSqlError e = pki_key::insertSqlData();
	if (e.isValid())
		return e;

	SQL_PREPARE(q, "INSERT INTO tokens (item, card_manufacturer, card_serial, "
					"card_model, card_label, slot_label, "
					"object_id) "
		  "VALUES (?, ?, ?, ?, ?, ?, ?)");
	q.bindValue(0, sqlItemId);
	q.bindValue(1, card_manufacturer);
	q.bindValue(2, card_serial);
	q.bindValue(3, card_model);
	q.bindValue(4, card_label);
	q.bindValue(5, slot_label);
	q.bindValue(6, object_id);
	q.exec();
	e = q.lastError();
	if (e.isValid())
		return e;
	SQL_PREPARE(q, "INSERT INTO token_mechanism (item, mechanism) "
		  "VALUES (?, ?)");
	q.bindValue(0, sqlItemId);
	foreach(CK_MECHANISM_TYPE m, mech_list) {
		q.bindValue(1, QVariant((uint)m));
		q.exec();
	}
	return q.lastError();
}

void pki_scard::restoreSql(const QSqlRecord &rec)
{
	pki_key::restoreSql(rec);
	card_manufacturer = rec.value(VIEW_tokens_card_manufacturer).toString();
	card_serial = rec.value(VIEW_tokens_card_serial).toString();
	card_model = rec.value(VIEW_tokens_card_model).toString();
	card_label = rec.value(VIEW_tokens_card_label).toString();
	slot_label = rec.value(VIEW_tokens_slot_label).toString();
	object_id = rec.value(VIEW_tokens_object_id).toString();
	card_manufacturer = rec.value(VIEW_tokens_card_manufacturer).toString();
	isPub = false;
	qDebug() << card_manufacturer <<card_serial<<card_model<<card_label<<slot_label<<object_id;
}

QSqlError pki_scard::deleteSqlData()
{
	XSqlQuery q;
	QSqlError e = pki_key::deleteSqlData();
	if (e.isValid())
		return e;
	SQL_PREPARE(q, "DELETE FROM tokens WHERE item=?");
	q.bindValue(0, sqlItemId);
	q.exec();
	e = q.lastError();
	if (e.isValid())
		return e;
	SQL_PREPARE(q, "DELETE FROM token_mechanism WHERE item=?");
	q.bindValue(0, sqlItemId);
	q.exec();
	return q.lastError();
}

static BIGNUM *attribute2bignum(pkcs11 &p11, CK_OBJECT_HANDLE object, unsigned long attr)
{
	pk11_attr_data bn(attr);
	p11.loadAttribute(bn, object);
	return bn.getBignum();
}

static QByteArray attribute2bytearray(pkcs11 &p11, CK_OBJECT_HANDLE object, unsigned long attr)
{
	pk11_attr_data bn(attr);
	p11.loadAttribute(bn, object);
	return bn.getData();
}

/* CKA_EC_POINT is the DER encoding of an OCTET STRING with the point
 * (PKCS#11 2.40, 10.10); some tokens give the bare point (BTD-126). Both
 * start with 0x04, the OCTET STRING tag and the prefix of an uncompressed
 * point, so a bare point can parse as a complete OCTET STRING (P-256 with
 * X[0] = 0x3f). The rule (BTD-298): the attribute is DER only when it is
 * one complete OCTET STRING whose content has the length of a point of
 * the curve, 1 + 2 * fieldBytes (uncompressed, hybrid) or 1 + fieldBytes
 * (compressed); else it is the bare point. The content of a bare point
 * read as DER is 2 or more bytes shorter than the point, so it never has
 * a point length. */
QByteArray pki_scard::ecPointFromAttribute(const QByteArray &attr,
		int fieldBytes)
{
	const unsigned char *p = (const unsigned char *)attr.constData();
	ASN1_OCTET_STRING *os = d2i_ASN1_OCTET_STRING(NULL, &p, attr.size());
	QByteArray point = attr;
	if (os && p == (const unsigned char *)attr.constData() + attr.size()) {
		int len = ASN1_STRING_get_length(os);
		if (len == 1 + 2 * fieldBytes || len == 1 + fieldBytes)
			point = QByteArray((const char *)
				ASN1_STRING_get0_data(os), len);
	}
	ASN1_OCTET_STRING_free(os);
	ign_openssl_error();
	return point;
}

EVP_PKEY *pki_scard::load_pubkey(pkcs11 &p11, CK_OBJECT_HANDLE object) const
{
	unsigned long keytype;
	EVP_PKEY *pkey = NULL;
	/* the EVP_PKEY type for fromParamData(), not the CKK_* value
	 * (BTD-126) */
	int evpType = EVP_PKEY_NONE;
	/* the builder keeps a pointer to the point until fromParamData() */
	QByteArray ecPoint;

	pk11_attr_ulong type(CKA_KEY_TYPE);
	p11.loadAttribute(type, object);
	keytype = type.getValue();

	QMap<const char *, BIGNUM*> params;
	QSharedPointer<OSSL_PARAM_BLD> bld(OSSL_PARAM_BLD_new(),
				OSSL_PARAM_BLD_free);
	Q_CHECK_PTR(bld.get());

	switch (keytype) {
	case CKK_RSA:
		evpType = EVP_PKEY_RSA;
		params[OSSL_PKEY_PARAM_RSA_E] = attribute2bignum(p11, object, CKA_PUBLIC_EXPONENT);
		params[OSSL_PKEY_PARAM_RSA_N] = attribute2bignum(p11, object, CKA_MODULUS);
		break;
	case CKK_DSA:
		evpType = EVP_PKEY_DSA;
		params[OSSL_PKEY_PARAM_FFC_P] = attribute2bignum(p11, object, CKA_PRIME);
		params[OSSL_PKEY_PARAM_FFC_Q] = attribute2bignum(p11, object, CKA_SUBPRIME);
		params[OSSL_PKEY_PARAM_FFC_G] = attribute2bignum(p11, object, CKA_BASE);
		params[OSSL_PKEY_PARAM_PUB_KEY] = attribute2bignum(p11, object, CKA_VALUE);
		break;
#ifndef OPENSSL_NO_EC
	case CKK_EC: {
		QByteArray ba;

		ba = attribute2bytearray(p11, object, CKA_EC_PARAMS);
		EC_GROUP *group = (EC_GROUP *)
			d2i_bytearray(D2I_VOID(d2i_ECPKParameters), ba);
		int nid = EC_GROUP_get_curve_name(group);
		int fieldBytes = (EC_GROUP_get_degree(group) + 7) / 8;
		EC_GROUP_free(group);
		pki_openssl_error();
		OSSL_PARAM_BLD_push_utf8_string(bld.get(), OSSL_PKEY_PARAM_GROUP_NAME,
			OBJ_nid2sn(nid), 0);

		ecPoint = ecPointFromAttribute(
			attribute2bytearray(p11, object, CKA_EC_POINT),
			fieldBytes);
		evpType = EVP_PKEY_EC;
		OSSL_PARAM_BLD_push_octet_string(bld.get(), OSSL_PKEY_PARAM_PUB_KEY,
			ecPoint.data(), ecPoint.size());
		break;
	}
#ifdef EVP_PKEY_ED25519
	case CKK_EC_EDWARDS: {
		QByteArray ba;
		ASN1_OCTET_STRING *os;
		pk11_attr_data grp(CKA_EC_PARAMS);
		p11.loadAttribute(grp, object);
		pk11_attr_data pt(CKA_EC_POINT);
		p11.loadAttribute(pt, object);
		ba = pt.getData();
		os = (ASN1_OCTET_STRING *)
			d2i_bytearray(D2I_VOID(d2i_ASN1_OCTET_STRING), ba);
		pki_openssl_error();
		pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
			(const uint8_t *)ASN1_STRING_get0_data(os),
			ASN1_STRING_get_length(os));
		pki_openssl_error();
		ASN1_OCTET_STRING_free(os);
		pki_openssl_error();
		break;
	}
#endif
#endif
	default:
		throw errorEx(QString("Unsupported CKA_KEY_TYPE: %1\n").arg(keytype));
	}
	pki_openssl_error();
	/* RSA, DSA and EC are built from their parameters; EdDSA is
	 * built above (BTD-126: the condition was inverted) */
	if (!pkey)
		pkey = fromParamData(bld, params, evpType);
	return pkey;
}

void pki_scard::load_token(pkcs11 &p11, CK_OBJECT_HANDLE object)
{
	tkInfo ti = p11.tokenInfo();
	card_label = ti.label();
	card_manufacturer = ti.manufacturerID();
	card_serial = ti.serial();
	card_model = ti.model();
	pkiSource = token;
	isPub = false;

	pk11_attr_data id(CKA_ID);
	p11.loadAttribute(id, object);
	if (id.getAttribute()->ulValueLen > 0) {
		object_id = QString(id.getData().toHex());
	}

	try {
		pk11_attr_data label(CKA_LABEL);
		p11.loadAttribute(label, object);
		slot_label = label.getText();
	} catch (errorEx &err) {
		qDebug() << "No PubKey Label:" << err.getString();
		// ignore
	}
	if (slot_label.isEmpty()) {
		try{
			x509name xn;

			pk11_attr_data subj(CKA_SUBJECT);
			p11.loadAttribute(subj, object);
			QByteArray der = subj.getData();
			xn.d2i(der);
			slot_label = xn.getMostPopular();
			pki_openssl_error();
		} catch (errorEx &err) {
			qDebug() << "No Pubkey Subject:" << err.getString();
			// ignore
		}
	}
	EVP_PKEY *pkey = load_pubkey(p11, object);
	if (pkey) {
		if (key)
			EVP_PKEY_free(key);
		key = pkey;
	}
	setIntName(slot_label);
	pki_openssl_error();
}

pk11_attr_data pki_scard::getIdAttr() const
{
	pk11_attr_data id(CKA_ID);
	if (object_id.isEmpty())
		return id;

	QByteArray val = QByteArray::fromHex(object_id.toLocal8Bit());
	id.setValue(reinterpret_cast<const unsigned char*>(val.constData()), val.length());
	return id;
}

TokenDeletion pki_scard::prepareTokenDeletion()
{
	slotid slot;

	if (!prepare_card(&slot))
		return TokenDeletion();
	return prepareTokenDeletion(slot);
}

/* A key type the token code cannot store, by its OpenSSL name: ML-DSA
 * and other provider keys have no EVP_PKEY id (BTD-184) */
static errorEx unknownKeytype(const EVP_PKEY *pkey)
{
	const char *name = EVP_PKEY_get0_type_name(pkey);
	return errorEx(QString("Unknown Keytype %1").arg(name ? QString(name) :
			QString::number(EVP_PKEY_get_id(pkey))));
}

/* A parameter of the key pk that is stored on the token, not of the
 * (still empty) key of this object (BTD-126: store_token() read every
 * parameter from this->key) */
static BIGNUM *bnParam(const EVP_PKEY *pk, const char *name)
{
	BIGNUM *bn = nullptr;
	if (EVP_PKEY_get_bn_param(pk, name, &bn) <= 0 || !bn)
		throw errorEx(QString("The key has no parameter %1").arg(name));
	return bn;
}

static QByteArray octetParam(const EVP_PKEY *pk, const char *name)
{
	size_t len = 0;
	if (EVP_PKEY_get_octet_string_param(pk, name, nullptr, 0, &len) <= 0)
		throw errorEx(QString("The key has no parameter %1").arg(name));
	QByteArray ba(len, 0);
	if (EVP_PKEY_get_octet_string_param(pk, name,
			(unsigned char *)ba.data(), ba.size(), &len) <= 0)
		throw errorEx(QString("The key has no parameter %1").arg(name));
	ba.resize(len);
	return ba;
}

static int curveNid(const EVP_PKEY *pk)
{
	char gname[80];
	if (EVP_PKEY_get_group_name(pk, gname, sizeof gname, nullptr) <= 0)
		return NID_undef;
	return OBJ_txt2nid(gname);
}

pk11_attlist pki_scard::objectAttributesNoId(EVP_PKEY *pk, bool priv) const
{
	QByteArray ba;
	EC_GROUP *group = nullptr;

	pk11_attlist attrs(pk11_attr_ulong(CKA_CLASS,
			priv ? CKO_PRIVATE_KEY : CKO_PUBLIC_KEY));

	switch (EVP_PKEY_type(EVP_PKEY_id(pk))) {
	case EVP_PKEY_RSA:
		attrs << pk11_attr_ulong(CKA_KEY_TYPE, CKK_RSA) <<
			pk11_attr_data(CKA_MODULUS, bnParam(pk, OSSL_PKEY_PARAM_RSA_N)) <<
			pk11_attr_data(CKA_PUBLIC_EXPONENT, bnParam(pk, OSSL_PKEY_PARAM_RSA_E));
		break;
	case EVP_PKEY_DSA:
		attrs << pk11_attr_ulong(CKA_KEY_TYPE, CKK_DSA) <<
			pk11_attr_data(CKA_PRIME, bnParam(pk, OSSL_PKEY_PARAM_FFC_P)) <<
			pk11_attr_data(CKA_SUBPRIME, bnParam(pk, OSSL_PKEY_PARAM_FFC_Q)) <<
			pk11_attr_data(CKA_BASE, bnParam(pk, OSSL_PKEY_PARAM_FFC_G));
		break;
#ifndef OPENSSL_NO_EC
	case EVP_PKEY_EC:
		group = EC_GROUP_new_by_curve_name(curveNid(pk));
		if (group) {
			ba = i2d_bytearray(I2D_VOID(i2d_ECPKParameters), group);
			EC_GROUP_free(group);
		}
		attrs << pk11_attr_ulong(CKA_KEY_TYPE, CKK_EC) <<
			pk11_attr_data(CKA_EC_PARAMS, ba);
		break;
#ifdef EVP_PKEY_ED25519
	case EVP_PKEY_ED25519:
		attrs << pk11_attr_ulong(CKA_KEY_TYPE, CKK_EC_EDWARDS);
		// should it also return params, somehow?
		break;
#endif
#endif
	default:
		throw unknownKeytype(pk);

	}
	return attrs;
}

pk11_attlist pki_scard::objectAttributes(bool priv) const
{

	pk11_attlist attrs = objectAttributesNoId(key, priv);
	attrs << getIdAttr();
	return attrs;
}

TokenDeletion pki_scard::prepareTokenDeletion(const slotid &slot)
{
	/* the session stays open, and logged in, until destroy() ran */
	auto p11 = std::make_shared<pkcs11>();
	p11->startSession(slot, true);

	tkInfo ti = p11->tokenInfo();
	if (!XCA_YESNO("token.delete_key", tr("Delete the private key '%1' from the token '%2 (#%3)' ?").
			arg(getIntName()).arg(ti.label()).arg(ti.serial())))
		return TokenDeletion();

	if (!p11->tokenLoginForModification())
		return TokenDeletion();

	pk11_attlist atts = objectAttributes(true);
	QList<CK_OBJECT_HANDLE> objects = p11->objectList(atts);
	atts = objectAttributes(false);
	objects += p11->objectList(atts);

	TokenDeletion d;
	d.found = !objects.isEmpty();
	d.destroy = [p11, objects]() { p11->deleteObjects(objects); };
	return d;
}

TokenRename pki_scard::prepareTokenRename(const slotid &slot,
			const QString &name)
{
	/* the session stays open, and logged in, until apply() ran */
	auto p11 = std::make_shared<pkcs11>();
	p11->startSession(slot, true);

	if (!p11->tokenLoginForModification())
		return TokenRename();

	/* Private key */
	pk11_attlist attrs = objectAttributes(true);
	QList<CK_OBJECT_HANDLE> priv = p11->objectList(attrs);
	if (!priv.count())
		return TokenRename();
	/* Public key */
	attrs = objectAttributes(false);
	QList<CK_OBJECT_HANDLE> pub = p11->objectList(attrs);

	TokenRename r;
	r.found = true;
	r.apply = [p11, priv, pub, name]() {
		pk11_attr_data label(CKA_LABEL, name.toUtf8());
		p11->storeAttribute(label, priv[0]);
		if (pub.count())
			p11->storeAttribute(label, pub[0]);
	};
	return r;
}

void pki_scard::store_token(const slotid &slot, const pki_key *key)
{
	/* the decrypted key stayed in memory until exit when the caller
	 * passed decryptKey() straight on (BTD-293); here, in lib/, the
	 * SoftHSM service tests reach it under ASan (BTD-307) */
	std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>
		priv(key->decryptKey(), &EVP_PKEY_free);
	store_token(slot, priv.get());
}

void pki_scard::store_token(const slotid &slot, EVP_PKEY *pkey)
{
	QByteArray ba;
	pk11_attlist pub_atts;
	pk11_attlist priv_atts;
	QList<CK_OBJECT_HANDLE> objects;

	pub_atts = objectAttributesNoId(pkey, false);
	priv_atts = objectAttributesNoId(pkey, true);

	pkcs11 p11;
	p11.startSession(slot, true);

	QList<CK_OBJECT_HANDLE> objs = p11.objectList(pub_atts);
	if (objs.count() == 0)
		objs = p11.objectList(priv_atts);
	if (objs.count() != 0) {
		XCA_INFO(tr("This Key is already on the token"));
		load_token(p11, objs[0]);
		return;
	}
	pk11_attr_data new_id = select_id(p11);

	pub_atts << new_id <<
		pk11_attr_bool(CKA_TOKEN, true) <<
		pk11_attr_data(CKA_LABEL, getIntName().toUtf8()) <<
		pk11_attr_bool(CKA_PRIVATE, false) <<
		pk11_attr_bool(CKA_WRAP, true) <<
		pk11_attr_bool(CKA_ENCRYPT, true) <<
		pk11_attr_bool(CKA_VERIFY, true);

	priv_atts << new_id <<
		pk11_attr_bool(CKA_TOKEN, true) <<
		pk11_attr_data(CKA_LABEL, desc.toUtf8()) <<
		pk11_attr_bool(CKA_PRIVATE, true) <<
		pk11_attr_bool(CKA_UNWRAP, true) <<
		pk11_attr_bool(CKA_DECRYPT, true) <<
		pk11_attr_bool(CKA_SIGN, true);

	switch (EVP_PKEY_type(EVP_PKEY_id(pkey))) {
	case EVP_PKEY_RSA:
		priv_atts <<
		pk11_attr_data(CKA_PRIVATE_EXPONENT, bnParam(pkey, OSSL_PKEY_PARAM_RSA_D)) <<
		pk11_attr_data(CKA_PRIME_1, bnParam(pkey, OSSL_PKEY_PARAM_RSA_FACTOR1)) <<
		pk11_attr_data(CKA_PRIME_2, bnParam(pkey, OSSL_PKEY_PARAM_RSA_FACTOR2)) <<
		pk11_attr_data(CKA_EXPONENT_1, bnParam(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT1)) <<
		pk11_attr_data(CKA_EXPONENT_2, bnParam(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT2)) <<
		pk11_attr_data(CKA_COEFFICIENT, bnParam(pkey, OSSL_PKEY_PARAM_RSA_COEFFICIENT1));
		break;
	case EVP_PKEY_DSA:
		priv_atts << pk11_attr_data(CKA_VALUE, bnParam(pkey, OSSL_PKEY_PARAM_PRIV_KEY));
		pub_atts << pk11_attr_data(CKA_VALUE, bnParam(pkey, OSSL_PKEY_PARAM_PUB_KEY));
		break;
#ifndef OPENSSL_NO_EC
	case EVP_PKEY_EC: {
		/* Public Key: the point of pkey (BTD-126: it was the curve's
		 * generator), as the DER OCTET STRING of CKA_EC_POINT */
		QByteArray ba = octetParam(pkey, OSSL_PKEY_PARAM_PUB_KEY);
		ASN1_OCTET_STRING *os = ASN1_OCTET_STRING_new();
		ASN1_STRING_set1_data(os, (const uint8_t *)ba.constData(),
				      ba.size());
		ba = i2d_bytearray(I2D_VOID(i2d_ASN1_OCTET_STRING), os);
		ASN1_OCTET_STRING_free(os);
		pki_openssl_error();
		pub_atts << pk11_attr_data(CKA_EC_POINT, ba);

		/* Private key */
		priv_atts << pk11_attr_data(CKA_VALUE, bnParam(pkey, OSSL_PKEY_PARAM_PRIV_KEY));
		break;
	}
#endif
	default:
		throw unknownKeytype(pkey);

	}

	if (!p11.tokenLoginForModification())
		throw errorEx(tr("PIN input aborted"));

	try {
		p11.createObject(pub_atts);
	} catch (errorEx &e) {
		XCA_ERROR(e);
	}
	p11.createObject(priv_atts);

	pub_atts.reset();

	pub_atts = objectAttributesNoId(pkey, false);
	pub_atts << new_id;

	objs = p11.objectList(pub_atts);
	if (objs.count() == 0)
		throw errorEx(tr("Unable to find copied key on the token"));

	load_token(p11, objs[0]);
}

QList<int> pki_scard::possibleHashNids()
{
	QList<int> nids;

	if (!Settings["only_token_hashes"])
		return pki_key::possibleHashNids();

	foreach(CK_MECHANISM_TYPE mechanism, mech_list) {
		switch (EVP_PKEY_type(getKeyType())) {
		case EVP_PKEY_RSA:
			switch (mechanism) {
			case CKM_MD5_RSA_PKCS:    nids << NID_md5; break;
			case CKM_RIPEMD160_RSA_PKCS: nids << NID_ripemd160; break;
			case CKM_SHA1_RSA_PKCS:   nids << NID_sha1; break;
			case CKM_SHA256_RSA_PKCS: nids << NID_sha256; break;
			case CKM_SHA384_RSA_PKCS: nids << NID_sha384; break;
			case CKM_SHA512_RSA_PKCS: nids << NID_sha512; break;
			}
			break;
		case EVP_PKEY_DSA:
			switch (mechanism) {
			case CKM_DSA_SHA1:        nids << NID_sha1; break;
			}
			break;
#ifndef OPENSSL_NO_EC
		case EVP_PKEY_EC:
			switch (mechanism) {
			case CKM_ECDSA_SHA1:      nids << NID_sha1; break;
			}
			break;
#endif
		}
	}
	if (nids.count() == 0) {
		switch (EVP_PKEY_type(getKeyType())) {
		case EVP_PKEY_RSA:
			nids << NID_md5 << NID_sha1 << NID_sha256 <<
				NID_sha384 << NID_sha512 << NID_ripemd160;
			break;
		case EVP_PKEY_DSA:
#ifndef OPENSSL_NO_EC
		case EVP_PKEY_EC:
#endif
			nids << NID_sha1;
			break;
		}
	}
	return nids;
}

bool pki_scard::find_key_on_card(slotid *slot) const
{
	pkcs11 p11;
	slotid sl;

	pk11_attlist cls(pk11_attr_ulong(CKA_CLASS, CKO_PUBLIC_KEY));
	cls << getIdAttr();

	foreach(sl, p11.getSlotList()) {
		pkcs11 p11sess;
		p11sess.startSession(sl);

		foreach(CK_OBJECT_HANDLE object, p11sess.objectList(cls)) {
			EVP_PKEY *pkey = load_pubkey(p11sess, object);
			bool match = EVP_PKEY_eq(key, pkey) == 1;
			EVP_PKEY_free(pkey);

			if (match) {
				*slot = sl;
				return true;
			}
		}
	}
	return false;
}

/* Assures the correct card is inserted and
 * returns the slot ID in slot true on success */
bool pki_scard::prepare_card(slotid *slot) const
{
	if (!pkcs11::libraries.loaded())
		return false;

	QString msg = tr("Please insert card: %1 %2 [%3] with Serial: %4").
			arg(card_manufacturer).arg(card_model).
			arg(card_label).arg(card_serial);
	do {
		try {
			if (find_key_on_card(slot))
				return true;
		} catch (errorEx &err) {
			qDebug() << "find_key_on_card:" << err.getString();
		} catch (...) {
			qDebug() << "find_key_on_card exception";
		}
	} while (XCA_OKCANCEL("token.insert_card", msg));
	return false;
}

class keygenThread: public QThread
{
public:
	errorEx err;
	const keyjob task;
	QString name;
	pkcs11 *p11;
	pk11_attr_data id;

	keygenThread(const keyjob &t, const QString &n, pkcs11 *_p11,
				const pk11_attr_data &_id)
		: QThread(), task(t), name(n), p11(_p11), id(_id) { }

	void run()
	{
		try {
			id = p11->generateKey(name, task.ktype.mech, task.size,
						task.ec_nid, id);
		} catch (errorEx &e) {
			err = e;
		}
	}
};

pk11_attr_data pki_scard::select_id(const pkcs11 &p11) const
{
	tkInfo ti = p11.tokenInfo();
	pk11_attr_data new_id(CKA_ID);

	QList<QStringList> fixed_ids = ti.fixed_ids();
	if (fixed_ids.size() > 0)
		new_id = fixedSlotId(ti.model(), fixed_ids);
	else
		new_id = p11.findUniqueID(CKO_PUBLIC_KEY);
	return new_id;
}

pk11_attr_data pki_scard::fixedSlotId(const QString &model,
				const QList<QStringList> &fixed_ids)
{
	pk11_attr_data new_id(CKA_ID);
	QStringList items;
	for (const QStringList &item : fixed_ids)
		items << item[0];
	int i = PwDialogCore::selectKeySlot(model, items);
	/* no valid choice: an empty CKA_ID would reach generateKey() or
	 * store_token() and land in a slot nobody chose (BTD-176) */
	if (i < 0 || i >= fixed_ids.size())
		throw secretError(secretError::rejected,
			QObject::tr("No key slot of %1 selected: the answer "
				"must be a slot number 1-%2")
				.arg(model).arg(fixed_ids.size()));
	new_id.setULong(fixed_ids[i][1].toULong());
	return new_id;
}

void pki_scard::generate(const keyjob &task)
{
	pk11_attlist atts;

	pkcs11 p11;
	p11.startSession(task.slot, true);
	p11.getRandom();

	pk11_attr_data new_id = select_id(p11);

	if (!p11.tokenLoginForModification())
		return;

	XcaProgress progress;
	keygenThread kt(task, getIntName(), &p11, new_id);
	kt.start();
	while (!kt.wait(20)) {
		progress.increment();
	}
	if (!kt.err.isEmpty())
		throw errorEx(kt.err);

	atts << pk11_attr_ulong(CKA_CLASS, CKO_PUBLIC_KEY) << kt.id;
	QList<CK_OBJECT_HANDLE> objects = p11.objectList(atts);
	if (objects.count() != 1)
		qCritical() << "OBJECTS found:" << objects.count();

	if (objects.count() == 0)
		throw errorEx(tr("Unable to find generated key on card"));

	load_token(p11, objects[0]);
}

pki_scard::~pki_scard()
{
}

QString pki_scard::getTypeString(void) const
{
	return tr("Token %1").arg(pki_key::getTypeString());
}

EVP_PKEY *pki_scard::decryptKey() const
{
	slotid slot_id;
	QString key_id;

	if (!prepare_card(&slot_id))
		throw errorEx(tr("Failed to find the key on the token"));

	pkcs11 *p11 = new pkcs11();
	p11->startSession(slot_id);
	if (p11->tokenLogin(card_label, false).isNull()) {
		delete p11;
		throw errorEx(tr("Invalid Pin for the token"));
	}
	pk11_attlist atts = objectAttributes(true);
	QList<CK_OBJECT_HANDLE> priv_objects = p11->objectList(atts);
	if (priv_objects.count() != 1) {
		delete p11;
		throw errorEx(tr("Failed to find the key on the token"));
	}
	EVP_PKEY *pkey = p11->getPrivateKey(key, priv_objects[0]);

	if (!pkey) {
		delete p11;
		throw errorEx(tr("Failed to initialize the key on the token"));
	}
	pki_openssl_error();
	return pkey;
}

void pki_scard::changePin()
{
	slotid slot;

	if (!prepare_card(&slot))
		return;

	pkcs11 p11;
	p11.changePin(slot, false);
}

void pki_scard::changeSoPin()
{
	slotid slot;

	if (!prepare_card(&slot))
		return;

	pkcs11 p11;
	p11.changePin(slot, true);
}

void pki_scard::initPin()
{
	slotid slot;

	if (!prepare_card(&slot))
		return;

	pkcs11 p11;
	p11.initPin(slot);
}

bool pki_scard::isToken()
{
	return true;
}

QVariant pki_scard::getIcon(const dbheader *hd) const
{
	return hd->id == HD_internal_name ?
		XcaPresentation::icon(":scardIco") : QVariant();
}

bool pki_scard::visible() const
{
	QStringList sl;
	if (pki_base::visible())
		return true;

	sl << card_serial << card_manufacturer << card_model <<
		card_label << slot_label << object_id;
	foreach(QString s, sl) {
		if (s.contains(limitPattern))
			return true;
	}
	return false;
}

void pki_scard::updateLabel(QString label)
{
	XSqlQuery q;
	Transaction;

	if (slot_label == label)
		return;
	TransThrow();

	SQL_PREPARE(q, "UPDATE tokens SET slot_label=? WHERE item=?");
	q.bindValue(0, label);
	q.bindValue(1, sqlItemId);
	execOrThrow(q, tr("The token label of '%1' could not be stored")
			.arg(getIntName()));
	AffectedItems(sqlItemId);
	QString old = slot_label;
	slot_label = label;
	/* an outer transaction may still roll back (review of xca#68) */
	DbTransaction::onRollback([this, old]() { slot_label = old; });
	TransCommitThrow();
}
