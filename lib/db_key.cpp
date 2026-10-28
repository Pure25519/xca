/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "db_key.h"
#include "pki_evp.h"

#include "pki_scard.h"
#include "pki_x509super.h"

#include "audit.h"
#include "exception.h"
#include "pkcs11.h"

#include "XcaWarningCore.h"
#include "PwDialogCore.h"

db_key::db_key() : db_base("keys")
{
	sqlHashTable = "public_keys";
	pkitype << asym_key << smartCard;
	updateHeaders();
	loadContainer();
}

void db_key::loadContainer()
{
	XSqlQuery q;

	db_base::loadContainer();
	foreach(pki_key *key, Store.getAll<pki_key>())
		key->setUcount(0);

	SQL_PREPARE(q, "SELECT pkey, COUNT(*) FROM x509super WHERE pkey IS NOT NULL GROUP by pkey");
	q.exec();
	while (q.next()) {
		pki_key *key = Store.lookupPki<pki_key>(q.value(0));
		if (!key) {
			qDebug() << "Unknown key" << q.value(0).toULongLong();
			continue;
		}
		key->setUcount(q.value(1).toInt());
	}
	XCA_SQLERROR(q.lastError());
}

dbheaderList db_key::getHeaders()
{
	dbheaderList h = db_base::getHeaders();
	h <<	new dbheader(HD_key_type, true, tr("Type")) <<
		new num_dbheader(HD_key_size, true, tr("Size")) <<
#ifndef OPENSSL_NO_EC
		new dbheader(HD_key_curve, false,tr("EC Group")) <<
#endif
		new num_dbheader(HD_key_use, true, tr("Use")) <<
		new dbheader(HD_key_passwd, true, tr("Password"));
	return h;
}

pki_base *db_key::newPKI(enum pki_type type)
{
	if (type == asym_key)
		return new pki_evp("");
	return new pki_scard("");
}

QList<pki_key *> db_key::getAllKeys()
{
	return Store.sqlSELECTpki<pki_key>("SELECT item from public_keys");
}

QList<pki_key *> db_key::getUnusedKeys()
{
	return Store.sqlSELECTpki<pki_key>(
		"SELECT public_keys.item FROM public_keys "
		"LEFT OUTER JOIN x509super ON x509super.pkey= public_keys.item "
		"WHERE x509super.item IS NULL");
}

void db_key::remFromCont(const QModelIndex &idx)
{
	db_base::remFromCont(idx);
	XSqlQuery q;

	QList<pki_x509super*> items = Store.sqlSELECTpki<pki_x509super>(
		"SELECT item FROM x509super WHERE pkey is NULL");
	foreach(pki_x509super *x509s, items) {
		x509s->setRefKey(NULL);
	}
	/* "UPDATE x509super SET pkey=NULL WHERE pkey=?" done in
	 * pki->deleteSqlData() */
}

void db_key::inToCont(pki_base *pki)
{
	db_base::inToCont(pki);
	pki_key *key = static_cast<pki_key*>(pki);
	unsigned hash = key->hash();
	QList<pki_x509super*> items = Store.sqlSELECTpki<pki_x509super>(
		"SELECT item FROM x509super WHERE pkey IS NULL AND key_hash=?",
		QList<QVariant>() << QVariant(hash));
	XSqlQuery q;
	SQL_PREPARE(q, "UPDATE x509super SET pkey=? WHERE item=?");
	q.bindValue(0, key->getSqlItemId());
	foreach(pki_x509super *x509s, items) {
		if (!x509s->compareRefKey(key))
			continue;
		/* Found item matching this key */
		x509s->setRefKey(key);
		q.bindValue(1, x509s->getSqlItemId());
		AffectedItems(x509s->getSqlItemId());
		q.exec();
		XCA_SQLERROR(q.lastError());
	}
}

pki_base* db_key::insert(pki_base *item)
{
	pki_key *lkey = dynamic_cast<pki_key *>(item);
	pki_key *oldkey;

	oldkey = static_cast<pki_key *>(getByReference(lkey));
	if (oldkey != NULL) {
		if ((oldkey->isPrivKey() && lkey->isPrivKey()) || lkey->isPubKey()){
			XCA_INFO(
			tr("The key is already in the database as:\n'%1'\nand is not going to be imported").arg(oldkey->getIntName()));
			delete lkey;
			return NULL;
		} else {
			XCA_INFO(
			tr("The database already contains the public part of the imported key as\n'%1\nand will be completed by the new, private part of the key").arg(oldkey->getIntName()));
		}
	}
	return insertKey(lkey, oldkey);
}

pki_key *db_key::insertKey(pki_key *lkey, pki_key *oldkey)
{
	pki_evp *evp = dynamic_cast<pki_evp*>(lkey);

	if (evp)
		evp->setOwnPass(pki_evp::ptCommon);
	if (oldkey) {
		lkey->setComment(oldkey->getComment());
		lkey->selfComment(tr("Extending public key from %1 by imported key '%2'")
			.arg(oldkey->getInsertionDate().toPretty())
			.arg(lkey->getIntName()));
		lkey->setIntName(oldkey->getIntName());
		deletePKI(index(oldkey));
	}
	return dynamic_cast<pki_key *>(insertPKI(lkey));
}

void db_key::keyParams(AuditParams &params, pki_key *key)
{
	params.set("key_type", key->getKeyTypeString());
	params.set("key_size", EVP_PKEY_bits(key->getPubKey()));
#ifndef OPENSSL_NO_EC
	if (key->getKeyType() == EVP_PKEY_EC)
		params.set("curve", OBJ_nid2sn(key->ecParamNid()));
#endif
}

static AuditParams keyjobParams(const keyjob &task, const QString &name)
{
	AuditParams p;
	p.set("name", name);
	if (!task.ktype.name.isEmpty())
		p.set("key_type", task.ktype.name);
	if (task.isEC() && task.ec_nid != NID_undef)
		p.set("curve", OBJ_nid2sn(task.ec_nid));
	else if (!task.isED25519())
		p.set("key_size", task.size);
	return p;
}

pki_key *db_key::generate(const keyjob &task, const QString &name,
			AuditParams &params, const ServiceContext &ctx)
{
	pki_key *key = nullptr, *stored = nullptr;

	if (task.ktype.type == -1)
		throw serviceError("invalid_key_type", tr("Unknown key type"));
	if (!task.isEC() && !task.isED25519() && task.size < 32)
		throw serviceError("invalid_key_size", tr("Key size too small !"));
	if (!keyjob(task).isValid())    /* isValid() is not const */
		throw serviceError("invalid_curve", tr("Unknown EC curve"));

    try {
	if (task.isToken()) {
		key = new pki_scard(name);
	} else {
		key = new pki_evp(name);
	}
	/* outside the transaction: may take long and may use a token */
	key->generate(task);
	key->pkiSource = generated;
	if (key->getIntName().isEmpty())
		key->autoIntName(name);

	Transaction;
	TransThrow();

	keyParams(params, key);
	params.set("name", key->getIntName());
	params.set("fingerprint", key->fingerprint("der sha256"));

	if (getByReference(key))
		throw serviceError("duplicate_key",
			tr("The key already exists in the database"));
	stored = dynamic_cast<pki_key*>(insert(key));
	/* insert() keeps the key in the store or deletes it */
	key = nullptr;
	if (!stored)
		throw serviceError("database_error",
			tr("The key could not be stored"));
	AuditLog::append(ctx, "key.generate", "key",
			stored->getSqlItemId().toString(), params);
	if (!TransCommit())
		throw serviceError("database_error",
			tr("Failed to commit the database transaction"));
    }
    catch (...) {
	delete key;
	throw;
    }
    return stored;
}

pki_key *db_key::newKey(const ServiceContext &ctx, const keyjob &task,
			const QString &name)
{
	AuditParams params = keyjobParams(task, name);
	try {
		return generate(task, name, params, ctx);
	} catch (serviceError &err) {
		/* after the rollback, so the entry is kept (lib/audit.h) */
		AuditLog::append(ctx, "key.generate", "key",
				QString(), params, "failure", err.code);
		throw;
	} catch (...) {
		/* errorEx (OpenSSL, token, database) and anything else */
		AuditLog::append(ctx, "key.generate", "key",
				QString(), params, "failure", "internal_error");
		throw;
	}
}

pki_key *db_key::newKey(const keyjob &task, const QString &name)
{
	pki_key *key = NULL;

	if (!task.isEC() && !task.isED25519() && task.size >= 32 &&
	    (task.size < 1024 || task.size > 8192))
	{
		if (!XCA_YESNO(tr("You are sure to create a key of the size: %1 ?").arg(task.size)))
			return NULL;
	}
	try {
		key = newKey(ServiceContext::localUser(
				ServiceContext::processChannel), task, name);
		emit keyDone(key);
		createSuccess(key);
	} catch (errorEx &err) {
		key = NULL;
		XCA_ERROR(err);
	}
	return key;
}

int db_key::exportFlags(pki_base *pki) const
{
	int disable_flags = 0;

	pki_key *key = dynamic_cast<pki_key *>(pki);

	if (!key)
		return 0;

	int keytype = key->getKeyType();
	if (keytype != EVP_PKEY_RSA && keytype != EVP_PKEY_DSA)
		disable_flags |= F_PVK;
#ifdef EVP_PKEY_ED25519
	if (keytype == EVP_PKEY_ED25519)
		disable_flags |= F_TRADITION;
#endif
	if (!key->SSH2_compatible())
		disable_flags |= F_SSH2;

	if (key->isPubKey() || key->isToken())
		disable_flags |= F_PRIVATE;
	if (keytype != EVP_PKEY_RSA && key->getJWKcrv().isEmpty())
		disable_flags |= F_JWK;

	return disable_flags;
}

const pki_export *db_key::clipboardFormat() const
{
	return pki_export::by_id(Settings["KeyFormat"]);
}

void db_key::writeItem(pki_base *pki, const pki_export *xport,
			QIODevice &file, const Passwd &pass) const
{
	const EVP_CIPHER *algo = NULL;
	pki_key *key = dynamic_cast<pki_key *>(pki);
	pki_evp *privkey = dynamic_cast<pki_evp *>(key);

	if (!key)
		return;
	if (xport->match_all(F_CRYPT))
		algo = EVP_aes_256_cbc();

	if (privkey && xport->match_all(F_DER | F_PRIVATE))
		privkey->writeKey(file, NULL, pass, false);
	else if (privkey && xport->match_all(F_PEM | F_PRIVATE))
		privkey->writeKey(file, algo, pass, true);
	else if (xport->match_all(F_DER))
		key->writePublic(file, false);
	else if (xport->match_all(F_PEM))
		key->writePublic(file, true);
	else if (privkey && xport->match_all(F_PKCS8))
		privkey->writePKCS8(file, algo, pass, true);
	else if (privkey && xport->match_all(F_SSH2 | F_PRIVATE))
		privkey->writeSSH2private(file);
	else if (xport->match_all(F_SSH2))
		key->writeSSH2public(file);
	else if (privkey && xport->match_all(F_PVK))
		privkey->writePVKprivate(file);
	else
		db_base::writeItem(pki, xport, file, pass);
}

void db_key::updateKeyEncryptionScheme()
{
	bool common_success = true;
	if (!pki_evp::validateDatabasePassword(pki_evp::passwd))
		return;
	if (Settings["legacy-keys-updated"])
		return;

	QList<pki_evp *> privates, withOwnPassword;
	privates = Store.sqlSELECTpki<pki_evp>("SELECT item from private_keys");

	qDebug() << "Updating encryption scheme of" << privates.size() << "keys";

	Transaction;
	if (!TransBegin())
		return;

	for (pki_evp *key : privates) {
		if (key->isPubKey()) {
			qWarning() << "BUG: private key" << key << "is not private";
			continue; // Should not happen
		}
		bool conv_success = key->updateLegacyEncryption();
		if (!conv_success && key->getOwnPass() == pki_key::ptPrivate) {
			withOwnPassword << key;
		} else {
			common_success &= conv_success;
		}
	}
	qDebug() << "Success:" << common_success << "Legacy keys:"
			<< withOwnPassword.size();
	ign_openssl_error();
	TransCommit();
	if (withOwnPassword.size() > 0) {
		QString items;
		for (pki_evp *key : withOwnPassword)
			items += "'" + key->getIntName() + "' ";
		XCA_WARN(tr("Internal key update: The keys: %1 must be updated once by resetting and setting its private password").arg(items));
	}
	if (common_success && withOwnPassword.isEmpty())
		Settings["legacy-keys-updated"] = true;
}

void db_key::setOwnPass(QModelIndex idx, enum pki_key::passType x)
{
	pki_evp *targetKey = fromIndex<pki_evp>(idx);
	enum pki_key::passType old_type;

	if (!idx.isValid() || !targetKey)
		return;
	if (targetKey->isToken()) {
		throw errorEx(tr("Tried to change password of a token"));
	}
	old_type = targetKey->getOwnPass();
	targetKey->setOwnPass(x);
	if (!targetKey->sqlUpdatePrivateKey())
		targetKey->setOwnPass(old_type);
}
