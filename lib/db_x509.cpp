/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "db_x509.h"
#include "db_x509req.h"
#include "db_crl.h"
#include "pki_x509.h"
#include "pki_x509req.h"
#include "pki_crl.h"
#include "pki_temp.h"
#include "pki_pkcs12.h"
#include "pki_pkcs7.h"
#include "pki_evp.h"
#include "pki_scard.h"
#include "pass_info.h"
#include "database_model.h"
#include "entropy.h"
#include "audit.h"
#include "issuance.h"
#include "request.h"

#include "XcaWarningCore.h"
#include "PwDialogCore.h"

#include <QRegularExpression>
#include <QTimeZone>

#include <openssl/rand.h>

db_x509::db_x509() : db_x509super("certificates")
{
	sqlHashTable = "certs";
	pkitype << x509;
	pkitype_depends << x509_req;
	updateHeaders();
	loadContainer();
}

void db_x509::loadContainer()
{
	db_x509super::loadContainer();

	XSqlQuery q("SELECT item, issuer FROM certs WHERE issuer is NOT NULL");
	while (q.next()) {
		pki_base *root = treeItem;
		pki_x509 *cert = Store.lookupPki<pki_x509>(q.value(0));
		pki_x509 *issuer = Store.lookupPki<pki_x509>(q.value(1));
		if (cert && issuer) {
			cert->setSigner(issuer);
			if (cert != issuer)
				root = issuer;
		}
		if (cert && cert->getParent() != root) {
			qDebug() << "MOVE" << cert->getIntName()
				<< "from" << cert->getParent()->getIntName()
				<< "to" << root->getIntName();
			treeItem->takeChild(cert);
			root->insert(cert);
		}
	}
	emit columnsContentChanged();
}

dbheaderList db_x509::getHeaders()
{
	dbheaderList h = db_x509super::getHeaders();
	h <<	new dbheader(HD_cert_ca, true, tr("CA"),
			tr("reflects the basic Constraints extension")) <<
		new num_dbheader(HD_cert_serial, true, tr("Serial")) <<
		new num_dbheader(HD_cert_md5fp, false,tr("MD5 fingerprint")) <<
		new num_dbheader(HD_cert_sha1fp,false,tr("SHA1 fingerprint")) <<
		new num_dbheader(HD_cert_sha256fp,false,tr("SHA256 fingerprint")) <<
		new date_dbheader(HD_cert_notBefore, false,tr("Start date"),
				tr("Not before")) <<
		new date_dbheader(HD_cert_notAfter, true, tr("Expiry date"),
				tr("Not after")) <<
		new date_dbheader(HD_cert_revocation,false, tr("Revocation")) <<
		new date_dbheader(HD_cert_crl_expire,true, tr("CRL Expiration"));
	return h;
}

pki_base *db_x509::newPKI(enum pki_type type)
{
	(void)type;
	return new pki_x509();
}

QList<pki_x509 *> db_x509::getAllIssuers()
{
	/* Select X509 CA certificates with available private key */
	return Store.sqlSELECTpki<pki_x509>(
		"SELECT x509super.item FROM x509super "
		"JOIN private_keys ON x509super.pkey = private_keys.item "
		"JOIN certs ON certs.item = x509super.item "
		"WHERE certs.ca=1") +
		Store.sqlSELECTpki<pki_x509>(
		"SELECT x509super.item FROM x509super "
		"JOIN tokens ON x509super.pkey = tokens.item "
		"JOIN certs ON certs.item = x509super.item "
		"WHERE certs.ca=1");
}

void db_x509::remFromCont(const QModelIndex &idx)
{
	if (!idx.isValid())
		return;
	db_crl *crls = Database.model<db_crl>();
	db_x509super::remFromCont(idx);
	pki_base *pki = fromIndex(idx);
	pki_x509 *child;
	pki_base *new_parent;
	QList<pki_x509 *> childs;

	Transaction;
	if (!TransBegin())
		return;

	while (pki->childCount()) {
		child = dynamic_cast<pki_x509*>(pki->takeFirst());
		child->delSigner(dynamic_cast<pki_x509*>(pki));
		new_parent = child->findIssuer();
		insertChild(child, new_parent);
		if (new_parent)
			childs << child;
	}
	XSqlQuery q;
	SQL_PREPARE(q, "UPDATE certs SET issuer=? WHERE item=?");
	foreach(pki_x509 *child, childs) {
		q.bindValue(0, child->getSigner()->getSqlItemId());
		q.bindValue(1, child->getSqlItemId());
		AffectedItems(child->getSqlItemId());
		q.exec();
	}
	crls->removeSigner(pki);
	TransCommit();
}

static bool recursiveSigning(pki_x509 *cert, pki_x509 *client)
{
	/* recursive signing check */
	for (pki_x509 *s = cert->getSigner(); s; s = s->getSigner()) {
		if (s == s->getSigner()) {
			return false;
		}
		if (s == client) {
			qWarning() << "Recursive signing:" << s->getIntName()
				<< "<->" << cert->getIntName();
			return true;
		}
	}
	return false;
}

void db_x509::inToCont(pki_base *pki)
{
	pki_x509 *cert = dynamic_cast<pki_x509*>(pki);
	cert->setParent(nullptr);
	pki_base *root = cert->getSigner();

	insertChild(cert, root);

	QList<pki_x509 *> childs;
	QList<pki_x509 *> items;
	unsigned pubhash = cert->pubHash();
	unsigned namehash = cert->getSubject().hashNum();
	x509revList revList;

	/* Search for another certificate (name and key)
	 * and use its childs if we are newer */
	items = Store.sqlSELECTpki<pki_x509>(
		"SELECT x509super.item FROM x509super "
		"JOIN certs ON certs.item = x509super.item "
		"WHERE certs.ca=1 AND x509super.subj_hash=? "
		"AND x509super.key_hash=?",
			QList<QVariant>() << namehash << pubhash);
	foreach(pki_x509 *other, items) {
		if (other == cert)
			continue;
		if (!other->compareNameAndKey(cert))
			continue;
		if (cert->getNotAfter() < other->getNotAfter())
			continue;
		foreach(pki_base *b, other->getChildItems()) {
			pki_x509 *child = dynamic_cast<pki_x509*>(b);
			if (!child)
				continue;
			child->delSigner(other);
			childs << child;
		}
		revList.merge(other->getRevList());
	}
	/* Search rootItem childs, whether they are ours */
	foreach(pki_base *b, treeItem->getChildItems()) {
		pki_x509 *child = dynamic_cast<pki_x509*>(b);
		if (!child || child == cert || child->getSigner() == child)
			continue;
		if (child->verify_only(cert))
			childs << child;
	}
	/* move collected childs to us */
	XSqlQuery q;
	x509revList revokedChilds;
	SQL_PREPARE(q, "UPDATE certs SET issuer=? WHERE item=?");
	q.bindValue(0, cert->getSqlItemId());
	foreach(pki_x509 *child, childs) {
		if (recursiveSigning(cert, child))
			continue;
		if (!child->verify(cert))
			continue;
		insertChild(child, cert);
		q.bindValue(1, child->getSqlItemId());
		AffectedItems(child->getSqlItemId());
		q.exec();
		XCA_SQLERROR(q.lastError());
		if (child->isRevoked())
			revokedChilds << child->getRevocation();
	}
	q.finish();
	revList.merge(revokedChilds);
	cert->setRevocations(revList);

	/* Update CRLs */
	QList<pki_crl *> crls = Store.sqlSELECTpki<pki_crl>(
			"SELECT item FROM crls WHERE iss_hash=?",
			QList<QVariant>() << namehash);
	SQL_PREPARE(q, "UPDATE crls SET issuer=? WHERE item=?");
	foreach(pki_crl *crl, crls) {
		crl->verify(cert);
		if (cert != crl->getIssuer())
			continue;
		q.bindValue(0, cert->getSqlItemId());
		q.bindValue(1, crl->getSqlItemId());
		AffectedItems(crl->getSqlItemId());
		q.exec();
		XCA_SQLERROR(q.lastError());
	}
}

QList<pki_x509*> db_x509::getCerts(bool unrevoked)
{
	QList<pki_x509*> c;
	c.clear();
	foreach(pki_x509 *pki, Store.getAll<pki_x509>()) {
		if (unrevoked && pki->isRevoked())
			continue;
		c.append(pki);
	}
	return c;
}

void db_x509::writeIndex(const QString &fname, bool hierarchy) const
{
	if (hierarchy) {
		QString dir = fname + "/";
		if (!QDir().mkpath(fname)) {
			throw errorEx(tr("Failed to create directory '%1'")
				.arg(fname));
		}
		QList<pki_x509*> issuers = Store.sqlSELECTpki<pki_x509>(
			"SELECT DISTINCT issuer FROM certs WHERE issuer != item");
		foreach(pki_x509 *ca, issuers) {
			XFile file(dir + ca->getUnderlinedName() + ".txt");
			file.open_write();
			writeIndex(file, Store.sqlSELECTpki<pki_x509>(
				"SELECT item FROM certs WHERE issuer=?",
				QList<QVariant>()<<QVariant(ca->getSqlItemId()))
			);
		}
	} else {
		XFile file(fname);
		file.open_write();
		writeIndex(file, Store.sqlSELECTpki<pki_x509>(
					"SELECT item FROM certs"));
	}
}

a1int db_x509::randomSerial()
{
	/* Rule 2 of the certstrap triage (BTD-31): positive, at least 64 bit
	 * from the CSPRNG, at most 20 octets. serial_len / 8 octets, at least
	 * 9: the first one is 0x01..0x7f, so the value is positive and keeps
	 * its length, the others are random (>= 70 random bits). */
	unsigned char buf[20];
	int len = qBound(9, (int)Settings["serial_len"] / 8, 20);

	Entropy::seed_rng();
	do {
		if (RAND_bytes(buf, len) != 1) {
			ign_openssl_error();
			throw serviceError("random_failure",
				tr("The random number generator failed"));
		}
		buf[0] &= 0x7f;
	} while (buf[0] == 0);

	a1int serial;
	serial.setRaw(buf, len);
	return serial;
}

bool db_x509::serialInUse(pki_x509 *signer, const a1int &serial)
{
	x509rev rev;

	if (signer->getSerial() == serial)
		return true;
	rev.setSerial(serial);
	if (signer->getRevList().contains(rev))
		return true;
	if (signer->getBySerial(serial))
		return true;

	XSqlQuery q;
	SQL_PREPARE(q, "SELECT COUNT(*) FROM certs WHERE issuer=? AND serial=?");
	q.bindValue(0, signer->getSqlItemId());
	q.bindValue(1, serial.toHex());
	q.exec();
	if (q.lastError().isValid())
		throw errorEx(q.lastError());
	return q.first() && q.value(0).toInt() > 0;
}

a1int db_x509::getUniqueSerial(pki_x509 *signer,
				const std::function<a1int()> &draw)
{
	// returns an unused unique serial
	a1int serial;
	for (int i=0; ; i++) {
		if (i > 100)
			throw serviceError("serial_exhausted",
				tr("Failed to retrieve unique random serial"));
		serial = draw();
		if (serial == a1int(0L))
			continue;
		if (!signer)
			break;
		if (serialInUse(signer, serial))
			continue;
		break;
	}
	return serial;
}

pki_base *db_x509::insert(pki_base *item)
{
	pki_x509 *cert = dynamic_cast<pki_x509 *>(item);
	pki_x509 *oldcert = dynamic_cast<pki_x509 *>(getByReference(cert));
	if (oldcert) {
		XCA_INFO(tr("The certificate already exists in the database as:\n'%1'\nand so it was not imported").arg(oldcert->getIntName()));
		delete cert;
		return NULL;
	}
	return insertPKI(cert);
}

void db_x509::markRequestSigned(pki_x509req *req, pki_x509 *cert)
{
	if (!req || !cert)
		return;
	pki_x509 *issuer = cert->getSigner();

	Transaction;
	if (!TransBegin())
		return;

	XSqlQuery q;
	req->setDone();
	SQL_PREPARE(q, "UPDATE requests SET signed=? WHERE item=?");
	q.bindValue(0, 1);
	q.bindValue(1, req->getSqlItemId());
	AffectedItems(req->getSqlItemId());
	q.exec();

	a1time a;
	req->selfComment(tr("Signed on %1 by '%2'").arg(a.toPretty())
		.arg(issuer ? issuer->getIntName() : tr("Unknown")));
	SQL_PREPARE(q, "UPDATE items SET comment=? WHERE id=?");
	q.bindValue(0, req->getComment());
	q.bindValue(1, req->getSqlItemId());
	q.exec();

	TransCommit();
}

static AuditParams issuanceParams(const IssuanceSpec &spec)
{
	AuditParams p;
	p.set("name", spec.name);
	p.set("subject", spec.subject.oneLine());
	if (spec.signer) {
		p.set("issuer", spec.signer->getSubject().oneLine());
		p.set("ca_id", spec.signer->getSqlItemId().toLongLong());
	}
	p.set("not_before", (QDateTime)spec.notBefore);
	/* the end date of the certificate; a cap is never silent */
	bool capped;
	p.set("not_after", (QDateTime)spec.effectiveNotAfter(&capped));
	p.set("validity_capped", capped);
	if (capped)
		p.set("requested_not_after", (QDateTime)spec.notAfter);
	p.set("hash_algo", spec.hashAlgo.name());
	if (!spec.templateName.isEmpty())
		p.set("template", spec.templateName);
	return p;
}

pki_x509 *db_x509::issue(const IssuanceSpec &spec, AuditParams &params,
			const ServiceContext &ctx)
{
	pki_x509 *cert = nullptr, *stored = nullptr, *signcert;
	pki_key *signkey, *clientkey = spec.key, *tempkey = nullptr;
	X509V3_CTX ext_ctx{};

    try {
	Transaction;
	TransThrow();

	// Step 1 - Subject and key
	if (spec.request) {
		clientkey = spec.request->getRefKey();
		if (clientkey == nullptr) {
			clientkey = spec.request->getPubKey();
			tempkey = clientkey;
		}
	} else if (!clientkey) {
		throw serviceError("missing_key",
			tr("Neither a key nor a certificate signing request was given"));
	}
	if (clientkey == nullptr)
		throw serviceError("invalid_public_key", tr("Invalid public key"));

	// initially create cert
	cert = new pki_x509();
	cert->setIntName(spec.name.isEmpty() && spec.request ?
			spec.request->getIntName() : spec.name);
	cert->setSubject(spec.subject);
	cert->setPubKey(clientkey);

	// Step 2 - select Signing
	if (spec.signer) {
		signcert = spec.signer;
		signkey = signcert->getRefKey();
	} else {
		signcert = cert;
		signkey = clientkey;
	}
	// if we can not sign
	if (! signkey || signkey->isPubKey())
		throw serviceError("no_private_signing_key",
			tr("The key you selected for signing is not a private one."));

	X509V3_set_ctx_nodb(&ext_ctx);
	X509V3_set_ctx(&ext_ctx, signcert->getCert(), cert->getCert(),
			NULL, NULL, 0);

	// set the issuers name
	cert->setIssuer(signcert->getSubject());
	cert->setSerial(getUniqueSerial(spec.signer));

	// Step 3 - Choose the Date, capped at the issuer chain
	bool capped;
	a1time notAfter = spec.effectiveNotAfter(&capped);
	if (capped && notAfter <= spec.notBefore)
		throw serviceError("invalid_validity",
			tr("The issuer chain ends on %1, not after the start of the certificate on %2")
			.arg(notAfter.toPrettyGMT()).arg(spec.notBefore.toPrettyGMT()));
	cert->setNotBefore(spec.notBefore);
	cert->setNotAfter(notAfter);

	// STEP 4 handle extensions

	// apply all extensions to the subject cert in the context
	spec.extensions.build(&ext_ctx, spec.selfSigned(), false);

	// apply extensions from CSR if requested
	if (spec.copyRequestExtensions && spec.request) {
		extList el = spec.request->getV3ext();
		int m = el.count();
		for (int i=0; i<m; i++)
			cert->addV3ext(el[i], true);
	}

	// and finally sign the request
	cert->sign(signkey, spec.hashAlgo);

	// set the comment field
	cert->setComment(spec.comment);
	cert->pkiSource = spec.source;

	params.set("serial", cert->getSerial().toHex());
	params.set("subject", cert->getSubject().oneLine());
	params.set("name", cert->getIntName());
	params.set("fingerprint", cert->fingerprint(EVP_sha256()));

	if (getByReference(cert))
		throw serviceError("duplicate_certificate",
			tr("The certificate already exists in the database"));
	pki_x509 *inserted = dynamic_cast<pki_x509*>(insert(cert));
	/* insert() keeps the certificate in the store or deletes it */
	cert = nullptr;
	if (!inserted)
		throw serviceError("database_error",
			tr("The certificate could not be stored"));
	stored = inserted;
	delete tempkey;
	tempkey = nullptr;
	markRequestSigned(spec.request, stored);
	AuditLog::append(ctx, "certificate.issue", "certificate",
			stored->getSqlItemId().toString(), params);
	if (!TransCommit())
		throw serviceError("database_error",
			tr("Failed to commit the database transaction"));
    }
    catch (...) {
	delete cert;
	delete tempkey;
	throw;
    }
    return stored;
}

pki_x509 *db_x509::newCert(const ServiceContext &ctx,
			const IssuanceSpec &spec)
{
	AuditParams params = issuanceParams(spec);
	try {
		return issue(spec, params, ctx);
	} catch (serviceError &err) {
		/* after the rollback, so the entry is kept (lib/audit.h) */
		AuditLog::append(ctx, "certificate.issue", "certificate",
				QString(), params, "failure", err.code);
		throw;
	} catch (...) {
		/* errorEx (database, OpenSSL, key decryption) and anything else */
		AuditLog::append(ctx, "certificate.issue", "certificate",
				QString(), params, "failure", "internal_error");
		throw;
	}
}

int db_x509::exportFlags(const QModelIndex &idx) const
{
	QStringList filt;
	int disable_flags = 0;

	pki_x509 *crt = fromIndex<pki_x509>(idx);
	if (!crt)
		return 0;

	pki_key *privkey = crt->getRefKey();

	if (!crt->getSigner() || crt->getSigner() == crt)
		disable_flags |= F_CHAIN;

	if (!privkey || !privkey->isPrivKey() || privkey->isToken())
		disable_flags |= F_PRIVATE;

	if (!crt->isCA())
		disable_flags |= F_CA;

	pki_key *key = crt->getPubKey();
	if (key && key->getKeyType() != EVP_PKEY_RSA && key->getJWKcrv().isEmpty())
		disable_flags |= F_JWK;
	delete key;

	return disable_flags;
}

void db_x509::writeTaggedPEM(const BioByteArray &b, const QString &tag, XFile &file)
{
	if (b.size() > 0) {
		file.write(QString("<%1>\n").arg(tag).toLatin1());
		file.write(b.byteArray());
		file.write(QString("</%1>\n").arg(tag).toLatin1());
	}
}

void db_x509::exportItems(const QModelIndexList &list,
			const pki_export *xport, XFile &file) const
{
	if (list.empty())
		return;

	pki_x509 *oldcrt = nullptr, *crt = fromIndex<pki_x509>(list[0]);

	QList<pki_x509*> certs;
	foreach(QModelIndex idx, list) {
		pki_x509 *x = fromIndex<pki_x509>(idx);
		if (x)
			certs << x;
	}

	if (xport->match_all(F_PEM)) {
		if (xport->match_all(F_CHAIN)) {
			for (; crt && crt != oldcrt; oldcrt = crt, crt = crt->getSigner())
				crt->writeCert(file, true);
		} else if (xport->match_all(F_UNREVOKED)) {
			foreach(pki_x509 *pki, Store.getAll<pki_x509>())
				if (!pki->isRevoked())
					pki->writeCert(file, true);
		} else if (xport->match_all(F_UNUSABLE)) {
			foreach(pki_x509 *pki, Store.getAll<pki_x509>())
				if (pki->unusable())
					pki->writeCert(file, true);
		} else if (xport->match_all(F_ALL)) {
			foreach(pki_x509 *pki, Store.getAll<pki_x509>())
				pki->writeCert(file, true);
		} else {
			if (xport->match_all(F_PRIVATE)) {
				pki_evp *pkey = (pki_evp *)crt->getRefKey();
				if (!pkey || pkey->isPubKey())
					throw errorEx(tr("There was no key found for the Certificate: '%1'").
							arg(crt->getIntName()));
				if (pkey->isToken())
					throw errorEx(tr("Not possible for a token key: '%1'").
							arg(crt->getIntName()));
				if (xport->match_all(F_PKCS8)) {
					pkey->writePKCS8(file, EVP_aes_256_cbc(),
						PwDialogCore::pwCallback, true);
				} else {
					pkey->writeKey(file, NULL, NULL, true);
				}
			}
			foreach(crt, certs)
				crt->writeCert(file, true);
		}
	} else if (xport->match_all(F_OVPN)) {
		BioByteArray key, cert, extra, ca;
		pki_evp *pkey = (pki_evp *)crt->getRefKey();
		if (pkey)
			pkey->pem(key, pki_export::by_id(20)); // PEM unencrypted
		for (; crt && crt != oldcrt; oldcrt = crt, crt = crt->getSigner())
		{
			if (crt == crt->getSigner())
				crt->pem(ca);
			else if (cert.size() == 0)
				crt->pem(cert);
			else
				crt->pem(extra);
		}
		writeTaggedPEM(ca, "ca", file);
		writeTaggedPEM(extra, "extra-certs", file);
		writeTaggedPEM(cert, "cert", file);
		writeTaggedPEM(key, "key", file);
		writeTaggedPEM(crt->getTaKey().toLatin1(), "tls-auth", file);
	} else if (xport->match_all(F_PKCS7)) {
		writePKCS7(crt, file, xport->flags, list);
	} else if (xport->match_all(F_INDEX)) {
		writeIndex(file, certs);
	} else if (xport->match_all(F_CAL)) {
		QStringList vcal;
		foreach(crt, certs) {
			vcal += xport->match_all(F_CA) ?
				crt->icsVEVENT_ca() : crt->icsVEVENT();
		}
		writeVcalendar(file, vcal);
	} else if (xport->match_all(F_TAKEY)) {
		file.write(crt->getTaKey().toLatin1());
	} else {
		qDebug() << "exportItems: db_base";
		db_base::exportItems(list, xport, file);
	}
}

void db_x509::exportItem(const QModelIndex &index,
			const pki_export *xport, XFile &file) const
{
	pki_x509 *crt = fromIndex<pki_x509>(index);

	if (xport->match_all(F_DER)) {
		crt->writeCert(file, false);
	} else if (xport->match_all(F_PKCS12)) {
		writePKCS12(crt, file, xport->match_all(F_CHAIN));
	} else if (xport->match_all(F_CONFIG)) {
		crt->opensslConf(file);
	} else {
		db_base::exportItem(index, xport, file);
	}
}

void db_x509::writeIndex(XFile &file, QList<pki_x509*> items) const
{
	QString index;
	foreach(pki_x509 *cert, items) {
		if (cert)
			index += cert->getIndexEntry();
	}
	file.write(index.toUtf8());
}

void db_x509::writePKCS12(pki_x509 *cert, XFile &file, bool chain) const
{
	QStringList filt;
	pki_pkcs12 *p12 = NULL;
	try {
		pki_evp *privkey = (pki_evp *)cert->getRefKey();
		if (!privkey || privkey->isPubKey()) {
			XCA_WARN(tr("There was no key found for the Certificate: '%1'").arg(cert->getIntName()));
			return;
		}
		if (privkey->isToken()) {
			XCA_WARN(tr("Not possible for the token-key Certificate '%1'").arg(cert->getIntName()));
			return;
		}
		p12 = new pki_pkcs12(cert->getIntName(), cert, privkey);
		pki_x509 *signer = cert->getSigner();
		while ((signer != NULL ) && (signer != cert) && chain) {
			p12->append_item(signer);
			cert = signer;
			signer = signer->getSigner();
		}
		encAlgo encAlgo((QString) Settings["pkcs12_enc_algo"]);
		p12->writePKCS12(file, encAlgo);
	}
	catch (errorEx &err) {
		XCA_ERROR(err);
	}
	delete p12;
}

void db_x509::writePKCS7(pki_x509 *cert, XFile &file, int flags,
			const QModelIndexList &list) const
{
	pki_pkcs7 *p7 = new pki_pkcs7(QString());

	try {
		if (flags & F_CHAIN) {
			while (cert) {
				p7->append_item(cert);
				if (cert->getSigner() == cert)
					break;
				cert = cert->getSigner();
			}
		} else if (flags & (F_UNREVOKED | F_ALL)) {
			foreach(pki_x509 *cer, Store.getAll<pki_x509>()) {
				if ((flags & F_ALL) || !cer->isRevoked())
					p7->append_item(cer);
			}
		} else if (flags & F_UNUSABLE) {
			foreach(pki_x509 *cer, Store.getAll<pki_x509>()) {
				if (cer->unusable())
					p7->append_item(cer);
			}
		} else if (flags) {
			foreach(QModelIndex idx, list) {
				cert = fromIndex<pki_x509>(idx);
				if (cert)
					p7->append_item(cert);
			}
		} else {
			p7->append_item(cert);
		}
		p7->writeP7(file, false);
	}
	catch (errorEx &err) {
		XCA_ERROR(err);
	}
	delete p7;
}

/* Revocation (BTD-33) */

/* The revocations table keeps whole seconds; the audit entry must carry
 * the same value, or AuditLog::verify() reports a mismatch */
static a1time wholeSeconds(const a1time &t)
{
	if (!t.isValid() || t.isUndefined())
		return t;
	return a1time(QDateTime::fromSecsSinceEpoch(t.toSecsSinceEpoch(),
				QTimeZone::utc()));
}

static void execOrThrow(XSqlQuery &q)
{
	q.exec();
	if (q.lastError().isValid())
		throw serviceError("database_error",
			QObject::tr("Database error: %1")
				.arg(q.lastError().text()));
}

namespace {
/* A row of the revocations table with its serial as stored: rows of
 * older databases need not be written like a1int::toHex() */
class revocationRow
{
  public:
	QString serial{};
	x509rev rev{};
};
}

static QList<revocationRow> revocationRows(const QVariant &caId)
{
	QList<revocationRow> rows;
	XSqlQuery q;

	SQL_PREPARE(q, "SELECT serial, date, invaldate, crlNo, reasonBit "
			"FROM revocations WHERE caId=?");
	q.bindValue(0, caId);
	execOrThrow(q);
	while (q.next()) {
		revocationRow row;
		row.serial = q.value(0).toString();
		row.rev = x509rev(q.record());
		rows << row;
	}
	return rows;
}

static int indexOfSerial(const QList<revocationRow> &rows, const a1int &serial)
{
	for (int i = 0; i < rows.size(); i++) {
		if (rows[i].rev.getSerial() == serial)
			return i;
	}
	return -1;
}

static void insertRevocation(const QVariant &caId, x509rev rev)
{
	XSqlQuery q;

	SQL_PREPARE(q, "INSERT INTO revocations "
			"(caId, serial, date, invaldate, crlNo, reasonBit) "
			"VALUES (?,?,?,?,?,?)");
	q.bindValue(0, caId);
	rev.executeQuery(q);
	if (q.lastError().isValid())
		throw serviceError("database_error",
			QObject::tr("Database error: %1")
				.arg(q.lastError().text()));
}

/* Reason and dates only: the CRL number of the first appearance stays */
static void updateRevocation(const QVariant &caId, const QString &serial,
				const x509rev &rev)
{
	XSqlQuery q;

	SQL_PREPARE(q, "UPDATE revocations SET date=?, invaldate=?, "
			"reasonBit=? WHERE caId=? AND serial=?");
	q.bindValue(0, rev.getDate().toPlain());
	q.bindValue(1, rev.getInvalDate().toPlain());
	q.bindValue(2, rev.getReasonBit());
	q.bindValue(3, caId);
	q.bindValue(4, serial);
	execOrThrow(q);
}

static void deleteRevocation(const QVariant &caId, const QString &serial)
{
	XSqlQuery q;

	SQL_PREPARE(q, "DELETE FROM revocations WHERE caId=? AND serial=?");
	q.bindValue(0, caId);
	q.bindValue(1, serial);
	execOrThrow(q);
}

/* The state AuditLog::verify() recomputes the row from */
static AuditParams revocationParams(const pki_x509 *ca, const QString &serial,
				const x509rev &rev)
{
	AuditParams p = AuditParams::revocation(
		ca ? ca->getSqlItemId().toLongLong() : 0, serial,
		rev.getReasonBit(), rev.getDate(), rev.getInvalDate());
	if (rev.getReasonBit() >= 0)
		p.set("reason", rev.getReason());
	if (rev.getCrlNo())
		p.set("crl_number", (qint64)rev.getCrlNo());
	return p;
}

static QString itemId(const pki_base *pki)
{
	return pki ? pki->getSqlItemId().toString() : QString();
}

/* The revocation state of the certificates of ca in memory */
static void refreshRevocations(pki_x509 *ca)
{
	x509revList list = ca->getRevList();

	foreach(pki_base *p, ca->getChildItems()) {
		pki_x509 *cert = dynamic_cast<pki_x509 *>(p);
		if (!cert)
			continue;
		x509rev rev;
		rev.setSerial(cert->getSerial());
		int i = list.indexOf(rev);
		cert->setRevoked(i == -1 ? x509rev() : list[i]);
	}
}

void db_x509::revoke(const ServiceContext &ctx, pki_x509 *cert,
			const x509rev &r)
{
	pki_x509 *ca = cert ? cert->getSigner() : nullptr;
	x509rev rev(r);

	if (cert)
		rev.setSerial(cert->getSerial());
	if (rev.getDate().isUndefined())
		rev.setDate(a1time());
	rev.setDate(wholeSeconds(rev.getDate()));
	rev.setInvalDate(wholeSeconds(rev.getInvalDate()));
	rev.setCrlNo(0);

	AuditParams params = revocationParams(ca, rev.getSerial().toHex(), rev);
	if (cert)
		params.set("name", cert->getIntName());

	auditedTransaction(ctx, AuditLog::actionRevoke, "certificate",
				itemId(cert), params, [&]() {
		if (!cert)
			throw serviceError("missing_certificate",
				tr("No certificate given"));
		if (!ca)
			throw serviceError("unknown_issuer",
				tr("The issuer of '%1' is not in the database")
					.arg(cert->getIntName()));
		if (ca == cert)
			throw serviceError("self_signed",
				tr("The self-signed certificate '%1' has no issuer to revoke it")
					.arg(cert->getIntName()));
		if (rev.getReasonBit() < 0)
			throw serviceError("invalid_reason",
				tr("Unknown revocation reason"));
		if (cert->isRevoked() || indexOfSerial(revocationRows(
				ca->getSqlItemId()), rev.getSerial()) != -1)
			throw serviceError("already_revoked",
				tr("The certificate '%1' is already revoked")
					.arg(cert->getIntName()));
		insertRevocation(ca->getSqlItemId(), rev);
		AuditLog::append(ctx, AuditLog::actionRevoke, "certificate",
				itemId(cert), params);
	});
	refreshRevocations(ca);
}

void db_x509::unrevoke(const ServiceContext &ctx, pki_x509 *cert)
{
	pki_x509 *ca = cert ? cert->getSigner() : nullptr;

	AuditParams params = AuditParams::unrevocation(
		ca ? ca->getSqlItemId().toLongLong() : 0,
		cert ? cert->getSerial().toHex() : QString());
	if (cert)
		params.set("name", cert->getIntName());

	auditedTransaction(ctx, AuditLog::actionUnrevoke, "certificate",
				itemId(cert), params, [&]() {
		if (!cert)
			throw serviceError("missing_certificate",
				tr("No certificate given"));
		if (!ca)
			throw serviceError("unknown_issuer",
				tr("The issuer of '%1' is not in the database")
					.arg(cert->getIntName()));
		QList<revocationRow> rows = revocationRows(ca->getSqlItemId());
		int i = indexOfSerial(rows, cert->getSerial());
		if (i == -1)
			throw serviceError("not_revoked",
				tr("The certificate '%1' is not revoked")
					.arg(cert->getIntName()));
		deleteRevocation(ca->getSqlItemId(), rows[i].serial);
		AuditParams p = AuditParams::unrevocation(
			ca->getSqlItemId().toLongLong(), rows[i].serial);
		p.set("name", cert->getIntName());
		AuditLog::append(ctx, AuditLog::actionUnrevoke, "certificate",
				itemId(cert), p);
	});
	refreshRevocations(ca);
}

void db_x509::setRevocations(const ServiceContext &ctx, pki_x509 *ca,
			const x509revList &list)
{
	AuditParams params;

	params.set("count", (qint64)list.size());
	if (ca) {
		params.set("ca_id", ca->getSqlItemId().toLongLong());
		params.set("name", ca->getIntName());
	}

	auditedTransaction(ctx, "ca.set_revocations", "certificate",
				itemId(ca), params, [&]() {
		if (!ca || !ca->isCA())
			throw serviceError("not_a_ca",
				tr("Revocations need a CA certificate"));
		QVariant caId = ca->getSqlItemId();
		QList<x509rev> wanted;
		for (x509rev rev : list) {
			if (rev.getSerial() == a1int(0L))
				throw serviceError("invalid_serial",
					tr("Invalid serial number '%1'")
						.arg(rev.getSerial().toHex()));
			if (rev.getReasonBit() < 0)
				throw serviceError("invalid_reason",
					tr("Unknown revocation reason"));
			if (wanted.contains(rev))
				throw serviceError("duplicate_serial",
					tr("The serial number %1 is listed twice")
						.arg(rev.getSerial().toHex()));
			if (rev.getDate().isUndefined())
				rev.setDate(a1time());
			rev.setDate(wholeSeconds(rev.getDate()));
			rev.setInvalDate(wholeSeconds(rev.getInvalDate()));
			rev.setCrlNo(0);
			wanted << rev;
		}
		for (const revocationRow &row : revocationRows(caId)) {
			pki_x509 *cert = ca->getBySerial(row.rev.getSerial());
			int i = wanted.indexOf(row.rev);
			if (i == -1) {
				deleteRevocation(caId, row.serial);
				AuditLog::append(ctx, AuditLog::actionUnrevoke,
					"certificate", itemId(cert),
					AuditParams::unrevocation(
						caId.toLongLong(), row.serial));
				continue;
			}
			x509rev rev = wanted.takeAt(i);
			/* a CRL already published this revocation date */
			if (row.rev.getCrlNo())
				rev.setDate(row.rev.getDate());
			rev.setCrlNo(row.rev.getCrlNo());
			if (rev.identical(row.rev))
				continue;
			updateRevocation(caId, row.serial, rev);
			AuditLog::append(ctx, AuditLog::actionRevoke,
				"certificate", itemId(cert),
				revocationParams(ca, row.serial, rev));
		}
		for (const x509rev &rev : wanted) {
			insertRevocation(caId, rev);
			AuditLog::append(ctx, AuditLog::actionRevoke,
				"certificate",
				itemId(ca->getBySerial(rev.getSerial())),
				revocationParams(ca, rev.getSerial().toHex(), rev));
		}
	});
	refreshRevocations(ca);
}

pki_x509 *db_x509::certBySerial(pki_x509 *issuer, const QString &serial) const
{
	static const QRegularExpression hex("^[0-9A-Fa-f]+$");
	static const QRegularExpression dec("^[0-9]+$");
	QString s = serial.trimmed();
	bool hexOnly = s.contains(':');
	QList<pki_x509 *> found;

	s.remove(':');
	if (s.startsWith("0x", Qt::CaseInsensitive)) {
		s = s.mid(2);
		hexOnly = true;
	}
	if (!issuer)
		throw serviceError("unknown_issuer", tr("No issuer given"));
	if (!hex.match(s).hasMatch())
		throw serviceError("invalid_serial",
			tr("Invalid serial number '%1'").arg(serial));
	if (!dec.match(s).hasMatch())
		hexOnly = true;

	pki_x509 *cert = issuer->getBySerial(a1int().setHex(s));
	if (cert)
		found << cert;
	if (!hexOnly) {
		cert = issuer->getBySerial(a1int().setDec(s));
		if (cert && !found.contains(cert))
			found << cert;
	}
	if (found.isEmpty())
		throw serviceError("unknown_serial",
			tr("'%1' has issued no certificate with serial number %2")
				.arg(issuer->getIntName(), serial));
	if (found.size() > 1)
		throw serviceError("ambiguous_serial",
			tr("The serial number %1 names the certificates '%2' (hex) and '%3' (decimal)")
				.arg(serial, found[0]->getIntName(),
					found[1]->getIntName()));
	return found[0];
}

void db_x509::toCertificate(QModelIndex index)
{
	pki_x509 *cert = fromIndex<pki_x509>(index);
	if (!cert)
		return;
	if (!cert->getRefKey() && cert->getSigner() != cert)
		extractPubkey(index);
	cert->pkiSource = transformed;
	newCert(cert);
}

void db_x509::toRequest(QModelIndex idx)
{
	db_x509req *reqs = Database.model<db_x509req>();
	pki_x509 *cert = fromIndex<pki_x509>(idx);
	if (!cert)
		return;

	RequestSpec spec;
	spec.name = cert->getIntName();
	spec.subject = cert->getSubject();
	spec.key = cert->getRefKey();
	spec.hashAlgo = cert->getDigest();
	spec.copiedExtensions = cert->getV3ext();
	spec.source = transformed;
	try {
		createSuccess(reqs->newRequest(
			ServiceContext::localUser(ServiceContext::gui), spec));
	}
	catch (errorEx &err) {
		XCA_ERROR(err);
	}
}

void db_x509::toToken(QModelIndex idx, bool alwaysSelect)
{
	pki_x509 *cert = fromIndex<pki_x509>(idx);
	if (!cert)
		return;
	try {
		cert->store_token(alwaysSelect);
	} catch (errorEx &err) {
		XCA_ERROR(err);
        }
}

void db_x509::updateCaProperties(pki_x509 *cert)
{
	XSqlQuery q;
	Transaction;
	TransThrow();

	SQL_PREPARE(q, "UPDATE authority SET crlDays=?, "
			"template=? WHERE item=?");

	q.bindValue(0, cert->getCrlDays());
	q.bindValue(1, cert->getTemplateSqlId());
	q.bindValue(2, cert->getSqlItemId());

	AffectedItems(cert->getSqlItemId());
	q.exec();
	TransDone(q.lastError());
	XCA_SQLERROR(q.lastError());
}
