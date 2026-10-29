/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "db_x509req.h"
#include "db_key.h"
#include "pki_x509req.h"
#include "audit.h"
#include "exception.h"
#include "func.h"
#include "request.h"
#include "XcaWarningCore.h"

db_x509req::db_x509req() : db_x509super("requests")
{
	sqlHashTable = "requests";
	pkitype << x509_req;
	pkitype_depends << x509;
	updateHeaders();
	loadContainer();
}

dbheaderList db_x509req::getHeaders()
{
	dbheaderList h = db_x509super::getHeaders();
	h <<	new dbheader(HD_req_signed, true, tr("Signed"),
			tr("whether the request is already signed or not")) <<
		new dbheader(HD_req_unstr_name, false, tr("Unstructured name"),
			QString(OBJ_nid2ln(NID_pkcs9_unstructuredName))) <<
		new dbheader(HD_req_chall_pass, false, tr("Challenge password"),
			 QString(OBJ_nid2ln(NID_pkcs9_challengePassword))) <<
		new num_dbheader(HD_req_certs, false, tr("Certificate count"),
			 tr("Number of certificates in the database with the same public key"));

	return h;
}

pki_base *db_x509req::newPKI(enum pki_type type)
{
	(void)type;
	return new pki_x509req();
}

pki_base *db_x509req::insert(pki_base *item)
{
	pki_x509req *oldreq, *req;
	req = (pki_x509req *)item;
	oldreq = (pki_x509req *)getByReference(req);
	if (oldreq) {
		XCA_INFO(tr("The certificate signing request already exists in the database as\n'%1'\nand thus was not stored").arg(oldreq->getIntName()));
		delete req;
		return NULL;
	}
	return insertPKI(req);
}

static AuditParams requestParams(const RequestSpec &spec)
{
	AuditParams p;
	p.set("name", spec.name);
	p.set("subject", spec.subject.oneLine());
	p.set("hash_algo", spec.hashAlgo.name());
	if (spec.key)
		db_key::keyParams(p, spec.key);
	if (!spec.templateName.isEmpty())
		p.set("template", spec.templateName);
	return p;
}

pki_x509req *db_x509req::create(const RequestSpec &spec, AuditParams &params,
			const ServiceContext &ctx)
{
	pki_x509req *req = nullptr, *stored = nullptr;

    try {
	Transaction;
	TransThrow();

	if (!spec.key)
		throw serviceError("missing_key",
			tr("No key was given to sign the request"));
	if (spec.key->isPubKey())
		throw serviceError("no_private_key",
			tr("The key you selected for signing is not a private one."));

	req = new pki_x509req();
	req->pkiSource = spec.source;
	req->setIntName(spec.name);
	req->addAttribute(NID_pkcs9_unstructuredName, spec.unstructuredName);
	req->addAttribute(NID_pkcs9_challengePassword,
				spec.challengePassword);
	req->createReq(spec.key, spec.subject, spec.hashAlgo,
				spec.buildExtensions());
	req->setComment(spec.comment);

	params.set("subject", req->getSubject().oneLine());
	params.set("fingerprint", fingerprint(req->i2d(), EVP_sha256()));

	pki_x509req *oldreq = dynamic_cast<pki_x509req*>(getByReference(req));
	if (oldreq)
		throw serviceError("duplicate_request",
			tr("The certificate signing request already exists in the database as\n'%1'\nand thus was not stored").arg(oldreq->getIntName()));
	stored = dynamic_cast<pki_x509req*>(insert(req));
	/* insert() keeps the request in the store or deletes it */
	req = nullptr;
	if (!stored)
		throw serviceError("database_error",
			tr("The certificate signing request could not be stored"));
	AuditLog::append(ctx, "request.create", "request",
			stored->getSqlItemId().toString(), params);
	if (!TransCommit())
		throw serviceError("database_error",
			tr("Failed to commit the database transaction"));
    }
    catch (...) {
	delete req;
	/* rolled back and unstored: the object is ours again (BTD-130) */
	if (stored && !isStored(stored))
		delete stored;
	throw;
    }
    return stored;
}

pki_x509req *db_x509req::newRequest(const ServiceContext &ctx,
			const RequestSpec &spec)
{
	AuditParams params = requestParams(spec);
	try {
		return create(spec, params, ctx);
	} catch (serviceError &err) {
		/* after the rollback, so the entry is kept (lib/audit.h) */
		AuditLog::append(ctx, "request.create", "request",
				QString(), params, "failure", err.code);
		throw;
	} catch (...) {
		/* errorEx (database, OpenSSL, key decryption) and anything else */
		AuditLog::append(ctx, "request.create", "request",
				QString(), params, "failure", "internal_error");
		throw;
	}
}

void db_x509req::writeItem(pki_base *pki, const pki_export *xport,
		QIODevice &file, const Passwd &) const
{
	pki_x509req *req = dynamic_cast<pki_x509req *>(pki);
	if (!req)
		return;

	if (xport->match_all(F_CONFIG)) {
		req->opensslConf(file);
	} else {
		req->writeReq(file, xport->match_all(F_PEM));
	}
}

void db_x509req::setSigned(QModelIndex index, bool signe)
{
	pki_x509req *req = fromIndex<pki_x509req>(index);
	if (!req)
		return;
	req->markSigned(signe);
	emit columnsContentChanged();
}

void db_x509req::resetX509count()
{
	foreach(pki_x509req *r, getAllRequests())
		r->resetX509count();
}

QList<pki_x509req *> db_x509req::getAllRequests()
{
	return Store.sqlSELECTpki<pki_x509req>("SELECT item FROM requests");
}
