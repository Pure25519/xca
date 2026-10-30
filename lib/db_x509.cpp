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
#include "issuance_checks.h"
#include "request.h"

#include "XcaWarningCore.h"
#include "PwDialogCore.h"

#include <QCoreApplication>
#include <algorithm>
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

void db_x509::remFromCont(pki_base *pki)
{
	if (!index(pki).isValid())
		return;
	db_crl *crls = Database.model<db_crl>();
	db_x509super::remFromCont(pki);
	pki_x509 *child;

	/* Memory only: the database got the new issuers of the childs with
	 * the delete (pki_x509::deleteSqlData()), or never had pki because
	 * its insert was rolled back (BTD-130) */
	while (pki->childCount()) {
		child = dynamic_cast<pki_x509*>(pki->takeFirst());
		child->delSigner(dynamic_cast<pki_x509*>(pki));
		insertChild(child, child->findIssuer());
	}
	crls->removeSigner(pki);
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
	/* A rollback gives a child back its signer, place in the tree and
	 * revocation (BTD-130) */
	auto keep = [this](pki_x509 *child) {
		pki_x509 *signer = child->getSigner();
		pki_base *parent = child->getParent();
		x509rev rev = child->getRevocation();
		DbTransaction::onRollback([=]() {
			child->setSigner(signer);
			child->setRevoked(rev);
			if (child->getParent() != parent)
				insertChild(child, parent);
		});
	};

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
			keep(child);
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
		if (child->verify_only(cert)) {
			keep(child);
			childs << child;
		}
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
		pki_x509 *old = crl->getIssuer();
		crl->verify(cert);
		if (cert != crl->getIssuer())
			continue;
		DbTransaction::onRollback([crl, old]() {
			crl->setIssuer(old);
		});
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
	bool done = req->getDone();
	QString comment = req->getComment();
	DbTransaction::onRollback([req, done, comment]() {
		req->setDone(done);
		req->setComment(comment);
	});
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
		p.set("requested_not_after",
			(QDateTime)spec.requestedNotAfter());
	p.set("hash_algo", spec.hashAlgo.name());
	if (!spec.templateName.isEmpty())
		p.set("template", spec.templateName);
	if (!spec.profile.isEmpty())
		p.set("profile", spec.profile);
	return p;
}

/* The subject as given, byte for byte; with a profile that adds a
 * missing O, that O after the CSR's own RDNs (BTD-65) */
static x509name subjectOf(const IssuanceSpec &spec)
{
	x509name subject(spec.subject);
	const QString &o = spec.csrPolicy.missingO;
	if (spec.csrPolicy.profile && !o.isEmpty() &&
	    X509_NAME_get_index_by_NID(subject.get0(),
				NID_organizationName, -1) < 0)
		subject.addEntryByNid(NID_organizationName, o);
	return subject;
}

/* Under a profile the SAN is the CSR's, in its order and encoding, with
 * the profile's criticality; the registered ApplicationUri is appended
 * when the CSR has none. A dNSName is never made from the CN.
 * IssuanceChecks::request() has checked the SAN against the profile and
 * refused a CSR with two extension instances, so ext is the only one. */
static void requestSan(const IssuanceSpec &spec, pki_x509 *cert)
{
	if (!spec.extensions.subjectAltName.isEmpty())
		throw serviceError("san_conflict",
			QCoreApplication::translate("db_x509",
			"A profile takes the subject alternative name from the request, the spec gives one as well"));
	X509_REQ *req = spec.request->getReq();
	STACK_OF(X509_EXTENSION) *exts = X509_REQ_get_extensions(req);
	X509_EXTENSION *ext = nullptr;
	for (int i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
		X509_EXTENSION *e = sk_X509_EXTENSION_value(exts, i);
		if (OBJ_obj2nid(X509_EXTENSION_get_object(e)) ==
					NID_subject_alt_name)
			ext = e;
	}
	const QString &uri = spec.csrPolicy.registeredUri;
	GENERAL_NAMES *names = ext ? (GENERAL_NAMES *)X509V3_EXT_d2i(ext) :
				GENERAL_NAMES_new();
	bool hasUri = false;
	for (int i = 0; i < sk_GENERAL_NAME_num(names); i++)
		hasUri |= sk_GENERAL_NAME_value(names, i)->type == GEN_URI;
	if (!uri.isEmpty() && !hasUri) {
		GENERAL_NAME *gn = a2i_GENERAL_NAME(nullptr, nullptr, nullptr,
				GEN_URI, uri.toUtf8().constData(), 0);
		if (gn)
			sk_GENERAL_NAME_push(names, gn);
		X509_add1_ext_i2d(cert->getCert(), NID_subject_alt_name, names,
			spec.csrPolicy.sanCritical, X509V3_ADD_DEFAULT);
	} else if (ext) {
		/* the device's own bytes, the profile's criticality */
		X509_EXTENSION *copy = X509_EXTENSION_dup(ext);
		X509_EXTENSION_set_critical(copy, spec.csrPolicy.sanCritical);
		X509_add_ext(cert->getCert(), copy, -1);
		X509_EXTENSION_free(copy);
	}
	GENERAL_NAMES_free(names);
	sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
	openssl_error();
}

/* An extension of the CSR, decoded; nullptr if it has none */
static void *requestedExt(X509_REQ *req, int nid, int *critical)
{
	STACK_OF(X509_EXTENSION) *exts = X509_REQ_get_extensions(req);
	void *value = X509V3_get_d2i(exts, nid, critical, nullptr);
	sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
	return value;
}

/* Replaces or adds the extension nid of cert, keeping its place */
static void putExt(pki_x509 *cert, int nid, void *value, int critical)
{
	X509 *x = cert->getCert();
	int at = X509_get_ext_by_NID(x, nid, -1);
	if (at >= 0)
		X509_EXTENSION_free(X509_delete_ext(x, at));
	X509_EXTENSION *ext = X509V3_EXT_i2d(nid, critical, value);
	if (ext)
		X509_add_ext(x, ext, at);
	X509_EXTENSION_free(ext);
}

/* The EKU a CSR asks for: its own, or ekuDefault when it has none
 * (*fromDefault); every purpose must be in ekuAllowed when that is set.
 * For an end entity anyExtendedKeyUsage, OCSPSigning and codeSigning of
 * the CSR need ekuAllowed to name them (mr-processor review of xca#47). */
static EXTENDED_KEY_USAGE *requestedEku(const ExtensionSpec &e,
			X509_REQ *req, int *critical, bool leaf, bool *fromDefault)
{
	EXTENDED_KEY_USAGE *eku = (EXTENDED_KEY_USAGE *)
			requestedExt(req, NID_ext_key_usage, critical);
	*fromDefault = !eku && !e.ekuDefault.isEmpty();
	if (*fromDefault) {
		eku = sk_ASN1_OBJECT_new_null();
		*critical = 0;
		for (const QString &p : e.ekuDefault) {
			ASN1_OBJECT *o = OBJ_txt2obj(CCHAR(p), 0);
			if (o)
				sk_ASN1_OBJECT_push(eku, o);
		}
	}
	static const QList<int> sensitive { NID_anyExtendedKeyUsage,
		NID_OCSP_sign, NID_code_sign };
	for (int i = 0; eku && i < sk_ASN1_OBJECT_num(eku); i++) {
		const ASN1_OBJECT *o = sk_ASN1_OBJECT_value(eku, i);
		bool allowed = e.ekuAllowed.isEmpty() && (*fromDefault ||
			!leaf || !sensitive.contains(OBJ_obj2nid(o)));
		for (const QString &a : e.ekuAllowed) {
			ASN1_OBJECT *ao = OBJ_txt2obj(CCHAR(a), 0);
			allowed |= ao && !OBJ_cmp(o, ao);
			ASN1_OBJECT_free(ao);
		}
		if (!allowed) {
			QString name = OBJ_obj2QString(o);
			EXTENDED_KEY_USAGE_free(eku);
			ign_openssl_error();
			throw serviceError("csr_eku_not_allowed",
				QCoreApplication::translate("db_x509",
				"The request asks for the extended key usage %1, which the template does not allow")
				.arg(name));
		}
	}
	ign_openssl_error();
	return eku;
}

/* Union of two values of extension nid, the CSR's entries first */
static void *unionOf(int nid, void *req, void *templ)
{
	if (nid == NID_key_usage) {
		ASN1_BIT_STRING *a = (ASN1_BIT_STRING *)req,
				*b = (ASN1_BIT_STRING *)templ;
		for (int bit = 0; bit < 9; bit++) {
			if (ASN1_BIT_STRING_get_bit(b, bit))
				ASN1_BIT_STRING_set_bit(a, bit, 1);
		}
		return a;
	}
	if (nid == NID_subject_alt_name) {
		GENERAL_NAMES *a = (GENERAL_NAMES *)req,
				*b = (GENERAL_NAMES *)templ;
		for (int i = 0; i < sk_GENERAL_NAME_num(b); i++) {
			GENERAL_NAME *gn = sk_GENERAL_NAME_value(b, i);
			bool seen = false;
			for (int j = 0; j < sk_GENERAL_NAME_num(a); j++)
				seen |= !GENERAL_NAME_cmp(gn,
						sk_GENERAL_NAME_value(a, j));
			if (!seen)
				sk_GENERAL_NAME_push(a, GENERAL_NAME_dup(gn));
		}
		return a;
	}
	EXTENDED_KEY_USAGE *a = (EXTENDED_KEY_USAGE *)req,
			*b = (EXTENDED_KEY_USAGE *)templ;
	for (int i = 0; i < sk_ASN1_OBJECT_num(b); i++) {
		const ASN1_OBJECT *o = sk_ASN1_OBJECT_value(b, i);
		bool seen = false;
		for (int j = 0; j < sk_ASN1_OBJECT_num(a); j++)
			seen |= !OBJ_cmp(o, sk_ASN1_OBJECT_value(a, j));
		if (!seen)
			sk_ASN1_OBJECT_push(a, OBJ_dup(o));
	}
	return a;
}

static void freeExtValue(int nid, void *value)
{
	if (!value)
		return;
	if (nid == NID_key_usage)
		ASN1_BIT_STRING_free((ASN1_BIT_STRING *)value);
	else if (nid == NID_subject_alt_name)
		GENERAL_NAMES_free((GENERAL_NAMES *)value);
	else
		EXTENDED_KEY_USAGE_free((EXTENDED_KEY_USAGE *)value);
}

/* SAN, key usage and EKU of the CSR against the template's, each by its
 * merge mode (BTD-54); every other extension of the CSR as XCA always
 * did: added with "copy extensions" when the template lacks it.
 * An end entity never takes keyCertSign or cRLSign from a CSR. The
 * template's criticality wins (union only adds it); legacy keeps the
 * CSR's, as XCA always did. *merge receives the decision per extension
 * for the audit: "ku=union+csr", "eku=request+default", ... */
static void mergeRequest(const IssuanceSpec &spec, pki_x509 *cert,
			QString *merge)
{
	const ExtensionSpec &e = spec.extensions;
	X509_REQ *req = spec.request->getReq();
	X509 *x = cert->getCert();
	bool leaf = e.basicCA != ExtensionSpec::bc_ca;
	static const char *modeNames[] = { "legacy", "template", "request",
					   "union" };
	const QList<QPair<int, ExtensionSpec::requestMerge> > modes {
		{ NID_subject_alt_name, e.sanMerge },
		{ NID_key_usage, e.kuMerge },
		{ NID_ext_key_usage, e.ekuMerge },
	};
	QStringList decisions;
	QList<int> handled;
	for (const auto &m : modes) {
		int nid = m.first;
		ExtensionSpec::requestMerge mode = m.second;
		bool templ = X509_get_ext_by_NID(x, nid, -1) >= 0;
		handled << nid;
		QString decision = QString("%1=%2")
			.arg(nid == NID_subject_alt_name ? "san" :
			     nid == NID_key_usage ? "ku" : "eku")
			.arg(modeNames[mode]);
		if (mode == ExtensionSpec::merge_template ||
		    (mode == ExtensionSpec::merge_legacy &&
		     (!spec.copyRequestExtensions || templ))) {
			decisions << decision;
			continue;
		}
		int crit = 0;
		bool fromDefault = false;
		void *value = nid == NID_ext_key_usage ?
			requestedEku(e, req, &crit, leaf, &fromDefault) :
			requestedExt(req, nid, &crit);
		if (!value) {
			decisions << decision;
			continue;
		}
		decision += fromDefault ? "+default" : "+csr";
		decisions << decision;
		if (nid == NID_key_usage && leaf) {
			ASN1_BIT_STRING *ku = (ASN1_BIT_STRING *)value;
			for (int bit : { 5, 6 }) {
				if (!ASN1_BIT_STRING_get_bit(ku, bit))
					continue;
				freeExtValue(nid, value);
				throw serviceError("csr_keycertsign_not_ca",
					QCoreApplication::translate("db_x509",
					"'%1' asks for %2 in an end-entity certificate (RFC 5280 4.2.1.9)")
					.arg(spec.request->getIntName(),
					     bit == 5 ? "keyCertSign" : "cRLSign"));
			}
		}
		/* the template's flag: its extension, else the spec's */
		int tcrit = 0;
		void *t = templ ? X509_get_ext_d2i(x, nid, &tcrit, nullptr) :
				  nullptr;
		bool templCrit = templ ? tcrit > 0 :
			nid == NID_key_usage ? e.keyUsageCritical :
			nid == NID_ext_key_usage ? e.extKeyUsageCritical :
						   crit > 0;
		if (mode == ExtensionSpec::merge_union && templ) {
			value = unionOf(nid, value, t);
			crit = templCrit || crit > 0;
		} else if (mode != ExtensionSpec::merge_legacy) {
			crit = templCrit;
		}
		freeExtValue(nid, t);
		putExt(cert, nid, value, crit > 0);
		freeExtValue(nid, value);
	}
	*merge = decisions.join(",");
	if (!spec.copyRequestExtensions)
		return;
	extList el = spec.request->getV3ext();
	for (int i = 0; i < el.count(); i++) {
		if (!handled.contains(el[i].nid()))
			cert->addV3ext(el[i], true);
	}
}

/* The extensions named in order first, in that order (BTD-54) */
static void orderExtensions(const QList<int> &order, pki_x509 *cert)
{
	if (order.isEmpty())
		return;
	X509 *x = cert->getCert();
	QList<QPair<int, X509_EXTENSION *> > exts;
	while (X509_get_ext_count(x) > 0) {
		X509_EXTENSION *ext = X509_delete_ext(x, 0);
		int rank = order.indexOf(OBJ_obj2nid(
				X509_EXTENSION_get_object(ext)));
		exts << qMakePair(rank < 0 ? order.size() : rank, ext);
	}
	std::stable_sort(exts.begin(), exts.end(),
		[](const QPair<int, X509_EXTENSION *> &a,
		   const QPair<int, X509_EXTENSION *> &b) {
			return a.first < b.first;
		});
	for (const auto &p : exts) {
		X509_add_ext(x, p.second, -1);
		X509_EXTENSION_free(p.second);
	}
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

	IssuanceChecks::spec(spec);

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
	cert->setSubject(subjectOf(spec));
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

	// the issuer up to the root, checked before anything is signed
	QList<const pki_x509 *> chain =
			IssuanceChecks::issuerChain(spec.signer);
	IssuanceChecks::issuers(spec, chain, signkey, params);
	IssuanceChecks::request(spec, params);

	X509V3_set_ctx_nodb(&ext_ctx);
	X509V3_set_ctx(&ext_ctx, signcert->getCert(), cert->getCert(),
			NULL, NULL, 0);

	// set the issuers name
	cert->setIssuer(signcert->getSubject());

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

	// apply all extensions to the subject cert in the context; under a
	// profile without CSR only the registration's SAN is free input, so
	// a failure is that SAN's (BTD-191)
	try {
		spec.extensions.build(&ext_ctx, spec.selfSigned(), false);
	} catch (errorEx &err) {
		if (!spec.csrPolicy.profile || spec.request)
			throw;
		throw serviceError("registration_san_invalid",
			tr("The subject alternative name of the registration of '%1' cannot be built: %2")
			.arg(spec.name, err.getString()));
	}

	// apply extensions from CSR if requested; a profile takes only
	// the SAN (BTD-65), SAN, KU and EKU follow their merge mode (BTD-54)
	QString merge;
	if (spec.csrPolicy.profile && spec.request) {
		requestSan(spec, cert);
		/* eku_default and the purposes a CSR may name (BTD-54) */
		if (spec.extensions.ekuMerge != ExtensionSpec::merge_legacy)
			mergeRequest(spec, cert, &merge);
	} else if (spec.request) {
		mergeRequest(spec, cert, &merge);
	}
	if (!merge.isEmpty())
		params.set("merge", merge);
	orderExtensions(spec.extensionOrder, cert);

	IssuanceChecks::certificate(spec, cert, chain);
	IssuanceChecks::names(spec, cert, chain);

	// the serial only once every check passed
	cert->setSerial(getUniqueSerial(spec.signer));

	// and finally sign the request
	cert->sign(signkey, spec.hashAlgo);
	/* the issuer is the CA that signed, not the latest one with its DN */
	cert->setSigner(spec.signer);

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
	/* rolled back and unstored: the object is ours again (BTD-130) */
	if (stored && !isStored(stored))
		delete stored;
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
		AuditLog::appendFailure(ctx, "certificate.issue", "certificate",
				QString(), params, err.code);
		throw;
	} catch (...) {
		/* errorEx (database, OpenSSL, key decryption) and anything else */
		AuditLog::appendFailure(ctx, "certificate.issue", "certificate",
				QString(), params, "internal_error");
		throw;
	}
}

int db_x509::exportFlags(pki_base *pki) const
{
	int disable_flags = 0;

	pki_x509 *crt = dynamic_cast<pki_x509 *>(pki);
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

const pki_export *db_x509::clipboardFormat() const
{
	return pki_export::by_id(Settings["CertFormat"]);
}

/* The certificate and its issuers up to the self-signed root */
static QList<pki_base *> certChain(pki_x509 *crt)
{
	QList<pki_base *> chain;
	for (pki_x509 *oldcrt = nullptr; crt && crt != oldcrt;
				oldcrt = crt, crt = crt->getSigner())
		chain << crt;
	return chain;
}

/* The certificates a format writes: the chain of the first item, all
 * certificates of the database, or the items */
QList<pki_base *> db_x509::exportedObjects(const QList<pki_base *> &items,
			const pki_export *xport) const
{
	QList<pki_base *> certs;

	if (xport->match_all(F_CHAIN)) {
		certs = certChain(items.isEmpty() ? nullptr :
				dynamic_cast<pki_x509 *>(items[0]));
	} else if (xport->flags & (F_UNREVOKED | F_ALL | F_UNUSABLE)) {
		foreach(pki_x509 *pki, Store.getAll<pki_x509>()) {
			if (xport->match_all(F_UNUSABLE) ? pki->unusable() :
			    xport->match_all(F_ALL) || !pki->isRevoked())
				certs << pki;
		}
	} else {
		foreach(pki_base *pki, items) {
			if (dynamic_cast<pki_x509 *>(pki))
				certs << pki;
		}
	}
	return certs;
}

/* Formats with F_PRIVATE write the key of the item; the clipboard text
 * writes it for every item */
QList<pki_key *> db_x509::exportedPrivateKeys(const QList<pki_base *> &items,
			const pki_export *xport) const
{
	QList<pki_key *> keys;

	if (!xport || !xport->match_all(F_PRIVATE))
		return keys;
	foreach(pki_base *pki, items) {
		pki_x509 *crt = dynamic_cast<pki_x509 *>(pki);
		pki_key *key = crt ? crt->getRefKey() : nullptr;
		if (key && key->isPrivKey() && !key->isToken() &&
		    !keys.contains(key))
			keys << key;
	}
	return keys;
}

void db_x509::writeTaggedPEM(const BioByteArray &b, const QString &tag, QIODevice &file)
{
	if (b.size() > 0) {
		file.write(QString("<%1>\n").arg(tag).toLatin1());
		file.write(b.byteArray());
		file.write(QString("</%1>\n").arg(tag).toLatin1());
	}
}

void db_x509::writeItems(const QList<pki_base *> &list,
			const pki_export *xport, QIODevice &file,
			const Passwd &pass) const
{
	if (list.empty())
		return;

	pki_x509 *crt = dynamic_cast<pki_x509 *>(list[0]);
	if (!crt)
		return;

	QList<pki_x509*> certs;
	foreach(pki_base *pki, list) {
		pki_x509 *x = dynamic_cast<pki_x509 *>(pki);
		if (x)
			certs << x;
	}

	if (xport->match_all(F_PEM)) {
		if (xport->flags & (F_CHAIN | F_UNREVOKED | F_UNUSABLE | F_ALL)) {
			foreach(pki_base *pki, exportedObjects(list, xport))
				static_cast<pki_x509 *>(pki)->writeCert(file, true);
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
						pass, true);
				} else {
					pkey->writeKey(file, NULL, pass, true);
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
		foreach(pki_base *pki, exportedObjects(list, xport)) {
			crt = static_cast<pki_x509 *>(pki);
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
		/* the tls-auth key of the last certificate of the chain */
		writeTaggedPEM(crt->getTaKey().toLatin1(), "tls-auth", file);
	} else if (xport->match_all(F_PKCS7)) {
		writePKCS7(exportedObjects(list, xport), file);
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
		qDebug() << "writeItems: db_base";
		db_base::writeItems(list, xport, file, pass);
	}
}

void db_x509::writeItem(pki_base *pki, const pki_export *xport,
			QIODevice &file, const Passwd &pass) const
{
	pki_x509 *crt = dynamic_cast<pki_x509 *>(pki);
	if (!crt)
		return;

	if (xport->match_all(F_DER)) {
		crt->writeCert(file, false);
	} else if (xport->match_all(F_PKCS12)) {
		writePKCS12(crt, file, xport->match_all(F_CHAIN), pass);
	} else if (xport->match_all(F_CONFIG)) {
		crt->opensslConf(file);
	} else {
		db_base::writeItem(pki, xport, file, pass);
	}
}

void db_x509::writeIndex(QIODevice &file, QList<pki_x509*> items) const
{
	QString index;
	foreach(pki_x509 *cert, items) {
		if (cert)
			index += cert->getIndexEntry();
	}
	file.write(index.toUtf8());
}

void db_x509::writePKCS12(pki_x509 *cert, QIODevice &file, bool chain,
			const Passwd &pass) const
{
	pki_evp *privkey = (pki_evp *)cert->getRefKey();
	if (!privkey || privkey->isPubKey())
		throw errorEx(tr("There was no key found for the Certificate: '%1'").arg(cert->getIntName()));
	if (privkey->isToken())
		throw errorEx(tr("Not possible for the token-key Certificate '%1'").arg(cert->getIntName()));

	pki_pkcs12 p12(cert->getIntName(), cert, privkey);
	if (chain) {
		foreach(pki_base *signer, certChain(cert).mid(1))
			p12.append_item(signer);
	}
	encAlgo encAlgo = encAlgo::forExport();
	p12.writePKCS12(file, encAlgo, pass);
}

void db_x509::writePKCS7(const QList<pki_base *> &certs, QIODevice &file) const
{
	pki_pkcs7 p7;

	foreach(pki_base *pki, certs)
		p7.append_item(pki);
	p7.writeP7(file, false);
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
			throw serviceError("issuer_not_ca",
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
