/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "db_crl.h"
#include "issuance_checks.h"
#include "db_x509.h"
#include "audit.h"
#include "exception.h"
#include "func.h"
#include "database_model.h"

#include <QSet>
#include <climits>

#include <openssl/evp.h>
#include <openssl/x509v3.h>

db_crl::db_crl() : db_x509name("crls")
{
	sqlHashTable = "crls";
	pkitype << revocation;
	pkitype_depends << x509;
	updateHeaders();
	loadContainer();
}

dbheaderList db_crl::getHeaders()
{
	dbheaderList h = db_x509name::getHeaders();
	h <<	new dbheader(HD_crl_signer, true, tr("Signer"),
			tr("Internal name of the signer")) <<
		new num_dbheader(HD_crl_revoked, true, tr("No. revoked"),
			tr("Number of revoked certificates")) <<
		new date_dbheader(HD_crl_lastUpdate,false, tr("Last update")) <<
		new date_dbheader(HD_crl_nextUpdate, true, tr("Next update")) <<
		new num_dbheader(HD_crl_crlnumber, false, tr("CRL number"));
	return h;
}

pki_base *db_crl::newPKI(enum pki_type type)
{
	(void)type;
	return new pki_crl();
}

void db_crl::revokeCerts(pki_crl *crl)
{
	db_x509 *certs = Database.model<db_x509>();
	x509revList revlist;

	if (!certs || !crl)
		return;

	pki_x509 *signer = crl->getIssuer();
	if (!signer)
		return;

	revlist = crl->getRevList();
	signer->mergeRevList(revlist);
	foreach(x509rev revok, revlist) {
		pki_x509 *crt = signer->getBySerial(revok.getSerial());
		if (!crt)
			continue;
		x509rev old = crt->getRevocation();
		crt->setRevoked(revok);
		DbTransaction::onRollback([crt, old]() {
			crt->setRevoked(old);
		});
	}
}

void db_crl::removeSigner(pki_base *signer)
{
	foreach(pki_crl *crl, Store.getAll<pki_crl>()) {
		if (crl->getIssuer() == signer) {
			crl->setIssuer(NULL);
		}
	}
}

void db_crl::inToCont(pki_base *pki)
{
	pki_crl *crl = dynamic_cast<pki_crl *>(pki);
	unsigned hash = crl->getSubject().hashNum();
	QList<pki_x509 *> items;

	items = Store.sqlSELECTpki<pki_x509>(
		"SELECT x509super.item FROM x509super "
		"JOIN certs ON certs.item = x509super.item "
		"WHERE x509super.subj_hash=? AND certs.ca=1",
			QList<QVariant>() << QVariant(hash));
	foreach(pki_x509 *x, items) {
		qDebug() << "Possible Crl issuer:" << x->getIntName();
		crl->verify(x);
	}
	db_base::inToCont(pki);
}

pki_base *db_crl::insert(pki_base *item)
{
	pki_crl *crl = dynamic_cast<pki_crl *>(item);
	pki_crl *oldcrl = dynamic_cast<pki_crl *>(getByReference(crl));
	if (oldcrl) {
		XCA_INFO(tr("The revocation list already exists in the database as:\n'%1'\nand so it was not imported").arg(oldcrl->getIntName()));
		delete(crl);
		return NULL;
	}
	Transaction;
	if (!TransBegin()) {
		/* keeps or deletes, like insertPKI() (BTD-149) */
		delete crl;
		return NULL;
	}
	crl = dynamic_cast<pki_crl *>(insertPKI(crl));
	if (!crl)
		return NULL;
	revokeCerts(crl);
	if (!TransCommit()) {
		/* rolled back and unstored (BTD-130) */
		delete crl;
		return NULL;
	}
	return crl;
}

void db_crl::writeItems(const QList<pki_base *> &items,
			const pki_export *xport, QIODevice &file,
			const Passwd &) const
{
	QStringList vcal;
	foreach(pki_base *pki, items) {
		pki_crl *crl = dynamic_cast<pki_crl *>(pki);
		if (!crl)
			continue;
		if (xport->match_all(F_CAL))
			vcal << crl->icsVEVENT();
		else
			crl->writeCrl(file, xport->match_all(F_PEM));
	}
	if (vcal.size() > 0)
		writeVcalendar(file, vcal);
}

namespace {
/* RFC 5280 3.3: the entry of an expired certificate may leave the CRL
 * once it was listed in one CRL issued after the certificate's notAfter.
 * Keeps CRLs small for devices with tight limits (S7: 4096 bytes). A
 * serial without certificate in the database always stays. */
class expiredEntries
{
	pki_x509 *ca;
	/* lastUpdate and serials of the stored CRLs of ca */
	QList<QPair<a1time, QSet<QString> > > crls{};
	bool loaded{};

  public:
	expiredEntries(pki_x509 *c) : ca(c) { }
	bool drop(const x509rev &rev);
};
}

bool expiredEntries::drop(const x509rev &rev)
{
	pki_x509 *cert = ca->getBySerial(rev.getSerial());
	if (!cert)
		return false;
	a1time notAfter = cert->getNotAfter();
	if (notAfter.isUndefined())
		return false;
	if (!loaded) {
		foreach(pki_crl *crl, Store.getAll<pki_crl>()) {
			if (crl->getIssuer() != ca)
				continue;
			QSet<QString> serials;
			foreach(x509rev r, crl->getRevList())
				serials << r.getSerial().toHex();
			crls << qMakePair(crl->getLastUpdate(), serials);
		}
		loaded = true;
	}
	QString serial = rev.getSerial().toHex();
	for (const auto &c : crls) {
		if (c.first > notAfter && c.second.contains(serial))
			return true;
	}
	return false;
}

/* The authority key identifier of a CRL always holds a key identifier
 * (OPC UA): the CA's subject key identifier, or for a CA without one the
 * SHA-1 hash of its public key (RFC 5280 4.2.1.2, method 1, as OpenSSL
 * computes "hash"), next to the CA's issuer name and serial */
static x509v3ext authorityKeyId(pki_x509 *ca, X509V3_CTX *ctx)
{
	x509v3ext e;
	e.create(NID_authority_key_identifier, "keyid,issuer", ctx);
	if (X509_get0_subject_key_id(ca->getCert()))
		return e;

	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned len = 0;
	AUTHORITY_KEYID *akid = (AUTHORITY_KEYID *)e.d2i();
	if (!akid || !X509_pubkey_digest(ca->getCert(), EVP_sha1(), md, &len)) {
		AUTHORITY_KEYID_free(akid);
		openssl_error();
		throw errorEx(QObject::tr("Failed to build the authority key identifier"));
	}
	ASN1_OCTET_STRING_free(akid->keyid);
	akid->keyid = ASN1_OCTET_STRING_new();
	ASN1_OCTET_STRING_set(akid->keyid, md, len);
	X509_EXTENSION *ext = X509V3_EXT_i2d(NID_authority_key_identifier, 0, akid);
	AUTHORITY_KEYID_free(akid);
	e.set(ext);
	X509_EXTENSION_free(ext);
	openssl_error();
	return e;
}

static void execOrThrow(XSqlQuery &q)
{
	q.exec();
	if (q.lastError().isValid())
		throw serviceError("database_error",
			QObject::tr("Database error: %1")
				.arg(q.lastError().text()));
}

/* The last CRL number of the CA as the database has it */
static a1int storedCrlNumber(pki_x509 *ca)
{
	XSqlQuery q;
	a1int num;

	SQL_PREPARE(q, "SELECT crlNo FROM authority WHERE item=?");
	q.bindValue(0, ca->getSqlItemId());
	execOrThrow(q);
	if (q.first())
		num.set(q.value(0).toUInt());
	return num;
}

/* The CA's last CRL: the database and the CA object may differ until
 * a commit, the higher one counts */
static a1int lastCrlNumber(pki_x509 *ca)
{
	a1int last = storedCrlNumber(ca);
	if (ca->getCrlNumber() > last)
		last = ca->getCrlNumber();
	return last;
}

static void storeCrlNumber(pki_x509 *ca, uint number, const a1time &expire)
{
	XSqlQuery q;

	SQL_PREPARE(q, "UPDATE authority set crlNo=?, crlExpire=? WHERE item=?");
	q.bindValue(0, number);
	q.bindValue(1, expire.toPlain());
	q.bindValue(2, ca->getSqlItemId());
	AffectedItems(ca->getSqlItemId());
	execOrThrow(q);
}

bool db_crl::raiseCrlNumber(pki_crl *crl)
{
	pki_x509 *ca = crl ? crl->getIssuer() : nullptr;
	a1int num;

	if (!ca || !ca->getSqlItemId().isValid() || !crl->getCrlNumber(&num))
		return false;
	if (!(num > lastCrlNumber(ca)))
		return false;
	/* the authority table keeps the number as unsigned 32 bit */
	bool numeric;
	qint64 number = num.toDec().toLongLong(&numeric);
	if (!numeric || number > UINT_MAX)
		return false;
	storeCrlNumber(ca, (uint)number, crl->getNextUpdate());
	return true;
}

pki_crl *db_crl::newCrl(const ServiceContext &ctx, const crljob &task,
			QString name)
{
	pki_x509 *cert = task.issuer;
	pki_crl *stored = nullptr;
	AuditParams params;

	if (cert) {
		params.set("ca_id", cert->getSqlItemId().toLongLong());
		params.set("issuer", cert->getSubject().oneLine());
	}
	bool numeric;
	qint64 number = task.crlNumber.toDec().toLongLong(&numeric);
	if (numeric)
		params.set("crl_number", number);
	params.set("this_update", (QDateTime)task.lastUpdate);
	params.set("next_update", (QDateTime)task.nextUpdate);
	params.set("hash_algo", task.hashAlgo.name());
	if (!task.trigger.isEmpty())
		params.set("trigger", task.trigger);

	try {
		auditedTransaction(ctx, AuditLog::actionCrlGenerate, "crl",
					QString(), params, [&]() {
			pki_crl *crl = nullptr;
			x509v3ext e;
			X509V3_CTX ext_ctx;
			XSqlQuery q;

			if (!cert)
				throw serviceError("missing_issuer",
					tr("No CA certificate given"));
			pki_key *signkey = cert->getRefKey();
			if (!signkey || signkey->isPubKey()) {
				/* a non-CA has no use for its key here */
				if (!cert->isCA())
					throw serviceError("issuer_not_ca",
						tr("'%1' is not a CA certificate")
							.arg(cert->getIntName()));
				throw serviceError("no_private_signing_key",
					tr("There is no private key for '%1'")
						.arg(cert->getIntName()));
			}
			/* the issuer checks of certificates (BTD-188) */
			IssuanceChecks::crlIssuer(cert, signkey, task.hashAlgo,
						params);
			a1int last = lastCrlNumber(cert);
			if (!(task.crlNumber > last))
				throw serviceError("crl_number_not_increasing",
					tr("The CRL number %1 does not exceed the last CRL number %2 of '%3'")
						.arg(task.crlNumber.toDec(), last.toDec(),
							cert->getIntName()));
			/* the authority table keeps the number as unsigned 32 bit */
			if (!numeric || number > UINT_MAX)
				throw serviceError("invalid_crl_number",
					tr("The CRL number %1 is too large")
						.arg(task.crlNumber.toDec()));

			X509V3_set_ctx(&ext_ctx, cert->getCert(), NULL, NULL, NULL, 0);
			X509V3_set_ctx_nodb(&ext_ctx);
			if (name.isEmpty())
				name = cert->getIntName();
			try {
				crl = new pki_crl();
				crl->createCrl(name, cert);
				crl->pkiSource = generated;

				expiredEntries expired(cert);
				foreach(x509rev rev, cert->getRevList()) {
					if (!expired.drop(rev))
						crl->addRev(rev, task.withReason);
				}
				crl->addV3ext(authorityKeyId(cert, &ext_ctx));
				if (task.subAltName &&
				    cert->hasExtension(NID_subject_alt_name)) {
					crl->addV3ext(e.create(NID_issuer_alt_name,
						"issuer:copy", &ext_ctx));
				}
				crl->setCrlNumber(task.crlNumber);
				crl->setIssuer(cert);
				crl->setLastUpdate(task.lastUpdate);
				crl->setNextUpdate(task.nextUpdate);
				crl->sign(signkey, task.hashAlgo);
				params.set("signature_algorithm", OBJ_nid2ln(
					X509_CRL_get_signature_nid(crl->getCrl())));

				storeCrlNumber(cert, (uint)number, task.nextUpdate);
				SQL_PREPARE(q, "UPDATE revocations set crlNo=? "
						"WHERE crlNo IS NULL AND caId=?");
				q.bindValue(0, (uint)number);
				q.bindValue(1, cert->getSqlItemId());
				execOrThrow(q);
				params.set("this_update", (QDateTime)crl->getLastUpdate());
				params.set("next_update", (QDateTime)crl->getNextUpdate());
				params.set("count", (qint64)crl->numRev());
				params.set("der_size", (qint64)crl->i2d().size());
			} catch (...) {
				delete crl;
				throw;
			}
			/* insertPKI() keeps the CRL in the store or deletes it */
			stored = dynamic_cast<pki_crl *>(insertPKI(crl));
			if (!stored)
				throw serviceError("database_error",
					tr("The revocation list could not be stored"));
			params.set("name", stored->getIntName());
			AuditLog::append(ctx, AuditLog::actionCrlGenerate, "crl",
					stored->getSqlItemId().toString(), params);
		});
	} catch (...) {
		/* rolled back and unstored: ours again (BTD-130) */
		if (stored && !isStored(stored))
			delete stored;
		throw;
	}
	cert->setCrlNumber(task.crlNumber);
	cert->setCrlExpire(task.nextUpdate);
	return stored;
}
