/* vi: set sw=4 ts=4:
 *
 * Import and export as service functions (BTD-34).
 */

#include "importexport.h"
#include "audit.h"
#include "database_model.h"
#include "db_crl.h"
#include "db_key.h"
#include "func.h"
#include "pass_info.h"
#include "pki_export.h"
#include "pki_key.h"
#include "pki_multi.h"
#include "pki_pkcs12.h"
#include "pki_temp.h"
#include "pki_x509.h"
#include "pki_x509req.h"
#include "pki_crl.h"
#include "PwDialogCore.h"
#include "sql.h"

#include <QBuffer>
#include <QMap>
#include <QSaveFile>

QString auditObjectType(const pki_base *pki)
{
	switch (pki ? pki->getType() : none) {
	case x509: return "certificate";
	case asym_key:
	case smartCard: return "key";
	case x509_req: return "request";
	case revocation: return "crl";
	case tmpl: return "template";
	default: return "object";
	}
}

QString importExistsMessage(const pki_base *existing)
{
	return QObject::tr("The item is already in the database as:\n'%1'\n"
			"and was not imported again").arg(existing->getIntName());
}

static QString itemId(const pki_base *pki)
{
	return pki && pki->getSqlItemId().isValid() ?
		pki->getSqlItemId().toString() : QString();
}

/* SHA-256 of the DER form; of the public key for keys */
static QString objectFingerprint(pki_base *pki)
{
	pki_key *key = dynamic_cast<pki_key *>(pki);
	if (key)
		return key->fingerprint("der sha256");
	if (dynamic_cast<pki_temp *>(pki))
		return QString();
	return fingerprint(pki->i2d(), EVP_sha256());
}

/* A password source error as the service error of the call */
static serviceError passwordError(const secretError &err)
{
	return serviceError(err.why == secretError::rejected ?
			"wrong_password" : "missing_password", err.getString());
}

/* Import */

namespace {
/* The revocations table, to audit what an import changes in it: a CRL
 * adds its entries for a CA of the database, a renewed CA takes over the
 * entries of its predecessor (db_crl::revokeCerts, db_x509::inToCont) */
class revocationRow
{
  public:
	QString date{}, invaldate{};
	QVariant crlNo{};
	int reasonBit{};

	bool operator==(const revocationRow &o) const
	{
		return date == o.date && invaldate == o.invaldate &&
			crlNo == o.crlNo && reasonBit == o.reasonBit;
	}
};
typedef QMap<QPair<qint64, QString>, revocationRow> revocationTable;

revocationTable readRevocations()
{
	revocationTable table;
	XSqlQuery q;

	SQL_PREPARE(q, "SELECT caId, serial, date, invaldate, crlNo, reasonBit "
			"FROM revocations");
	q.exec();
	if (q.lastError().isValid())
		throw errorEx(q.lastError());
	while (q.next()) {
		revocationRow r;
		r.date = q.value(2).toString();
		r.invaldate = q.value(3).toString();
		r.crlNo = q.value(4);
		r.reasonBit = q.value(5).toInt();
		table[qMakePair(q.value(0).toLongLong(),
				q.value(1).toString().toUpper())] = r;
	}
	return table;
}

QString revokedItemId(qint64 caId, const QString &serial)
{
	pki_x509 *ca = Store.lookupPki<pki_x509>(QVariant(caId));
	if (!ca)
		return QString();
	a1int sn;
	sn.setHex(serial);
	return itemId(ca->getBySerial(sn));
}

/* One certificate.revoke per new or changed and certificate.unrevoke
 * per removed row, as the revocation service functions write them,
 * so that AuditLog::verify() can replay the table */
void auditRevocationChanges(const ServiceContext &ctx,
		const revocationTable &before, const revocationTable &after)
{
	for (auto i = after.constBegin(); i != after.constEnd(); ++i) {
		if (before.contains(i.key()) && before[i.key()] == i.value())
			continue;
		a1time date, invalDate;
		date.fromPlain(i->date);
		invalDate.fromPlain(i->invaldate);
		AuditParams p = AuditParams::revocation(i.key().first,
			i.key().second, i->reasonBit, date, invalDate);
		if (!i->crlNo.isNull())
			p.set("crl_number", i->crlNo.toLongLong());
		AuditLog::append(ctx, AuditLog::actionRevoke, "certificate",
			revokedItemId(i.key().first, i.key().second), p);
	}
	for (auto i = before.constBegin(); i != before.constEnd(); ++i) {
		if (after.contains(i.key()))
			continue;
		AuditLog::append(ctx, AuditLog::actionUnrevoke, "certificate",
			revokedItemId(i.key().first, i.key().second),
			AuditParams::unrevocation(i.key().first, i.key().second));
	}
}

/* The object of the database that makes pki a duplicate, or NULL.
 * Same rules as db_*::insert(): a private key completes a public key
 * of the database (*completes), templates are never duplicates */
pki_base *findExisting(db_base *db, pki_base *pki, pki_key **completes)
{
	*completes = nullptr;
	if (dynamic_cast<pki_temp *>(pki))
		return nullptr;
	pki_base *old = db->getByReference(pki);
	pki_key *oldkey = dynamic_cast<pki_key *>(old);
	pki_key *newkey = dynamic_cast<pki_key *>(pki);
	if (oldkey && newkey && oldkey->isPubKey() && newkey->isPrivKey()) {
		*completes = oldkey;
		return nullptr;
	}
	return old;
}

/* A stored CRL: its CA, number and nextUpdate, and whether it raised the
 * CA's last CRL number (BTD-49) */
bool raiseCrlNumber(db_crl *db, pki_crl *crl, AuditParams &p)
{
	pki_x509 *ca = crl->getIssuer();
	a1int num;

	if (ca && ca->getSqlItemId().isValid())
		p.set("ca_id", ca->getSqlItemId().toLongLong());
	bool numeric = crl->getCrlNumber(&num);
	qint64 number = numeric ? num.toDec().toLongLong(&numeric) : 0;
	if (numeric)
		p.set("crl_number", number);
	p.set("next_update", (QDateTime)crl->getNextUpdate());
	bool raised = db->raiseCrlNumber(crl);
	p.set("authority_updated", raised);
	return raised;
}
}

/* Deletes the objects not stored, never one of the database. With
 * ImportSpec::unstored, the given objects go back to the caller */
static void dropItems(const QList<pki_base *> &items, const ImportSpec &spec)
{
	foreach(pki_base *pki, items) {
		if (pki->getSqlItemId().isValid())
			continue;
		if (spec.unstored && spec.items.contains(pki))
			*spec.unstored << pki;
		else
			delete pki;
	}
}

ImportResult database_model::importItems(const ServiceContext &ctx,
				const ImportSpec &spec)
{
	ImportResult result;
	QList<pki_base *> items;
	QList<pki_crl *> raised;
	AuditParams params;
	QStringList sources = spec.files;

	if (!spec.data.isEmpty())
		sources << (spec.dataName.isEmpty() ?
				QString("data") : spec.dataName);
	if (!sources.isEmpty())
		params.set("file", sources.join(", "));

	/* Take over the given objects first, so that nothing leaks */
	foreach(pki_base *pki, spec.items) {
		pki_multi *multi = dynamic_cast<pki_multi *>(pki);
		if (multi) {
			items += multi->pull();
			delete multi;
		} else if (pki) {
			items << pki;
		}
	}

	try {
		/* Read: no database access, may ask for the password */
		pki_multi read;
		try {
			PasswordSourceScope scope(pass_info::ImportPassword,
						spec.passwordSource);
			foreach(const QString &file, spec.files)
				read.probeAnything(file);
			if (!spec.data.isEmpty())
				read.probeData(spec.data, spec.dataName);
		} catch (secretError &err) {
			items += read.pull();
			throw passwordError(err);
		} catch (serviceError &) {
			items += read.pull();
			throw;
		} catch (errorEx &err) {
			items += read.pull();
			throw serviceError("unreadable_input", err.getString());
		}
		items += read.pull();
		result.failedFiles = read.failed_files;
		params.set("count", (qint64)items.size());

		if (items.isEmpty()) {
			if (!result.failedFiles.isEmpty())
				throw serviceError("no_pki_data",
					tr("No PKI data found in: '%1'").arg(
					result.failedFiles.join("', '")));
			throw serviceError("nothing_to_import",
					tr("Nothing to import"));
		}
		foreach(pki_base *pki, items) {
			if (!modelForPki(pki))
				throw serviceError("unsupported_type",
					tr("The type of the item '%1' is not recognized")
					.arg(pki->getIntName()));
		}

		Transaction;
		TransThrow();
		while (!items.isEmpty()) {
			/* stays in items, deleted on an error, until it is
			 * dropped or handed to insert() */
			pki_base *pki = items.first();
			db_base *db = modelForPki(pki);
			pki_key *completes = nullptr;
			AuditParams p;

			/* an object of the database, e.g. selected on the
			 * command line: nothing to import, nothing to delete */
			if (pki->getSqlItemId().isValid()) {
				items.removeFirst();
				if (!result.existing.contains(pki))
					result.existing << pki;
				continue;
			}
			pki_base *existing = findExisting(db, pki, &completes);

			p.set("name", pki->getIntName());
			if (!pki->getFilename().isEmpty())
				p.set("file", pki->getFilename());
			p.set("fingerprint", objectFingerprint(pki));

			if (existing) {
				items.removeFirst();
				delete pki;
				p.set("name", existing->getIntName());
				p.set("outcome", "existing");
				AuditLog::append(ctx, "object.import",
					auditObjectType(existing),
					itemId(existing), p);
				result.existing << existing;
				continue;
			}
			if (completes)
				p.set("item_id", itemId(completes));

			revocationTable before = readRevocations();
			items.removeFirst();
			pki_base *stored;
			if (completes) {
				stored = model<db_key>()->insertKey(
					static_cast<pki_key *>(pki), completes);
			} else {
				stored = db->insert(pki);
			}
			/* insert() keeps the object in the store or deletes it */
			if (!stored)
				throw serviceError("database_error",
					tr("The item could not be stored"));
			/* in memory now: undone if the transaction fails */
			result.created << stored;
			auditRevocationChanges(ctx, before, readRevocations());
			pki_crl *crl = dynamic_cast<pki_crl *>(stored);
			if (crl && raiseCrlNumber(model<db_crl>(), crl, p))
				raised << crl;

			p.set("name", stored->getIntName());
			p.set("outcome", completes ? "completed" : "created");
			AuditLog::append(ctx, "object.import",
				auditObjectType(stored), itemId(stored), p);
		}
		if (!TransCommit())
			throw serviceError("database_error",
				tr("Failed to commit the database transaction"));
		/* in order: a later, higher CRL of the same CA wins */
		foreach(pki_crl *crl, raised) {
			crl->getIssuer()->setCrlNumber(crl->getCrlNumber());
			crl->getIssuer()->setCrlExpire(crl->getNextUpdate());
		}
	} catch (serviceError &err) {
		/* the transaction is rolled back here and what it stored is
		 * out of the store and the views again (BTD-130): it goes
		 * back to the caller or is deleted (BTD-114) */
		dropItems(items + result.created, spec);
		/* after the rollback, so the entry is kept (lib/audit.h) */
		AuditLog::append(ctx, "object.import", "object", QString(),
				params, "failure", err.code);
		throw;
	} catch (...) {
		dropItems(items + result.created, spec);
		AuditLog::append(ctx, "object.import", "object", QString(),
				params, "failure", "internal_error");
		throw;
	}
	return result;
}

/* Export */

static QString exportPasswordPrompt(const pki_export *xport,
			const pki_base *pki, const QString &fileName)
{
	QString name = pki ? pki->getIntName() : QString();
	QString file = nativeSeparator(fileName);

	if (xport->match_all(F_PKCS12))
		return QObject::tr("Please enter the password to encrypt the key "
			"of certificate '%1' in the PKCS#12 file:\n%2")
			.arg(name).arg(file);
	if (xport->match_all(F_PKCS8))
		return QObject::tr("Please enter the password to protect the "
			"PKCS#8 key '%1' in file:\n%2").arg(name).arg(file);
	return QObject::tr("Please enter the password to protect the private "
			"key '%1' in file:\n%2").arg(name).arg(file);
}

QByteArray db_base::exportItems(const ServiceContext &ctx,
				const ExportSpec &spec)
{
	const pki_export *xport = spec.clipboard ? clipboardFormat() :
							spec.format;
	QString objectType = pkitype.isEmpty() ? QString("object") :
		auditObjectType(spec.items.isEmpty() ? nullptr : spec.items[0]);
	AuditParams params;

	if (spec.clipboard)
		params.set("format", "clipboard");
	else if (xport)
		params.set("format", (qint64)xport->id);
	if (!spec.fileName.isEmpty())
		params.set("file", spec.fileName);
	params.set("count", (qint64)spec.items.size());
	if (spec.items.size() == 1 && spec.items[0])
		params.set("name", spec.items[0]->getIntName());

	try {
		if (spec.items.isEmpty())
			throw serviceError("nothing_to_export",
				tr("No item selected"));
		foreach(pki_base *pki, spec.items) {
			if (!pki || !pkitype.contains(pki->getType()))
				throw serviceError("wrong_object_type",
					tr("The item does not belong to this list"));
		}
		if (!spec.clipboard) {
			if (!xport || !pkitype.contains(xport->pki_type))
				throw serviceError("invalid_format",
					tr("Unknown export format"));
			if ((xport->flags & F_SINGLE) && spec.items.size() > 1)
				throw serviceError("single_item_format",
					tr("The format '%1' takes only one item")
					.arg(xport->desc));
			if (xport->flags & exportFlags(spec.items))
				throw serviceError("format_not_applicable",
					tr("The format '%1' is not possible for the "
					   "selected items").arg(xport->desc));
		}

		if (!spec.pkcs12Algorithm.isEmpty() &&
		    !encAlgo::all_encAlgos.contains(
				encAlgo(spec.pkcs12Algorithm).getEncAlgoNid()))
			throw serviceError("invalid_pkcs12_algorithm",
				tr("Unknown PKCS#12 algorithm '%1'")
				.arg(spec.pkcs12Algorithm));
		encAlgo::ExportScope algorithm(spec.pkcs12Algorithm);

		/* The password, before the database is touched */
		Passwd pass;
		bool encrypted = !spec.clipboard && xport->match_all(F_CRYPT);
		if (encrypted) {
			PasswordSourceScope scope(pass_info::ExportPassword,
						spec.passwordSource);
			pass_info p(XCA_TITLE, exportPasswordPrompt(xport,
					spec.items[0], spec.fileName));
			p.setPurpose(pass_info::ExportPassword);
			try {
				if (PwDialogCore::execute(&p, &pass, true) != pw_ok)
					throw serviceError("cancelled",
						tr("The export was cancelled"));
			} catch (secretError &err) {
				throw passwordError(err);
			}
			/* PKCS#12 accepts an empty password, OpenSSL's PEM
			 * and PKCS#8 encryption rejects it */
			if (pass.isEmpty() && !xport->match_all(F_PKCS12))
				throw serviceError("missing_password",
					tr("The password must not be empty"));
		}

		/* The output, in memory */
		QByteArray out;
		if (spec.clipboard) {
			BioByteArray bba;
			foreach(pki_base *pki, spec.items) {
				pki->pem(bba);
				openssl_error();
			}
			out = bba.byteArray();
		} else {
			QBuffer buf(&out);
			buf.open(QIODevice::WriteOnly);
			writeItems(spec.items, xport, buf, pass);
			buf.close();
		}

		/* The entries, then the file, then the commit: no private key
		 * leaves the database without its audit entry. The file is
		 * written beside the target and renamed over it only after
		 * the commit: a failure leaves an existing file as it was
		 * (BTD-114); QSaveFile drops the temporary file on failure */
		QSaveFile file(spec.fileName);
		Transaction;
		TransThrow();
		QList<pki_base *> objects = spec.clipboard ? spec.items :
					exportedObjects(spec.items, xport);
		foreach(pki_base *pki, objects) {
			AuditParams p = params;
			p.set("name", pki->getIntName());
			p.set("count", (qint64)objects.size());
			AuditLog::append(ctx, "object.export",
				auditObjectType(pki), itemId(pki), p);
		}
		/* of the items: a chain carries only the key of the first */
		foreach(pki_key *key, exportedPrivateKeys(spec.items, xport)) {
			AuditParams p = params;
			p.set("name", key->getIntName());
			p.set("fingerprint", key->fingerprint("der sha256"));
			/* as written: the clipboard text is never encrypted,
			 * also with the format "PEM + PKCS#8" (pki_evp::pem);
			 * a PKCS#12 file with an empty password protects
			 * nothing */
			p.set("encrypted", encrypted && !pass.isEmpty());
			AuditLog::append(ctx, "key.export_private", "key",
				itemId(key), p);
		}
		if (!spec.fileName.isEmpty()) {
			if (!file.open(QIODevice::WriteOnly))
				throw serviceError("write_failed",
					tr("Error opening file: '%1': %2")
					.arg(spec.fileName).arg(file.errorString()));
			/* a new key file and a replaced one: owner only */
			if (xport && xport->match_all(F_PRIVATE))
				file.setPermissions(QFile::ReadOwner |
						QFile::WriteOwner);
			if (file.write(out) != out.size())
				throw serviceError("write_failed",
					tr("Failed writing to %1").arg(spec.fileName));
		}
		if (!TransCommit())
			throw serviceError("database_error",
				tr("Failed to commit the database transaction"));
		/* The success entries say "handed to the file layer": if the
		 * rename fails now, a write_failed entry follows them. The
		 * temporary file carries the permissions set above (POSIX);
		 * on Windows the inherited ACL of the directory, and the
		 * directory must be writable (no direct-write fallback) */
		if (!spec.fileName.isEmpty() && !file.commit())
			throw serviceError("write_failed",
				tr("Failed writing to %1: %2").arg(spec.fileName)
				.arg(file.errorString()));
		return out;
	} catch (serviceError &err) {
		/* after the rollback, so the entry is kept (lib/audit.h) */
		AuditLog::append(ctx, "object.export", objectType,
			spec.items.size() == 1 ? itemId(spec.items[0]) : QString(),
			params, "failure", err.code);
		throw;
	} catch (...) {
		AuditLog::append(ctx, "object.export", objectType,
			spec.items.size() == 1 ? itemId(spec.items[0]) : QString(),
			params, "failure", "internal_error");
		throw;
	}
}

QList<pki_base *> db_base::exportedObjects(const QList<pki_base *> &items,
			const pki_export *) const
{
	return items;
}

/* Formats with F_PRIVATE write the private key of each key item */
QList<pki_key *> db_base::exportedPrivateKeys(const QList<pki_base *> &items,
			const pki_export *xport) const
{
	QList<pki_key *> keys;

	if (!xport || !xport->match_all(F_PRIVATE))
		return keys;
	foreach(pki_base *pki, items) {
		pki_key *key = dynamic_cast<pki_key *>(pki);
		if (key && key->isPrivKey() && !key->isToken())
			keys << key;
	}
	return keys;
}
