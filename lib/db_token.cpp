
#include "db_token.h"
#include "audit.h"
#include "exception.h"
#include "importexport.h"
#include "pki_scard.h"
#include "pki_x509.h"
#include "sql.h"
#include "XcaWarningCore.h"

std::function<bool(pki_base *, const QString &)> db_token::tokenRenameHook{};

db_token::db_token() : db_base("manageTokens")
{
	updateHeaders();
}

void db_token::saveHeaderState()
{
}

void db_token::rename_token_in_database(pki_scard *token)
{
	if (!token)
		return;
	Transaction;
	TransThrow();
	/* a failed query is a database_error, not an empty list (BTD-128) */
	XSqlQuery q;
	SQL_PREPARE(q, "SELECT item FROM tokens "
			"WHERE card_serial=? AND card_model=? and object_id=?");
	q.bindValue(0, token->getSerial());
	q.bindValue(1, token->getModel());
	q.bindValue(2, token->getId());
	execOrThrow(q, tr("The token keys could not be read"));
	QList<pki_scard*> list;
	while (q.next()) {
		pki_scard *item = Store.lookupPki<pki_scard>(q.value(0));
		if (item)
			list << item;
	}

	foreach(pki_scard *item, list) {
		if (token->compare(item))
			item->updateLabel(token->getIntName());
	}
	TransCommitThrow();
}

/* The object on the token for the audit entry: the CKA_ID of a key,
 * the SHA-256 fingerprint of a certificate (BTD-128) */
static QString tokenObjectId(pki_base *pki)
{
	pki_scard *card = dynamic_cast<pki_scard *>(pki);
	if (card)
		return card->getId();
	pki_x509 *cert = dynamic_cast<pki_x509 *>(pki);
	if (cert)
		return cert->fingerprint(EVP_sha256());
	return QString();
}

void db_token::rename(const ServiceContext &ctx, pki_base *pki,
			const QString &name)
{
	QString oldName = pki ? pki->getIntName() : QString();
	QString objectId = tokenObjectId(pki);
	AuditParams params;

	if (pki && name == oldName)
		return;
	params.set("name", name);
	params.set("old_name", oldName);
	params.set("on_token", true);
	auditedTransaction(ctx, "object.rename", auditObjectType(pki),
				objectId, params, [&]() {
		if (!pki || rootItem->indexOf(pki) == -1)
			throw serviceError("missing_object",
				tr("The item is not on the token"));
		/* The database first and the label on the token last: a
		 * database failure leaves the token as it was, a token
		 * failure rolls the database back (BTD-128) */
		pki->setIntName(name);
		DbTransaction::onRollback([pki, oldName]() {
			pki->setIntName(oldName);
		});
		rename_token_in_database(dynamic_cast<pki_scard*>(pki));
		if (!(tokenRenameHook ? tokenRenameHook(pki, name) :
				pki->renameOnToken(slot, name)))
			throw serviceError("token_error",
				tr("The object '%1' was not renamed on the token")
					.arg(oldName));
		AuditLog::append(ctx, "object.rename", auditObjectType(pki),
				objectId, params);
	});
	QModelIndex i = index(pki);
	emit dataChanged(i, i);
}
