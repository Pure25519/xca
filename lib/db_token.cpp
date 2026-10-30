
#include "db_token.h"
#include "audit.h"
#include "exception.h"
#include "importexport.h"
#include "pki_scard.h"
#include "sql.h"
#include "XcaWarningCore.h"

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
	QList<pki_scard*> list = Store.sqlSELECTpki<pki_scard>(
                QString("SELECT item FROM tokens "
			"WHERE card_serial=? AND card_model=? and object_id=?"),
                QList<QVariant>() << QVariant(token->getSerial())
				<< QVariant(token->getModel())
				<< QVariant(token->getId()));

	foreach(pki_scard *item, list) {
		if (token->compare(item))
			item->updateLabel(token->getIntName());
	}
	TransCommitThrow();
}

void db_token::rename(const ServiceContext &ctx, pki_base *pki,
			const QString &name)
{
	QString oldName = pki ? pki->getIntName() : QString();
	AuditParams params;

	if (pki && name == oldName)
		return;
	params.set("name", name);
	params.set("old_name", oldName);
	params.set("on_token", true);
	auditedTransaction(ctx, "object.rename", auditObjectType(pki),
				QString(), params, [&]() {
		if (!pki || rootItem->indexOf(pki) == -1)
			throw serviceError("missing_object",
				tr("The item is not on the token"));
		if (!pki->renameOnToken(slot, name))
			throw serviceError("token_error",
				tr("The object '%1' was not renamed on the token")
					.arg(oldName));
		pki->setIntName(name);
		rename_token_in_database(dynamic_cast<pki_scard*>(pki));
		AuditLog::append(ctx, "object.rename", auditObjectType(pki),
				QString(), params);
	});
	QModelIndex i = index(pki);
	emit dataChanged(i, i);
}
