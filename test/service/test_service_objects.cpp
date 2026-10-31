/* vi: set sw=4 ts=4:
 *
 * Rename, name and comment, and deletion through the service functions
 * of BTD-35: db_base::rename(), updateProperties(), deleteItems() and
 * db_token::rename(). Dependent objects are handled as before and
 * reported; one audit entry per operation, the chain and the
 * revocations table verify.
 */

#include <QDateTime>
#include <QSignalSpy>

#include "lib/audit.h"
#include "lib/database_model.h"
#include "lib/db_crl.h"
#include "lib/db_key.h"
#include "lib/db_temp.h"
#include "lib/db_token.h"
#include "lib/db_x509.h"
#include "lib/db_x509req.h"
#include "lib/exception.h"
#include "lib/issuance.h"
#include "lib/pki_crl.h"
#include "lib/pki_temp.h"
#include "lib/pki_x509.h"
#include "lib/pki_x509req.h"
#include "lib/request.h"

#include "ServiceTestCase.h"

class test_service_objects : public ServiceTestCase
{
	Q_OBJECT

	ServiceContext ctx{ ServiceContext::cli, "os:service-test" };

	static db_key *keys()
	{
		return Database.model<db_key>();
	}
	static db_x509 *certs()
	{
		return Database.model<db_x509>();
	}
	static pki_key *newKey(const QString &name)
	{
		return keys()->newKey(keyjob("EC:prime256v1"), name);
	}
	pki_x509 *issue(const QString &cn, pki_key *key, pki_x509 *signer);
	pki_x509req *request(const QString &cn, pki_key *key);
	static AuditEntry last()
	{
		return AuditLog::entries().last();
	}
	static void verifyChain();
	static void verifyDataChanged(const db_base *model,
				const QSignalSpy &spy);
	template <class T> static T *reread(const QVariant &id)
	{
		return Store.lookupPki<T>(id);
	}
	static qint64 revocationRows();

  private slots:
	void renameKeyAndCertificate();
	void renameRejected();
	void updateProperties();
	void deleteCertificate();
	void deleteKeyWithDependents();
	void deleteCaWithDependents();
	void deleteTogether();
	void deleteRejected_data();
	void deleteRejected();
	void deleteDatabaseError();
	void tokenRenameRejected();
};

pki_x509 *test_service_objects::issue(const QString &cn, pki_key *key,
			pki_x509 *signer)
{
	IssuanceSpec spec;
	QDateTime now = QDateTime::currentDateTimeUtc();

	spec.name = cn;
	spec.subject.addEntryByNid(NID_commonName, cn);
	spec.key = key;
	spec.signer = signer;
	spec.notBefore = a1time(now.addDays(-1));
	spec.notAfter = a1time(now.addYears(signer ? 1 : 10));
	spec.hashAlgo = digest(NID_sha256);
	spec.extensions.subjectKeyId = true;
	spec.extensions.authorityKeyId = true;
	spec.extensions.basicCA = signer ? ExtensionSpec::bc_not_ca :
					ExtensionSpec::bc_ca;
	if (!signer)
		spec.extensions.keyUsage << "keyCertSign" << "cRLSign";
	return certs()->newCert(ctx, spec);
}

pki_x509req *test_service_objects::request(const QString &cn, pki_key *key)
{
	RequestSpec spec;
	spec.name = cn;
	spec.subject.addEntryByNid(NID_commonName, cn);
	spec.key = key;
	spec.hashAlgo = digest(NID_sha256);
	return Database.model<db_x509req>()->newRequest(ctx, spec);
}

void test_service_objects::verifyChain()
{
	AuditVerifyResult v = AuditLog::verify();
	QVERIFY2(v.ok(), v.toJson().constData());
}

qint64 test_service_objects::revocationRows()
{
	XSqlQuery q("SELECT COUNT(*) FROM revocations");
	return q.first() ? q.value(0).toLongLong() : -1;
}

/* Every dataChanged() of the model names cells that exist: the view's
 * proxy model maps the range column by column without a bounds check, so
 * a column past the last one read beyond its mapping (BTD-227) */
void test_service_objects::verifyDataChanged(const db_base *model,
			const QSignalSpy &spy)
{
	QVERIFY(spy.size() > 0);
	for (const QList<QVariant> &args : spy) {
		QModelIndex tl = args[0].value<QModelIndex>();
		QModelIndex br = args[1].value<QModelIndex>();
		QVERIFY(tl.isValid() && br.isValid());
		QCOMPARE(tl.parent(), br.parent());
		QVERIFY(tl.row() <= br.row() && tl.column() <= br.column());
		QVERIFY(br.row() < model->rowCount(br.parent()));
		QVERIFY2(br.column() < model->columnCount(br.parent()),
			qPrintable(QString("column %1 of %2").arg(br.column())
				.arg(model->columnCount(br.parent()))));
	}
}

/* Acceptance criterion 1: rename of a key and a certificate */
void test_service_objects::renameKeyAndCertificate()
{
	pki_key *key = newKey("old key");
	pki_x509 *cert = issue("old cert", key, nullptr);
	QVERIFY(key && cert);
	QVariant keyId = key->getSqlItemId(), certId = cert->getSqlItemId();
	int entries = AuditLog::entries().size();

	keys()->rename(ctx, key, "new key");
	AuditEntry e = last();
	QCOMPARE(e.action, QString("object.rename"));
	QCOMPARE(e.result, QString("success"));
	QCOMPARE(e.objectType, QString("key"));
	QCOMPARE(e.objectId, keyId.toString());
	QCOMPARE(e.params.value("old_name").toString(), QString("old key"));
	QCOMPARE(e.params.value("name").toString(), QString("new key"));

	certs()->rename(ctx, cert, "new cert");
	e = last();
	QCOMPARE(e.action, QString("object.rename"));
	QCOMPARE(e.objectType, QString("certificate"));
	QCOMPARE(e.objectId, certId.toString());
	QCOMPARE(e.params.value("old_name").toString(), QString("old cert"));
	QCOMPARE(AuditLog::entries().size(), entries + 2);

	/* the same name changes nothing and writes nothing */
	certs()->rename(ctx, cert, "new cert");
	QCOMPARE(AuditLog::entries().size(), entries + 2);

	/* the inline editor of the view goes the same way */
	QModelIndex idx = keys()->index(key);
	QVERIFY(keys()->setData(idx, QString("edited key"), Qt::EditRole));
	QCOMPARE(last().params.value("old_name").toString(), QString("new key"));
	QCOMPARE(last().channel, QString("gui"));

	reopenDatabase();
	QCOMPARE(reread<pki_key>(keyId)->getIntName(), QString("edited key"));
	QCOMPARE(reread<pki_x509>(certId)->getIntName(), QString("new cert"));
	verifyChain();
}

/* An object that is not in the database: unchanged, one failure entry */
void test_service_objects::renameRejected()
{
	pki_key *key = newKey("stored key");
	QVERIFY(key);
	pki_x509 loose;
	loose.setIntName("loose");
	int entries = AuditLog::entries().size();

	try {
		certs()->rename(ctx, &loose, "renamed");
		QFAIL("no serviceError");
	} catch (serviceError &err) {
		QCOMPARE(err.code, QString("missing_object"));
	}
	QCOMPARE(loose.getIntName(), QString("loose"));
	QCOMPARE(AuditLog::entries().size(), entries + 1);
	QCOMPARE(last().action, QString("object.rename"));
	QCOMPARE(last().result, QString("failure"));
	QCOMPARE(last().errorCode, QString("missing_object"));

	/* a key is no object of the certificate list */
	try {
		certs()->rename(ctx, key, "renamed");
		QFAIL("no serviceError");
	} catch (serviceError &err) {
		QCOMPARE(err.code, QString("wrong_object_type"));
	}
	QCOMPARE(key->getIntName(), QString("stored key"));
	verifyChain();
}

/* Properties dialog: name and comment, one entry each */
void test_service_objects::updateProperties()
{
	pki_key *key = newKey("ca key");
	pki_x509 *cert = issue("props", key, nullptr);
	QVERIFY(cert);
	QVariant id = cert->getSqlItemId();
	int entries = AuditLog::entries().size();
	QSignalSpy changed(certs(), &QAbstractItemModel::dataChanged);

	certs()->updateProperties(ctx, cert, "props 2", "a comment");
	verifyDataChanged(certs(), changed);
	/* no index past the last column (QAbstractItemModel::hasIndex()) */
	QModelIndex row = certs()->index(cert);
	QVERIFY(row.isValid());
	QVERIFY(!certs()->index(row.row(), certs()->columnCount(row.parent()),
				row.parent()).isValid());
	QList<AuditEntry> list = AuditLog::entries();
	QCOMPARE(list.size(), entries + 2);
	QCOMPARE(list[entries].action, QString("object.rename"));
	QCOMPARE(list[entries].params.value("old_name").toString(),
		QString("props"));
	QCOMPARE(list[entries + 1].action, QString("object.update_comment"));
	QCOMPARE(list[entries + 1].params.value("name").toString(),
		QString("props 2"));
	QVERIFY(!list[entries + 1].params.contains("comment"));

	/* only the comment */
	certs()->updateProperties(ctx, cert, "props 2", "another comment");
	QCOMPARE(AuditLog::entries().size(), entries + 3);
	QCOMPARE(last().action, QString("object.update_comment"));

	reopenDatabase();
	cert = reread<pki_x509>(id);
	QCOMPARE(cert->getIntName(), QString("props 2"));
	QCOMPARE(cert->getComment(), QString("another comment"));
	verifyChain();
}

/* Acceptance criterion 1: delete of a certificate */
void test_service_objects::deleteCertificate()
{
	pki_x509 *ca = issue("Delete CA", newKey("ca key"), nullptr);
	pki_key *eeKey = newKey("ee key");
	pki_x509 *ee = issue("ee", eeKey, ca);
	QVERIFY(ca && ee);
	QString id = ee->getSqlItemId().toString();
	int entries = AuditLog::entries().size();

	DeleteResult r = certs()->deleteItems(ctx, { ee });
	QCOMPARE(r.deleted.size(), 1);
	QCOMPARE(r.deleted[0].objectType, QString("certificate"));
	QCOMPARE(r.deleted[0].id, id);
	QCOMPARE(r.deleted[0].name, QString("ee"));
	QVERIFY(r.dependents.isEmpty());
	QCOMPARE(r.revocations, 0);

	QCOMPARE(AuditLog::entries().size(), entries + 1);
	AuditEntry e = last();
	QCOMPARE(e.action, QString("object.delete"));
	QCOMPARE(e.result, QString("success"));
	QCOMPARE(e.objectType, QString("certificate"));
	QCOMPARE(e.objectId, id);
	QCOMPARE(e.params.value("name").toString(), QString("ee"));
	QCOMPARE(e.params.value("dependents").toInt(), 0);
	QCOMPARE(e.params.value("revocations").toInt(), 0);

	QCOMPARE(Store.getAll<pki_x509>().size(), 1);
	QVERIFY(!certs()->getByName("ee"));
	/* the key stays */
	QVERIFY(keys()->getByName("ee key"));
	reopenDatabase();
	QCOMPARE(Store.getAll<pki_x509>().size(), 1);
	verifyChain();
}

/* Acceptance criterion 1: delete of a key with dependent objects; the
 * certificate and the request stay without their private key */
void test_service_objects::deleteKeyWithDependents()
{
	pki_key *key = newKey("shared key");
	pki_x509 *cert = issue("self", key, nullptr);
	pki_x509req *req = request("req", key);
	QVERIFY(cert && req);
	QVERIFY(cert->getRefKey() == key);
	QVariant certId = cert->getSqlItemId(), reqId = req->getSqlItemId();

	DeleteResult r = keys()->deleteItems(ctx, { key });
	QCOMPARE(r.deleted.size(), 1);
	QCOMPARE(r.deleted[0].objectType, QString("key"));
	QCOMPARE(r.dependents.size(), 2);
	QVERIFY(r.dependents.contains(cert));
	QVERIFY(r.dependents.contains(req));
	QVERIFY(!cert->getRefKey());
	QVERIFY(!req->getRefKey());

	AuditEntry e = last();
	QCOMPARE(e.action, QString("object.delete"));
	QCOMPARE(e.objectType, QString("key"));
	QCOMPARE(e.params.value("dependents").toInt(), 2);
	QVERIFY(!e.params.contains("revocations"));

	reopenDatabase();
	QVERIFY(Store.getAll<pki_key>().isEmpty());
	QVERIFY(reread<pki_x509>(certId));
	QVERIFY(!reread<pki_x509>(certId)->getRefKey());
	QVERIFY(reread<pki_x509req>(reqId));
	verifyChain();
}

/* A CA with an issued certificate, a revoked one and a CRL: the
 * certificates and the CRL stay without issuer, the CA's revocation
 * rows go, and verify() knows why */
void test_service_objects::deleteCaWithDependents()
{
	pki_x509 *ca = issue("Root", newKey("root key"), nullptr);
	pki_x509 *ee = issue("leaf", newKey("leaf key"), ca);
	pki_x509 *gone = issue("revoked", newKey("revoked key"), ca);
	QVERIFY(ca && ee && gone);
	x509rev rev;
	rev.setReason("Key Compromise");
	certs()->revoke(ctx, gone, rev);
	crljob job(ca);
	pki_crl *crl = Database.model<db_crl>()->newCrl(ctx, job);
	QVERIFY(crl);
	QCOMPARE(revocationRows(), 1);
	QVariant caId = ca->getSqlItemId(), crlId = crl->getSqlItemId();

	DeleteResult r = certs()->deleteItems(ctx, { ca });
	QCOMPARE(r.deleted.size(), 1);
	QCOMPARE(r.revocations, 1);
	QCOMPARE(r.dependents.size(), 3);
	QVERIFY(r.dependents.contains(ee));
	QVERIFY(r.dependents.contains(gone));
	QVERIFY(r.dependents.contains(crl));
	QVERIFY(!ee->getSigner());
	QCOMPARE(revocationRows(), 0);

	AuditEntry e = last();
	QCOMPARE(e.action, QString("object.delete"));
	QCOMPARE(e.objectId, caId.toString());
	QCOMPARE(e.params.value("dependents").toInt(), 3);
	QCOMPARE(e.params.value("revocations").toInt(), 1);
	/* the revocation entry of the deleted CA no longer expects a row */
	verifyChain();
	reopenDatabase();
	QVERIFY(Store.lookupPki<pki_crl>(crlId));
	verifyChain();
}

/* Objects deleted together are no dependents of each other */
void test_service_objects::deleteTogether()
{
	pki_key *key = newKey("pair key");
	pki_x509 *cert = issue("pair", key, nullptr);
	QVERIFY(cert);

	DeleteResult r = keys()->deleteItems(ctx, { key });
	QCOMPARE(r.dependents.size(), 1);

	pki_key *key2 = newKey("pair key 2");
	pki_x509 *cert2 = issue("pair 2", key2, nullptr);
	int entries = AuditLog::entries().size();
	r = certs()->deleteItems(ctx, { cert, cert2 });
	QCOMPARE(r.deleted.size(), 2);
	QCOMPARE(r.deleted[0].name, QString("pair"));
	QCOMPARE(r.deleted[1].name, QString("pair 2"));
	QVERIFY(r.dependents.isEmpty());
	QCOMPARE(AuditLog::entries().size(), entries + 2);
	QVERIFY(Store.getAll<pki_x509>().isEmpty());
	verifyChain();
}

void test_service_objects::deleteRejected_data()
{
	QTest::addColumn<QString>("variant");
	QTest::addColumn<QString>("code");

	QTest::newRow("empty") << "empty" << "nothing_to_delete";
	QTest::newRow("other list") << "other list" << "wrong_object_type";
	QTest::newRow("not stored") << "not stored" << "missing_object";
	QTest::newRow("twice") << "twice" << "missing_object";
}

/* Nothing is deleted, not even the valid objects of the call */
void test_service_objects::deleteRejected()
{
	QFETCH(QString, variant);
	QFETCH(QString, code);

	pki_key *key = newKey("valid key");
	pki_x509 *cert = issue("valid", key, nullptr);
	pki_x509 loose;
	QList<pki_base *> items;

	if (variant == "other list")
		items << cert << key;
	else if (variant == "not stored")
		items << cert << &loose;
	else if (variant == "twice")
		items << cert << cert;
	int entries = AuditLog::entries().size();

	try {
		certs()->deleteItems(ctx, items);
		QFAIL("no serviceError");
	} catch (serviceError &err) {
		QCOMPARE(err.code, code);
	}
	QCOMPARE(AuditLog::entries().size(), entries + 1);
	QCOMPARE(last().action, QString("object.delete"));
	QCOMPARE(last().result, QString("failure"));
	QCOMPARE(last().errorCode, code);
	QCOMPARE(Store.getAll<pki_x509>().size(), 1);
	QCOMPARE(Store.getAll<pki_key>().size(), 1);
	QVERIFY(certs()->index(cert).isValid());
	verifyChain();
}

/* Regression (BTD-35): db_base::deletePKI() freed the object after a
 * failed DELETE although it stayed in the view; now the deletion fails
 * as a whole, the object stays and the failure is audited */
void test_service_objects::deleteDatabaseError()
{
	pki_x509 *ca = issue("Error CA", newKey("ca key"), nullptr);
	pki_x509 *ee = issue("error ee", newKey("ee key"), ca);
	QVERIFY(ca && ee);
	QVariant id = ee->getSqlItemId();
	XSqlQuery q;
	QVERIFY(q.exec("DROP TABLE takeys"));

	try {
		certs()->deleteItems(ctx, { ca, ee });
		QFAIL("no serviceError");
	} catch (serviceError &err) {
		QCOMPARE(err.code, QString("database_error"));
	}
	QCOMPARE(last().action, QString("object.delete"));
	QCOMPARE(last().result, QString("failure"));
	QCOMPARE(last().errorCode, QString("database_error"));
	/* the first object failed: nothing was deleted, in memory neither */
	QCOMPARE(last().objectId, ca->getSqlItemId().toString());
	QVERIFY(Store.find(id.toULongLong()) == ee);
	QVERIFY(certs()->index(ee).isValid());
	QCOMPARE(certs()->allItemsCount(), 2);
	XSqlQuery c("SELECT COUNT(*) FROM certs");
	QVERIFY(c.first());
	QCOMPARE(c.value(0).toInt(), 2);
	verifyChain();
}

/* Renaming on a token needs one; without the object on the token's
 * list nothing changes and the failure is audited */
void test_service_objects::tokenRenameRejected()
{
	pki_key *key = newKey("not on a token");
	db_token tokens;
	try {
		tokens.rename(ctx, key, "renamed");
		QFAIL("no serviceError");
	} catch (serviceError &err) {
		QCOMPARE(err.code, QString("missing_object"));
	}
	QCOMPARE(key->getIntName(), QString("not on a token"));
	AuditEntry e = last();
	QCOMPARE(e.action, QString("object.rename"));
	QCOMPARE(e.result, QString("failure"));
	QCOMPARE(e.params.value("on_token").toBool(), true);
	verifyChain();
}

XCA_SERVICE_TEST_MAIN(test_service_objects)
#include "test_service_objects.moc"
