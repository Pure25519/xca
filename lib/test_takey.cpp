/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2026 BxC Security GmbH.
 *
 * All rights reserved.
 */

#include <QTest>
#include <QFile>

#include "database_model.h"
#include "PwDialogCore.h"
#include "XcaWarningCore.h"
#include "pki_multi.h"
#include "pki_x509.h"
#include "sql.h"
#include "oid.h"

#define DBFILE "test_takey.xdb"

static const char ca_pem[] =
"-----BEGIN CERTIFICATE-----\n"
"MIIBbTCCARKgAwIBAgIUEj9WZ3EpaRGV0heub1H0CQY1ML8wCgYIKoZIzj0EAwIw\n"
"EzERMA8GA1UEAwwIQlRENDUtQ0EwIBcNMjYxMDI3MjM0OTU1WhgPMjEyNjEwMDMy\n"
"MzQ5NTVaMBMxETAPBgNVBAMMCEJURDQ1LUNBMFkwEwYHKoZIzj0CAQYIKoZIzj0D\n"
"AQcDQgAENiII9vMT/mkgnU/w16fEoYf61XNHky/QcKbrCyDW9vQaW/MA5sUiDDGU\n"
"9yZBYsqJMfsg0dJj+M7gAYBA0QoHl6NCMEAwHQYDVR0OBBYEFJAruK7g3ieqVKFu\n"
"Qu0GhaHqDf9JMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqG\n"
"SM49BAMCA0kAMEYCIQD1ADN2/Wcw/w9OaZ3ai5SXKqkxpHHYjAkuzz8hellflQIh\n"
"AIWf3UQ4+xJtmxw+n6DMcveZGmnEH3fQT2JDwR83+Ft2\n"
"-----END CERTIFICATE-----\n";

class test_takey: public QObject
{
	Q_OBJECT

	pki_x509 *ca{};
	static QByteArray taKeyPem(char fill);
	QByteArray storedValue();

private slots:
	void initTestCase();
	void cleanupTestCase();
	void importTwice();
};

/* An OpenVPN static key file with 256 bytes of 'fill' */
QByteArray test_takey::taKeyPem(char fill)
{
	QByteArray hex = QByteArray(2048/8, fill).toHex();
	QByteArray pem("-----BEGIN OpenVPN Static key V1-----\n");
	for (int i = 0; i < 16; i++)
		pem += hex.mid(32*i, 32) + "\n";
	pem += "-----END OpenVPN Static key V1-----\n";
	return pem;
}

/* The decoded takeys.value of the CA, or an empty array */
QByteArray test_takey::storedValue()
{
	XSqlQuery q;
	SQL_PREPARE(q, "SELECT value FROM takeys WHERE item = ?");
	q.bindValue(0, ca->getSqlItemId());
	q.exec();
	if (!q.next())
		return QByteArray();
	return QByteArray::fromBase64(q.value(0).toByteArray());
}

void test_takey::initTestCase()
{
	initOIDs();
	xcaWarning::setGui(new xcaWarningCore());
	QFile::remove(DBFILE);
	PwDialogCore::cmdline_passwd = "testdbpass";
	Database.open(DBFILE);
	QVERIFY(Database.isOpen());

	/* Database.insert() takes ownership of the pki_multi */
	pki_multi *multi = new pki_multi();
	multi->fromPEMbyteArray(QByteArray(ca_pem), "BTD45-CA");
	QCOMPARE(multi->get().size(), 1);
	Database.insert(multi);
	QList<pki_x509 *> certs = Store.getAll<pki_x509>();
	QCOMPARE(certs.size(), 1);
	ca = certs[0];
	QVERIFY(ca->isCA());
}

void test_takey::cleanupTestCase()
{
	Database.close();
	QFile::remove(DBFILE);
}

void test_takey::importTwice()
{
	/* First import: INSERT */
	QVERIFY(ca->importTaKey(taKeyPem('\x11')));
	QCOMPARE(storedValue(), QByteArray(2048/8, '\x11'));

	/* Second import of another key: UPDATE */
	QVERIFY(ca->importTaKey(taKeyPem('\x22')));
	QCOMPARE(storedValue(), QByteArray(2048/8, '\x22'));
	QCOMPARE(ca->getTaKey().toLatin1(), taKeyPem('\x22'));

	XSqlQuery q;
	SQL_PREPARE(q, "SELECT COUNT(*) FROM takeys");
	q.exec();
	QVERIFY(q.next());
	QCOMPARE(q.value(0).toInt(), 1);
}

QTEST_MAIN(test_takey)
#include "test_takey.moc"
