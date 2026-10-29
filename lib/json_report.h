/* vi: set sw=4 ts=4:
 *
 * JSON documents of the XCA objects and of the list outputs (BTD-39).
 *
 * The contract is the set of bxc-pki object schemas (bxc-pki
 * schemas/<name>.schema.json, PLAN.md section 7): certificate, csr, crl, key,
 * template, list (--list-items, --issuers, --index, --hierarchy) and
 * error. Every document carries its schema URN in the member "schema".
 * Binary objects are embedded as PEM (LF, 64 characters per line),
 * timestamps are RFC 3339 in UTC, serials uppercase hex of whole octets
 * (a1int::toHex, see serial()), OIDs dotted with the OpenSSL short name next to them,
 * distinguished names in RFC 4514 notation plus their attributes in
 * encoding order.
 *
 * Only public data: a key document holds the public key (PEM label
 * PUBLIC KEY) and the kind of protection, never private key material, a
 * password or a PIN; nothing in here decrypts a key. The challengePassword
 * attribute of a request is left out.
 *
 * Items that are not stored in the database (read from a file) have no
 * id and no creation date: both are null. A key read from a file reports
 * storage "file" and protection "own" (the file is encrypted) or "none",
 * never "database" (BTD-41).
 *
 * xca --no-gui --json writes each document as one line (JSON Lines) with
 * line(); stdout then carries only JSON documents, informational texts
 * go to stderr (xcaWarningCore). Only Qt Core and OpenSSL are used here.
 */

#ifndef __JSON_REPORT_H
#define __JSON_REPORT_H

#include <stdio.h>

#include <QByteArray>
#include <QJsonObject>
#include <QJsonValue>
#include <QList>
#include <QString>

#include <openssl/evp.h>
#include <openssl/x509.h>

class a1int;
class a1time;
class errorEx;
class pki_base;
class pki_crl;
class pki_key;
class pki_temp;
class pki_x509;
class pki_x509req;
class x509name;

class JsonReport
{
	static bool json;

  public:
	/* xca --no-gui --json */
	static void setActive(bool on);
	static bool active();

	/* The objects, by their schema */
	static QJsonObject certificate(const pki_x509 *cert);
	static QJsonObject request(const pki_x509req *req);
	static QJsonObject crl(const pki_crl *crl);
	static QJsonObject key(const pki_key *key);
	static QJsonObject temp(const pki_temp *temp);
	/* One of the above by the type of pki; an empty object for a
	 * type without schema */
	static QJsonObject object(const pki_base *pki);

	/* The list documents (list schema, kind items, issuers, index,
	 * hierarchy). index() and hierarchy() read the certificates of
	 * the open database like db_x509::writeIndex() does. */
	static QJsonObject itemList(const QList<pki_base *> &items);
	static QJsonObject issuerList(const QList<pki_x509 *> &issuers);
	static QJsonObject index();
	static QJsonObject hierarchy();

	/* Error object (error schema without the REST members status and
	 * instance). The code of a serviceError; missing_password or
	 * password_rejected for a secretError, not_confirmed for a
	 * confirmationError (BTD-41); internal_error for any other
	 * exception. */
	static QJsonObject error(const QString &code, const QString &detail);
	static QJsonObject error(const errorEx &err);

	/* One document as one compact line with '\n' (JSON Lines) */
	static QByteArray line(const QJsonObject &doc);
	static void write(FILE *fp, const QJsonObject &doc);
	/* "-": the document to stdout, any other path: a file holding
	 * this one document. Throws errorEx if the file is not written. */
	static void writeTo(const QString &path, const QJsonObject &doc);

	/* Building blocks, public for the tests */
	static QJsonValue timestamp(const a1time &t);
	static QJsonObject dn(const x509name &name);
	static QJsonObject publicKey(const EVP_PKEY *pkey);
	static QJsonValue oidName(const ASN1_OBJECT *obj);
	static QJsonValue revocationReason(int code);
	/* Serial number as uppercase hex of whole octets without a sign
	 * octet (a1int::toHex, BTD-105). Also defined for legacy values
	 * bxc-pki never issues (BTD-41): zero is "00", a negative serial
	 * is "-" and the octets of its magnitude, and a serial may be
	 * longer than 20 octets. */
	static QString serial(const a1int &serial);
	static QString objectType(const pki_base *pki);
};

#endif
