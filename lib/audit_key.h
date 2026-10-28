/* vi: set sw=4 ts=4:
 *
 * Signing key of the audit checkpoints (BTD-37, PLAN.md section 6.3).
 *
 * Audit keys live in the table audit_keys of the XCA database, never in
 * items: no key list, dialog, service spec, export or delete function of
 * XCA reaches them. The private key is PKCS#8, AES-256 encrypted with the
 * database password like every other private key of the database
 * (prototype limit: whoever knows the database password can sign
 * checkpoints). A retired key keeps its public part, its private part is
 * dropped.
 *
 * Key type: Ed25519. Signing and verifying use EVP_DigestSign() without a
 * digest, so ML-DSA-65 (BTD-16) only changes the type passed to
 * EVP_PKEY_Q_keygen().
 *
 * Key id: lowercase hex SHA-256 of the DER SubjectPublicKeyInfo, i.e.
 *   openssl pkey -pubin -in key.pem -outform DER | openssl dgst -sha256
 */

#ifndef __AUDIT_KEY_H
#define __AUDIT_KEY_H

#include <QByteArray>
#include <QString>

#include "Passwd.h"

class pki_key;

class AuditKey
{
  public:
	static const char typeEd25519[];

	/* The database password as pki_evp::tryDecryptKey() gets it: the
	 * one the database was unlocked with, else from the password source
	 * (--password on the command line, the dialog in the GUI).
	 * Throws serviceError("audit_key_unavailable") without it. */
	static Passwd password();
	/* Generates a key, stores it encrypted with pass and returns its id;
	 * *publicPem receives the public key. The caller announces it in
	 * the chain. */
	static QString create(const Passwd &pass, QByteArray *publicPem);
	/* The id of the key that signs new checkpoints, empty if none yet */
	static QString current();
	/* Signs data with the private key of id */
	static QByteArray sign(const QString &id, const QByteArray &data,
			const Passwd &pass);
	/* Drops the private part of id; id no longer signs */
	static void retire(const QString &id);
	/* Re-encrypts the private keys on a change of the database password */
	static void reencrypt(const Passwd &newPass);

	static QString keyId(const QByteArray &publicPem);  // empty if invalid
	static bool verify(const QByteArray &publicPem, const QByteArray &data,
			const QByteArray &signature);

	/* Rejects a key whose public key belongs to an audit key, e.g. one
	 * imported from a dump of audit_keys: serviceError("audit_key") */
	static void refuseSigning(pki_key *key);
};

#endif
